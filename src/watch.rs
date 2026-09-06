//! Blocking "wait until pane text changes" engine (`wait-for-pane-change`).
//!
//! Polls `capture-pane -p` at a fixed interval and compares the visible
//! screen text byte-exactly against a baseline taken at call start. The
//! design is deliberately minimal (see `findings-plan-progress.md` §4/§5):
//! the displayed text is the sole observable — no cursor, title, mode, or
//! history metadata participates in the wake predicate. Any tmux error
//! (including a pane that disappeared) aborts the wait immediately; timeouts
//! are successful results.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::time::{Duration, Instant};

use serde::Deserialize;

use crate::errors::Result;
use crate::tmux;

/// Default poll interval when no config or env override applies.
const DEFAULT_POLL_INTERVAL_MS: u64 = 300;
/// Poll interval when `TMUX_MCP_SSH` is set (each poll costs an ssh exec).
const DEFAULT_SSH_POLL_INTERVAL_MS: u64 = 800;
/// Default debounce window: wake once output settles, not mid-burst.
const DEFAULT_STABLE_MS: u64 = 250;
/// Default blocking budget before a successful `timedOut` result.
const DEFAULT_TIMEOUT_MS: u64 = 30_000;
/// Default ceiling for caller-supplied `timeoutMs` when unconfigured.
const DEFAULT_TIMEOUT_MAX_MS: u64 = 600_000;

/// `[watch]` config section for `wait-for-pane-change`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WatchConfig {
    /// Milliseconds between poll ticks. Defaults to 800 over SSH, else 300.
    #[serde(default)]
    pub poll_interval_ms: Option<u64>,
    /// Default `timeoutMs` when the caller omits it.
    #[serde(default)]
    pub timeout_default_ms: Option<u64>,
    /// Maximum accepted `timeoutMs`; larger requests are rejected, not clamped.
    #[serde(default)]
    pub timeout_max_ms: Option<u64>,
    /// Default `stableMs` debounce window when the caller omits it.
    #[serde(default)]
    pub stable_ms: Option<u64>,
}

impl WatchConfig {
    /// Effective poll interval: config > env-derived default.
    pub fn effective_poll_interval_ms(&self) -> u64 {
        self.poll_interval_ms
            .unwrap_or_else(default_poll_interval_ms)
    }

    /// Effective default timeout budget for a wait.
    pub fn effective_timeout_default_ms(&self) -> u64 {
        self.timeout_default_ms.unwrap_or(DEFAULT_TIMEOUT_MS)
    }

    /// Effective timeout ceiling for caller-supplied `timeoutMs`.
    pub fn effective_timeout_max_ms(&self) -> u64 {
        self.timeout_max_ms.unwrap_or(DEFAULT_TIMEOUT_MAX_MS)
    }

    /// Effective default debounce window.
    pub fn effective_stable_ms(&self) -> u64 {
        self.stable_ms.unwrap_or(DEFAULT_STABLE_MS)
    }
}

fn default_poll_interval_ms() -> u64 {
    if crate::tmux::ssh_enabled().unwrap_or(false) {
        DEFAULT_SSH_POLL_INTERVAL_MS
    } else {
        DEFAULT_POLL_INTERVAL_MS
    }
}

/// Fixed LRU cap for the anchor registry. Bounds stale entries from panes
/// that die without our kill-tools firing (shells exiting, external kills,
/// tmux server restarts that reset `%N` ids). Hot panes are never evicted in
/// practice at this size.
const ANCHOR_REGISTRY_MAX_ENTRIES: usize = 256;

/// Pane-keyed store of the text the agent last had the opportunity to see.
///
/// Every input to a pane (`send-keys` family, `paste-text`, `execute-command`)
/// and every text read (`capture-pane`, text pane resources, every
/// `wait-for-pane-change` wake) refreshes the anchor. `wait-for-pane-change`
/// then arms against the anchor — not the screen at call time — which closes
/// the fast-command race: commands that finish during the LLM round trip
/// before the wait call wake instantly on the first poll.
///
/// The registry is LRU-bounded: purge-on-kill is the primary cleanup, the
/// cap is the backstop for unobservable pane deaths. FIFO would evict a
/// long-driven pane merely for being old; LRU keeps exactly the hot entries.
#[derive(Debug, Default)]
pub struct AnchorRegistry {
    entries: HashMap<String, PaneSnapshot>,
    /// Recency ring: most recently touched key is last.
    order: Vec<String>,
}

impl AnchorRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    fn key(pane_id: &str, socket: Option<&str>) -> String {
        format!("{}|{}", socket.unwrap_or(""), pane_id)
    }

    /// Store the anchor for a pane and mark it most recently used.
    pub fn set(&mut self, pane_id: &str, socket: Option<&str>, text: String) {
        let key = Self::key(pane_id, socket);
        if !self.entries.contains_key(&key) {
            self.order.push(key.clone());
            if self.order.len() > ANCHOR_REGISTRY_MAX_ENTRIES {
                // Evict the least recently used entry.
                if let Some(evicted) = self.order.first().cloned() {
                    self.order.remove(0);
                    self.entries.remove(&evicted);
                }
            }
        } else {
            self.order.retain(|k| k != &key);
            self.order.push(key.clone());
        }
        self.entries.insert(
            key,
            PaneSnapshot {
                pane_id: pane_id.to_string(),
                text,
            },
        );
    }

    /// Fetch the anchor for a pane, marking it most recently used.
    pub fn get(&mut self, pane_id: &str, socket: Option<&str>) -> Option<PaneSnapshot> {
        let key = Self::key(pane_id, socket);
        let snapshot = self.entries.get(&key).cloned();
        if snapshot.is_some() {
            self.order.retain(|k| k != &key);
            self.order.push(key);
        }
        snapshot
    }

    /// Drop a pane's anchor (purge on kill).
    pub fn purge_pane(&mut self, pane_id: &str, socket: Option<&str>) {
        let key = Self::key(pane_id, socket);
        self.entries.remove(&key);
        self.order.retain(|k| k != &key);
    }

    /// Number of stored anchors (for tests).
    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True when no anchors are stored (for Clippy's `is_empty` rule).
    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// One visible-screen observation of a pane.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaneSnapshot {
    /// Pane target id (`%N`) the snapshot came from.
    pub pane_id: String,
    /// Raw `capture-pane -p` output (visible screen, no colors, joined lines).
    pub text: String,
}

/// How a wait ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WaitOutcome {
    /// Displayed text differs from the baseline.
    Changed,
    /// The blocking budget elapsed with no (settled) change.
    TimedOut,
}

/// Terminal state of one `wait-for-pane-change` engine run.
#[derive(Debug, Clone)]
pub struct WaitResult {
    pub outcome: WaitOutcome,
    /// Wall-clock duration from engine start to wake/timeout.
    pub waited: Duration,
    /// How long the screen had been stable when the engine woke. On a
    /// `Changed` wake this is at least `stable_ms`; on timeout it is the
    /// time since the last observed change (or since start when none).
    pub quiet: Duration,
}

/// Source of pane snapshots; `TmuxPollSource` in production, fakes in tests.
///
/// Boxed futures because the crate's MSRV (1.70) predates async fn in traits.
pub trait ChangeSource: Send {
    /// Observe the pane once. `Err` aborts the wait (fail fast: a pane that
    /// disappeared reports the tmux error verbatim).
    fn snapshot(&mut self) -> Pin<Box<dyn Future<Output = Result<PaneSnapshot>> + Send + '_>>;
}

impl<S: ChangeSource + ?Sized> ChangeSource for &mut S {
    fn snapshot(&mut self) -> Pin<Box<dyn Future<Output = Result<PaneSnapshot>> + Send + '_>> {
        (**self).snapshot()
    }
}

/// Production source: one semaphore-acquiring `capture-pane` spawn per tick.
pub struct TmuxPollSource {
    pane_id: String,
    socket: Option<String>,
}

impl TmuxPollSource {
    /// Capture the visible screen of `pane_id` on each `snapshot()` call.
    pub fn new(pane_id: impl Into<String>, socket: Option<String>) -> Self {
        Self {
            pane_id: pane_id.into(),
            socket,
        }
    }
}

impl ChangeSource for TmuxPollSource {
    fn snapshot(&mut self) -> Pin<Box<dyn Future<Output = Result<PaneSnapshot>> + Send + '_>> {
        let pane_id = self.pane_id.clone();
        let socket = self.socket.clone();
        Box::pin(async move {
            // Visible screen only: lines=None with start/end=None captures
            // just the current screen (no scrollback budget).
            let text =
                tmux::capture_pane(&pane_id, None, false, None, None, true, socket.as_deref())
                    .await?;
            Ok(PaneSnapshot { pane_id, text })
        })
    }
}

/// Engine parameters resolved from input + `[watch]` config.
#[derive(Debug, Clone, Copy)]
pub struct WaitParams {
    /// Milliseconds between polls.
    pub poll_interval: Duration,
    /// Total blocking budget.
    pub timeout: Duration,
    /// Required quiet period after a change before waking.
    pub stable_ms: Duration,
}

impl WaitParams {
    /// Resolve parameters from caller input and config defaults.
    ///
    /// `timeout_ms`/`stable_ms` of `None` fall back to config defaults.
    /// An explicit `timeout_ms` above the configured ceiling is **rejected**
    /// (an error, not a silent clamp) so the caller can distinguish
    /// "pane quiet" from "server refused the budget".
    pub fn resolve(
        timeout_ms: Option<u64>,
        stable_ms: Option<u64>,
        config: &WatchConfig,
    ) -> Result<Self> {
        let timeout_ms = timeout_ms.unwrap_or_else(|| config.effective_timeout_default_ms());
        let ceiling = config.effective_timeout_max_ms();
        if timeout_ms > ceiling {
            return Err(crate::errors::Error::InvalidArgument {
                message: format!(
                    "timeoutMs {timeout_ms} exceeds the configured maximum of {ceiling} ms \
                     ([watch] timeout_max_ms)"
                ),
            });
        }
        Ok(Self {
            poll_interval: Duration::from_millis(config.effective_poll_interval_ms()),
            timeout: Duration::from_millis(timeout_ms),
            stable_ms: Duration::from_millis(
                stable_ms.unwrap_or_else(|| config.effective_stable_ms()),
            ),
        })
    }
}

/// Poll `source` until the visible text differs from the baseline.
///
/// The default baseline is `source`'s first snapshot (current screen);
/// callers pass `anchor` to arm against an earlier interaction instead
/// (see `AnchorRegistry`) so changes that landed before this call — the
/// fast-command race — still wake the engine. `quiet` timing is measured
/// from the last observed change. With `stable_ms > 0`, a change resets a
/// quiet-timer and the engine wakes only once the screen has been stable for
/// that long; `stable_ms == 0` wakes at the first difference. Any `source`
/// error aborts immediately — the caller surfaces it as a tool error
/// (pane-gone included).
pub async fn wait_for_change<S: ChangeSource + ?Sized>(
    source: &mut S,
    params: &WaitParams,
    anchor: Option<String>,
) -> Result<WaitResult> {
    let start = Instant::now();
    let mut current = source.snapshot().await?;
    let baseline = anchor.unwrap_or_else(|| current.text.clone());
    // Timestamp of the last observed change; the screen was "stable" since
    // the baseline by definition.
    let mut last_change = start;
    // An anchor that already differs from the current screen means a change
    // happened before this call (the fast-command race): report it at the
    // first poll rather than sleeping through a no-op wait.
    let mut has_changed = baseline != current.text;

    // Fast path (fast-command race): the anchor already differs from the
    // current screen, and no debounce is requested — the change happened
    // before this call and the screen is what the agent would capture now.
    // Wake immediately instead of sleeping a tick first.
    if has_changed && params.stable_ms.is_zero() {
        return Ok(WaitResult {
            outcome: WaitOutcome::Changed,
            waited: start.elapsed(),
            quiet: Duration::ZERO,
        });
    }

    loop {
        let elapsed = start.elapsed();
        if elapsed >= params.timeout {
            let quiet = if has_changed {
                last_change.duration_since(start)
            } else {
                elapsed
            };
            return Ok(WaitResult {
                outcome: WaitOutcome::TimedOut,
                waited: elapsed,
                quiet,
            });
        }

        // Sleep until the next tick, but never past the deadline.
        let remaining = params.timeout - elapsed;
        let tick = params.poll_interval.min(remaining);
        tokio::time::sleep(tick).await;

        let snapshot = source.snapshot().await?;
        if snapshot.text != current.text {
            if params.stable_ms.is_zero() {
                let now = Instant::now();
                return Ok(WaitResult {
                    outcome: WaitOutcome::Changed,
                    waited: now.duration_since(start),
                    quiet: Duration::ZERO,
                });
            }
            current = snapshot;
            last_change = Instant::now();
            has_changed = true;
        } else if has_changed {
            let quiet = last_change.elapsed();
            if quiet >= params.stable_ms {
                let now = Instant::now();
                return Ok(WaitResult {
                    outcome: WaitOutcome::Changed,
                    waited: now.duration_since(start),
                    quiet,
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::errors::Error;
    use std::cell::RefCell;

    /// Scripted source: yields queued snapshots in order, repeating the last.
    struct FakeSource {
        snapshots: RefCell<Vec<Result<PaneSnapshot>>>,
        polls: RefCell<u32>,
    }

    impl FakeSource {
        fn new(snapshots: Vec<Result<PaneSnapshot>>) -> Self {
            Self {
                snapshots: RefCell::new(snapshots),
                polls: RefCell::new(0),
            }
        }

        fn poll_count(&self) -> u32 {
            *self.polls.borrow()
        }
    }

    impl ChangeSource for FakeSource {
        fn snapshot(&mut self) -> Pin<Box<dyn Future<Output = Result<PaneSnapshot>> + Send + '_>> {
            *self.polls.borrow_mut() += 1;
            // Advance the script unless only one entry remains (it repeats).
            // `Error` is not `Clone`, so the repeating tail is regenerated
            // from its last text/error message when it is an error.
            let next = {
                let mut queue = self.snapshots.borrow_mut();
                if queue.len() > 1 {
                    queue.remove(0)
                } else {
                    match queue.last() {
                        Some(Ok(snap)) => Ok(snap.clone()),
                        Some(Err(Error::Tmux { message })) => Err(Error::Tmux {
                            message: message.clone(),
                        }),
                        _ => panic!("FakeSource exhausted"),
                    }
                }
            };
            let next = match next {
                Ok(snap) => Ok(snap),
                Err(Error::Tmux { message }) => Err(Error::Tmux { message }),
                Err(other) => panic!("unhandled error variant: {other:?}"),
            };
            Box::pin(std::future::ready(next))
        }
    }

    fn snap(text: &str) -> Result<PaneSnapshot> {
        Ok(PaneSnapshot {
            pane_id: "%1".into(),
            text: text.into(),
        })
    }

    fn fast_params(stable_ms: u64, timeout_ms: u64) -> WaitParams {
        WaitParams {
            poll_interval: Duration::from_millis(1),
            timeout: Duration::from_millis(timeout_ms),
            stable_ms: Duration::from_millis(stable_ms),
        }
    }

    #[test]
    fn test_wait_config_defaults_are_safe() {
        let config = WatchConfig::default();
        assert_eq!(config.effective_stable_ms(), 250);
        assert_eq!(config.effective_timeout_default_ms(), 30_000);
        assert_eq!(config.effective_timeout_max_ms(), 600_000);
        assert!(
            config.effective_poll_interval_ms() == 300
                || config.effective_poll_interval_ms() == 800,
            "poll interval defaults locally or over ssh, got {}",
            config.effective_poll_interval_ms()
        );
    }

    #[test]
    fn test_wait_config_env_ssh_uses_longer_interval() {
        // With TMUX_MCP_SSH set, the default interval is the ssh variant.
        let mut stub = crate::test_support::TmuxStub::new();
        stub.set_var("TMUX_MCP_SSH", "user@example.test");
        assert_eq!(
            WatchConfig::default().effective_poll_interval_ms(),
            DEFAULT_SSH_POLL_INTERVAL_MS
        );
        stub.remove_var("TMUX_MCP_SSH");
        assert_eq!(
            WatchConfig::default().effective_poll_interval_ms(),
            DEFAULT_POLL_INTERVAL_MS
        );
    }

    #[test]
    fn test_wait_params_resolve_defaults() {
        let config = WatchConfig::default();
        let params = WaitParams::resolve(None, None, &config).unwrap();
        assert_eq!(params.timeout, Duration::from_millis(30_000));
        assert_eq!(params.stable_ms, Duration::from_millis(250));
        assert_eq!(config.effective_timeout_max_ms(), DEFAULT_TIMEOUT_MAX_MS);
    }

    #[test]
    fn test_wait_params_reject_over_ceiling_timeout() {
        let config = WatchConfig::default();
        let err = WaitParams::resolve(Some(10_000_000), Some(0), &config)
            .expect_err("over-ceiling timeout must be rejected");
        let message = err.to_string();
        assert!(message.contains("exceeds the configured maximum"));
        assert!(message.contains("600000 ms"));
    }

    #[test]
    fn test_wait_params_accept_timeout_at_exact_ceiling() {
        let config = WatchConfig::default();
        let params = WaitParams::resolve(Some(DEFAULT_TIMEOUT_MAX_MS), Some(0), &config).unwrap();
        assert_eq!(
            params.timeout,
            Duration::from_millis(DEFAULT_TIMEOUT_MAX_MS)
        );
    }

    #[test]
    fn test_wait_params_custom_ceiling_is_respected() {
        let config = WatchConfig {
            timeout_max_ms: Some(120_000),
            ..WatchConfig::default()
        };
        let params = WaitParams::resolve(Some(120_000), None, &config).unwrap();
        assert_eq!(params.timeout, Duration::from_millis(120_000));
        let err = WaitParams::resolve(Some(120_001), None, &config)
            .expect_err("one past the custom ceiling must be rejected");
        assert!(err.to_string().contains("120000 ms"));
    }

    #[tokio::test]
    async fn test_wait_first_change_wakes_with_zero_stable() {
        let mut source = FakeSource::new(vec![snap("a"), snap("b")]);
        let params = fast_params(0, 5_000);
        let result = wait_for_change(&mut source, &params, None).await.unwrap();
        assert_eq!(result.outcome, WaitOutcome::Changed);
    }

    #[tokio::test]
    async fn test_wait_identical_text_does_not_wake() {
        let mut source = FakeSource::new(vec![snap("same"), snap("same"), snap("same")]);
        let params = fast_params(0, 50);
        let result = wait_for_change(&mut source, &params, None).await.unwrap();
        assert_eq!(result.outcome, WaitOutcome::TimedOut);
    }

    #[tokio::test]
    async fn test_wait_timeout_reports_quiet_since_start() {
        let mut source = FakeSource::new(vec![snap("same")]);
        let params = fast_params(0, 40);
        let result = wait_for_change(&mut source, &params, None).await.unwrap();
        assert_eq!(result.outcome, WaitOutcome::TimedOut);
        assert!(result.quiet >= Duration::from_millis(30));
    }

    /// Source that never repeats: emits a new text value on every poll.
    struct EndlessBurstSource {
        polls: RefCell<u32>,
    }

    impl ChangeSource for EndlessBurstSource {
        fn snapshot(&mut self) -> Pin<Box<dyn Future<Output = Result<PaneSnapshot>> + Send + '_>> {
            let count = {
                let mut polls = self.polls.borrow_mut();
                *polls += 1;
                *polls
            };
            let text = format!("tick-{count}");
            Box::pin(std::future::ready(Ok(PaneSnapshot {
                pane_id: "%1".into(),
                text,
            })))
        }
    }

    #[tokio::test]
    async fn test_wait_stable_ms_collapses_burst() {
        // Screen changes on every tick (streaming burst) — no quiet window.
        let mut source = EndlessBurstSource {
            polls: RefCell::new(0),
        };
        let params = fast_params(60, 200);
        let result = wait_for_change(&mut source, &params, None).await.unwrap();
        assert_eq!(
            result.outcome,
            WaitOutcome::TimedOut,
            "continuous changes with no quiet window time out"
        );
    }

    #[tokio::test]
    async fn test_wait_stable_ms_wakes_after_settling() {
        // Burst, then quiet: wake once the quiet window elapses.
        let mut source = FakeSource::new(vec![snap("a"), snap("b"), snap("b"), snap("b")]);
        let params = fast_params(30, 2_000);
        let result = wait_for_change(&mut source, &params, None).await.unwrap();
        assert_eq!(result.outcome, WaitOutcome::Changed);
        assert!(result.quiet >= params.stable_ms);
    }

    #[tokio::test]
    async fn test_wait_burst_then_revert_to_baseline_settles_changed() {
        // A change that reverts to baseline text still counts as changed:
        // the engine tracks the last observation, not the baseline.
        let mut source = FakeSource::new(vec![
            snap("a"),
            snap("flash"),
            snap("a"),
            snap("a"),
            snap("a"),
        ]);
        let params = fast_params(40, 2_000);
        let result = wait_for_change(&mut source, &params, None).await.unwrap();
        assert_eq!(
            result.outcome,
            WaitOutcome::Changed,
            "a transient change is still a change"
        );
    }

    #[tokio::test]
    async fn test_wait_source_error_aborts_with_error() {
        let mut source = FakeSource::new(vec![
            snap("a"),
            Err(Error::Tmux {
                message: "can't find pane: %1".into(),
            }),
        ]);
        let params = fast_params(0, 5_000);
        let err = wait_for_change(&mut source, &params, None)
            .await
            .expect_err("pane-gone error must propagate");
        match err {
            Error::Tmux { message } => assert!(message.contains("can't find pane")),
            other => panic!("expected tmux error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_wait_baseline_error_aborts_immediately() {
        let mut source = FakeSource::new(vec![Err(Error::Tmux {
            message: "no server running".into(),
        })]);
        let params = fast_params(0, 5_000);
        let err = wait_for_change(&mut source, &params, None)
            .await
            .expect_err("baseline failure must propagate");
        assert_eq!(source.poll_count(), 1, "no polling after baseline error");
        let _ = err;
    }

    #[tokio::test]
    async fn test_wait_empty_text_is_content() {
        // Empty is a legitimate screen state: baseline empty -> text must not wake.
        let mut source = FakeSource::new(vec![snap(""), snap(""), snap("")]);
        let params = fast_params(0, 50);
        let result = wait_for_change(&mut source, &params, None).await.unwrap();
        assert_eq!(result.outcome, WaitOutcome::TimedOut);
    }

    #[tokio::test]
    async fn test_wait_clearing_screen_wakes() {
        // Non-empty baseline -> empty screen is a change (e.g. `clear`).
        let mut source = FakeSource::new(vec![snap("before"), snap(""), snap("")]);
        let params = fast_params(0, 5_000);
        let result = wait_for_change(&mut source, &params, None).await.unwrap();
        assert_eq!(result.outcome, WaitOutcome::Changed);
    }

    #[tokio::test]
    async fn test_wait_whitespace_only_diff_wakes() {
        let mut source = FakeSource::new(vec![snap("line"), snap("line "), snap("line ")]);
        let params = fast_params(0, 5_000);
        let result = wait_for_change(&mut source, &params, None).await.unwrap();
        assert_eq!(
            result.outcome,
            WaitOutcome::Changed,
            "byte-exact comparison: a trailing space is a change"
        );
    }

    #[test]
    fn test_anchor_registry_set_get_purge() {
        let mut registry = AnchorRegistry::new();
        assert!(registry.is_empty());
        registry.set("%1", None, "first".into());
        registry.set("%2", Some("/tmp/sock"), "second".into());
        assert_eq!(registry.len(), 2);
        assert_eq!(registry.get("%1", None).unwrap().text, "first");
        assert_eq!(
            registry.get("%1", Some("/tmp/sock")),
            None,
            "socket keys differ"
        );
        assert_eq!(
            registry.get("%2", Some("/tmp/sock")).unwrap().text,
            "second"
        );
        registry.purge_pane("%1", None);
        assert_eq!(registry.get("%1", None), None);
        assert_eq!(registry.len(), 1);
    }

    #[test]
    fn test_anchor_registry_evicts_least_recently_used() {
        let mut registry = AnchorRegistry::new();
        registry.set("%1", None, "a".into());
        registry.set("%2", None, "b".into());
        // Touch %1 AFTER %2 exists so %2 becomes the LRU victim when the cap
        // is exceeded (recency = last touch, and %1's latest touch is newer).
        registry.set("%1", None, "a2".into());
        for i in 0..254 {
            registry.set(&format!("%{}", i + 3), None, format!("v{i}"));
        }
        assert_eq!(registry.len(), 256, "cap holds");
        // Adding one more evicts the least-recently-used entry (%2).
        registry.set("%999", None, "overflow".into());
        assert_eq!(registry.len(), 256, "capped after insert");
        assert_eq!(registry.get("%2", None), None);
        assert_eq!(registry.get("%999", None).unwrap().text, "overflow");
        // Hot entry survived.
        assert_eq!(registry.get("%1", None).unwrap().text, "a2");
    }

    #[tokio::test]
    async fn test_wait_anchored_pre_changed_screen_wakes_immediately() {
        // The fast-command race: anchor is the pre-output screen, the current
        // screen already contains the output. Zero debounce -> instant wake.
        let mut source = FakeSource::new(vec![snap("after output")]);
        let params = fast_params(0, 10_000);
        let result = wait_for_change(&mut source, &params, Some("before output".into()))
            .await
            .unwrap();
        assert_eq!(result.outcome, WaitOutcome::Changed);
        assert!(
            result.waited < Duration::from_millis(100),
            "no poll sleep needed"
        );
        assert_eq!(source.poll_count(), 1, "baseline captured, no polling");
    }

    #[tokio::test]
    async fn test_wait_anchored_pre_changed_screen_respects_debounce() {
        // With stable_ms > 0 the pre-changed anchor still needs the quiet
        // window before waking — the engine cannot assume when the change
        // settled.
        let mut source = FakeSource::new(vec![
            snap("after output"),
            snap("after output"),
            snap("after output"),
        ]);
        let params = fast_params(30, 5_000);
        let result = wait_for_change(&mut source, &params, Some("before".into()))
            .await
            .unwrap();
        assert_eq!(result.outcome, WaitOutcome::Changed);
    }

    #[tokio::test]
    async fn test_wait_anchor_matching_current_text_times_out_normally() {
        // Anchor equals the current screen: no pre-call change, and the pane
        // stays quiet — v1 timeout behavior.
        let mut source = FakeSource::new(vec![snap("same"), snap("same")]);
        let params = fast_params(0, 60);
        let result = wait_for_change(&mut source, &params, Some("same".into()))
            .await
            .unwrap();
        assert_eq!(result.outcome, WaitOutcome::TimedOut);
    }

    #[tokio::test]
    async fn test_wait_anchor_change_then_revert_wakes() {
        // Output landed and was replaced (e.g. cleared) between interaction
        // and wait: the anchor still differs from current, so it wakes —
        // the caller captures and sees the current state.
        let mut source = FakeSource::new(vec![snap("")]);
        let params = fast_params(0, 5_000);
        let result = wait_for_change(&mut source, &params, Some("old text".into()))
            .await
            .unwrap();
        assert_eq!(result.outcome, WaitOutcome::Changed);
    }

    #[tokio::test]
    async fn test_wait_dropped_future_stops_polling() {
        // Detach a wait and drop it; the fake's poll counter stops growing.
        let source = std::sync::Arc::new(tokio::sync::Mutex::new(FakeSource::new(vec![snap(
            "static",
        )])));
        let params = fast_params(0, 10_000);
        let handle = {
            let source = std::sync::Arc::clone(&source);
            tokio::spawn(async move {
                let mut guard = source.lock().await;
                let source: &mut FakeSource = &mut guard;
                let _ = wait_for_change(source, &params, None).await;
            })
        };
        tokio::time::sleep(Duration::from_millis(30)).await;
        handle.abort();
        let _ = handle.await;
        let count_after_abort = source.lock().await.poll_count();
        tokio::time::sleep(Duration::from_millis(50)).await;
        let count_later = source.lock().await.poll_count();
        assert_eq!(
            count_after_abort, count_later,
            "polling must stop once the wait future is dropped"
        );
    }
}
