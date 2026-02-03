use std::env;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::path::Path;
use std::sync::{Mutex, MutexGuard};

use tempfile::TempDir;

static ENV_LOCK: Mutex<()> = Mutex::new(());

const TMUX_STUB_SCRIPT: &str = r#"#!/bin/sh
socket=""
if [ "$1" = "-S" ]; then
  socket="$2"
  shift 2
fi

cmd="$1"
shift

if [ "${TMUX_STUB_FORCE_ERROR:-}" = "1" ] || [ "${TMUX_STUB_ERROR_CMD:-}" = "$cmd" ]; then
  echo "${TMUX_STUB_ERROR_MSG:-stub error}" 1>&2
  exit 1
fi

case "$cmd" in
  socket-test)
    if [ -z "$socket" ]; then
      echo "missing socket" 1>&2
      exit 1
    fi
    printf "%s" "$socket"
    ;;
  ssh-test)
    if [ "${TMUX_STUB_SSH_SEEN:-}" = "1" ]; then
      printf "%s" "via-ssh"
    else
      echo "missing ssh" 1>&2
      exit 1
    fi
    ;;
  list-sessions)
    printf '%b' "${TMUX_STUB_LIST_SESSIONS:-%1\talpha\t1\t2\n%2\tbeta\t0\t1}"
    ;;
  list-windows)
    printf '%b' "${TMUX_STUB_LIST_WINDOWS:-@1\tfirst\t1\n@2\tsecond\t0}"
    ;;
  list-panes)
    printf '%b' "${TMUX_STUB_LIST_PANES:-%1\tpane-one\t1\n%2\tpane-two\t0}"
    ;;
  list-clients)
    printf '%b' "${TMUX_STUB_LIST_CLIENTS:-/dev/ttys000\tclient0\talpha\t123\t1}"
    ;;
  list-buffers)
    printf '%b' "${TMUX_STUB_LIST_BUFFERS:-buffer0\t10\t1700000000}"
    ;;
  show-buffer)
    printf '%b' "${TMUX_STUB_SHOW_BUFFER:-stub-buffer}"
    ;;
  capture-pane)
    if [ "${TMUX_STUB_CAPTURE_OUTPUT+x}" = "x" ]; then
      printf '%b' "$TMUX_STUB_CAPTURE_OUTPUT"
    else
      if [ -n "${TMUX_STUB_CAPTURE_COUNT_FILE:-}" ]; then
        count=0
        if [ -f "$TMUX_STUB_CAPTURE_COUNT_FILE" ]; then
          count=$(cat "$TMUX_STUB_CAPTURE_COUNT_FILE" 2>/dev/null || echo 0)
        fi
        if [ -z "$count" ]; then
          count=0
        fi
        count=$((count+1))
        printf '%s' "$count" > "$TMUX_STUB_CAPTURE_COUNT_FILE"
      fi

      if [ -n "${TMUX_STUB_CAPTURE_AFTER:-}" ] && [ -n "${TMUX_STUB_CAPTURE_COUNT_FILE:-}" ]; then
        if [ "$count" -lt "$TMUX_STUB_CAPTURE_AFTER" ]; then
          printf '%b' "${TMUX_STUB_CAPTURE_BEFORE:-}"
        else
          printf '%b' "${TMUX_STUB_CAPTURE_AFTER_OUTPUT:-}"
        fi
      else
        if [ -n "${TMUX_MCP_TEST_COMMAND_ID:-}" ]; then
          printf '%b' "prompt\nTMUX_MCP_START_${TMUX_MCP_TEST_COMMAND_ID}\nstub-output\nTMUX_MCP_DONE_${TMUX_MCP_TEST_COMMAND_ID}_0\n"
        else
          printf '%b' "prompt\nTMUX_MCP_START_default\nstub-output\nTMUX_MCP_DONE_default_0\n"
        fi
      fi
    fi
    ;;
  display-message)
    printf '%b' "${TMUX_STUB_CURRENT_SESSION_OUTPUT:-%1\talpha\t1\t2}"
    ;;
  new-session)
    printf '%b' "${TMUX_STUB_NEW_SESSION_OUTPUT:-%9\tnew-session\t0\t1}"
    ;;
  new-window)
    printf '%b' "${TMUX_STUB_NEW_WINDOW_OUTPUT:-@9\tnew-window\t1}"
    ;;
  split-window)
    printf '%b' "${TMUX_STUB_SPLIT_WINDOW_OUTPUT:-%3\tnew-pane\t1\t@1}"
    ;;
  break-pane)
    printf '%b' "${TMUX_STUB_BREAK_PANE_OUTPUT:-@9\tbroken\t1\t%1}"
    ;;
  send-keys)
    if [ -n "${TMUX_STUB_SEND_KEYS_LOG:-}" ]; then
      printf '%s\n' "send-keys $*" >> "$TMUX_STUB_SEND_KEYS_LOG"
    fi
    ;;
  kill-session|kill-window|kill-pane|rename-window|rename-pane|rename-session|move-window|select-pane|select-window|select-layout|join-pane|swap-pane|resize-pane|set-option|detach-client|save-buffer|delete-buffer|set-buffer|load-buffer)
    ;;
  *)
    echo "unknown command: $cmd" 1>&2
    exit 1
    ;;
esac
"#;

const SSH_STUB_SCRIPT: &str = r#"#!/bin/sh
if [ "$#" -lt 2 ]; then
  echo "missing ssh args" 1>&2
  exit 1
fi
dest="$1"
shift
export TMUX_STUB_SSH_SEEN=1
exec "$@"
"#;

pub struct TmuxStub {
    _lock: MutexGuard<'static, ()>,
    _dir: TempDir,
    original_vars: Vec<(String, Option<OsString>)>,
}

impl TmuxStub {
    pub fn new() -> Self {
        let lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = TempDir::new().expect("create temp dir");
        let script_path = dir.path().join("tmux");
        let ssh_path = dir.path().join("ssh");
        write_executable(&script_path, TMUX_STUB_SCRIPT);
        write_executable(&ssh_path, SSH_STUB_SCRIPT);

        let mut stub = Self {
            _lock: lock,
            _dir: dir,
            original_vars: Vec::new(),
        };

        let mut path = OsString::new();
        path.push(stub._dir.path());
        path.push(OsStr::new(":"));
        if let Some(existing) = env::var_os("PATH") {
            path.push(existing);
        }
        stub.set_var("PATH", path);

        stub
    }

    pub fn set_var(&mut self, key: &str, value: impl AsRef<OsStr>) {
        self.record_original(key);
        env::set_var(key, value);
    }

    pub fn remove_var(&mut self, key: &str) {
        self.record_original(key);
        env::remove_var(key);
    }

    fn record_original(&mut self, key: &str) {
        if self.original_vars.iter().any(|(k, _)| k == key) {
            return;
        }
        self.original_vars.push((key.to_string(), env::var_os(key)));
    }
}

impl Drop for TmuxStub {
    fn drop(&mut self) {
        for (key, value) in self.original_vars.drain(..) {
            if let Some(value) = value {
                env::set_var(key, value);
            } else {
                env::remove_var(key);
            }
        }
    }
}

fn write_executable(path: &Path, contents: &str) {
    fs::write(path, contents).expect("write tmux stub");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(path).expect("stat stub").permissions();
        perms.set_mode(0o755);
        fs::set_permissions(path, perms).expect("chmod stub");
    }
}
