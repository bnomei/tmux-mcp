#![cfg_attr(target_os = "linux", allow(dead_code, unused_imports))]

use std::fs;
use std::path::Path;

use rstest::fixture;
use rstest::rstest;

use tmux_mcp_rs::tmux::{search_text, subsearch_text, SearchOptions, SubsearchOptions};
use tmux_mcp_rs::types::SearchMode;

const FIXTURE_PATH: &str = "tests/fixtures/old-man-and-the-sea.txt";

fn load_fixture() -> String {
    let fixture = Path::new(FIXTURE_PATH);
    fs::read_to_string(fixture).expect("read fixture")
}

#[cfg(not(target_os = "linux"))]
#[fixture]
fn oms_text() -> String {
    load_fixture()
}

#[cfg(target_os = "linux")]
#[test]
fn search_tests_skipped_on_linux() {
    eprintln!("skipping search fixture tests on linux");
}

#[cfg(not(target_os = "linux"))]
#[rstest]
fn literal_probe_then_subsearch(oms_text: String) {
    let result = search_text(
        "fixture",
        &oms_text,
        "DiMaggio",
        SearchMode::Literal,
        SearchOptions {
            context_bytes: Some(40),
            max_matches: Some(50),
            max_scan_bytes: None,
            include_similarity: false,
            fuzzy_match: false,
            similarity_threshold: None,
            resume_from_offset: None,
        },
    )
    .expect("literal search");

    assert!(result.total_matches >= 1);
    let first = &result.matches[0];
    assert!(first.offset_bytes < oms_text.len() as u64);
    assert!(first.snippet.contains("DiMaggio"));

    let sub = subsearch_text(
        "fixture",
        &oms_text,
        first.offset_bytes,
        first.match_len,
        "baseball",
        SearchMode::Literal,
        SubsearchOptions {
            context_bytes: 900,
            max_matches: Some(50),
            include_similarity: false,
            fuzzy_match: false,
            similarity_threshold: None,
            resume_from_offset: None,
        },
    )
    .expect("subsearch literal");

    assert!(sub.total_matches >= 1);
    assert!(sub.matches.iter().any(|m| m.snippet.contains("baseball")));
}

#[cfg(not(target_os = "linux"))]
#[rstest]
fn regex_probe_then_refine(oms_text: String) {
    let result = search_text(
        "fixture",
        &oms_text,
        r#"\"[^\"]+\""#,
        SearchMode::Regex,
        SearchOptions {
            context_bytes: Some(10),
            max_matches: Some(1000),
            max_scan_bytes: None,
            include_similarity: false,
            fuzzy_match: false,
            similarity_threshold: None,
            resume_from_offset: None,
        },
    )
    .expect("regex search");

    assert!(result.total_matches >= 10);
    let first = &result.matches[0];

    let refine = subsearch_text(
        "fixture",
        &oms_text,
        first.offset_bytes,
        first.match_len,
        r#"(the boy said|the old man said)"#,
        SearchMode::Regex,
        SubsearchOptions {
            context_bytes: 600,
            max_matches: Some(20),
            include_similarity: false,
            fuzzy_match: false,
            similarity_threshold: None,
            resume_from_offset: None,
        },
    )
    .expect("regex refine");

    assert!(refine.total_matches >= 1);
}

#[cfg(not(target_os = "linux"))]
#[rstest]
#[case("old man")]
#[case("the boy")]
fn literal_multiword_queries(oms_text: String, #[case] query: &str) {
    let result = search_text(
        "fixture",
        &oms_text,
        query,
        SearchMode::Literal,
        SearchOptions {
            context_bytes: Some(20),
            max_matches: Some(50),
            max_scan_bytes: None,
            include_similarity: false,
            fuzzy_match: false,
            similarity_threshold: None,
            resume_from_offset: None,
        },
    )
    .expect("multiword search");

    assert!(result.total_matches >= 1);
    assert!(result.matches.iter().any(|m| m.snippet.contains(query)));
}

#[cfg(all(not(target_os = "linux"), feature = "fuzzy"))]
#[rstest]
fn fuzzy_probe_then_confirm(oms_text: String) {
    let result = search_text(
        "fixture",
        &oms_text,
        "dimagio",
        SearchMode::Literal,
        SearchOptions {
            context_bytes: Some(40),
            max_matches: Some(50),
            max_scan_bytes: None,
            include_similarity: false,
            fuzzy_match: true,
            similarity_threshold: Some(0.85),
            resume_from_offset: None,
        },
    )
    .expect("fuzzy search");

    assert!(result.total_matches >= 1);
    let first = &result.matches[0];
    assert!(first.snippet.contains("DiMaggio"));
}

#[cfg(not(target_os = "linux"))]
#[rstest]
fn snippet_generation_is_bounded() {
    let text = "hello world";
    let result = search_text(
        "fixture",
        text,
        "world",
        SearchMode::Literal,
        SearchOptions {
            context_bytes: Some(2),
            max_matches: Some(10),
            max_scan_bytes: None,
            include_similarity: false,
            fuzzy_match: false,
            similarity_threshold: None,
            resume_from_offset: None,
        },
    )
    .expect("snippet search");

    let m = &result.matches[0];
    assert!(m.snippet.contains("world"));
    assert!(m.snippet.len() <= "world".len() + 4);
}

#[cfg(not(target_os = "linux"))]
#[rstest]
fn snippet_respects_scan_window() {
    let text = "prefix alpha beta suffix";
    let result = search_text(
        "fixture",
        text,
        "beta",
        SearchMode::Literal,
        SearchOptions {
            context_bytes: Some(10),
            max_matches: Some(5),
            max_scan_bytes: Some(17),
            include_similarity: false,
            fuzzy_match: false,
            similarity_threshold: None,
            resume_from_offset: None,
        },
    )
    .expect("scan-window search");

    let m = &result.matches[0];
    assert_eq!(m.context_start, 3);
    assert!(m.context_end <= 17);
    assert_eq!(&m.snippet, "fix alpha beta");
    assert!(m.snippet.contains("beta"));
}

#[cfg(not(target_os = "linux"))]
#[rstest]
fn match_id_is_deterministic() {
    let text = "aba";
    let result1 = search_text(
        "fixture",
        text,
        "a",
        SearchMode::Literal,
        SearchOptions {
            context_bytes: Some(1),
            max_matches: Some(10),
            max_scan_bytes: None,
            include_similarity: false,
            fuzzy_match: false,
            similarity_threshold: None,
            resume_from_offset: None,
        },
    )
    .expect("search first");
    let result2 = search_text(
        "fixture",
        text,
        "a",
        SearchMode::Literal,
        SearchOptions {
            context_bytes: Some(1),
            max_matches: Some(10),
            max_scan_bytes: None,
            include_similarity: false,
            fuzzy_match: false,
            similarity_threshold: None,
            resume_from_offset: None,
        },
    )
    .expect("search second");

    assert_eq!(result1.matches[0].match_id, result2.matches[0].match_id);
    assert_ne!(result1.matches[0].match_id, result1.matches[1].match_id);
}
