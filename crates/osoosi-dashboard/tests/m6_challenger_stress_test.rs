//! Empirical Adversarial Challenger Test Suite
//! Milestone M6: Research Ingestion, Verified Repos & SSRF Defense
//! Conducted by teamwork_challenger_m6_1 (Empirical Challenger)

use osoosi_dashboard::routes::research_ingest::{
    detect_verified_code_repo, ResearchExtractionItem,
};

#[test]
fn challenge_detect_verified_code_repo_ssrf_and_fake_repo_rejection() {
    let malicious_and_fake_urls = [
        // 1. SSRF & Cloud Metadata Endpoints
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254",
        "https://169.254.169.254",
        "http://127.0.0.1:8080/admin",
        "http://127.0.0.1:3030",
        "http://localhost:11434",
        "http://0.0.0.0:22",
        "http://[::1]:8080",
        // 2. Dangerous Protocols & Schemes
        "javascript:alert(document.cookie)",
        "data:text/html,<script>alert(1)</script>",
        "file:///etc/passwd",
        "file:///C:/Windows/System32/cmd.exe",
        "ftp://github.com/evil/repo",
        "ws://github.com/evil/repo",
        // 3. Fake & Fabricated Repositories (arXiv 404 Bug Report)
        "https://github.com/AlignmentResearch/rlhf-poisoning-benchmark",
        "https://github.com/oshoosiclaw/mac-agent-bench",
        "https://github.com/fork/rlhf-poisoning-benchmark",
        "https://github.com/fork/mac-agent-bench",
        "https://gitlab.com/victim/rlhf-poisoning-benchmark",
        "https://gitlab.com/victim/mac-agent-bench",
        // 4. Incomplete or Malformed URLs
        "https://github.com",
        "https://github.com/",
        "https://github.com/onlyowner",
        "https://github.com/onlyowner/",
        "https://github.com/dummy/dummy",
        "https://github.com///",
        "https://evil-domain.com/owner/repo",
        "https://github.com.evil.com/owner/repo",
    ];

    for &url in &malicious_and_fake_urls {
        let item = ResearchExtractionItem {
            arxiv_id: Some("2605.99999".to_string()),
            title: Some(format!("Check url {}", url)),
            source_quote: Some(format!("Text pointing to {}", url)),
            has_code_repo: Some(true),
            code_repo_url: Some(url.to_string()),
            ..Default::default()
        };

        let (has_repo, resolved_url) = detect_verified_code_repo(&item);
        assert!(
            !has_repo,
            "CRITICAL SECURITY BUG: Malicious/Fake URL '{}' was accepted as a verified code repo! resolved_url='{}'",
            url,
            resolved_url
        );
        assert_eq!(
            resolved_url, "",
            "Resolved URL must be empty when rejected: '{}'",
            url
        );
    }
}

#[test]
fn challenge_detect_verified_code_repo_baseline_and_valid_repos_acceptance() {
    let valid_cases = [
        (
            "2603.02277",
            "https://github.com/UKGovernmentBEIS/inspect_evals",
        ),
        ("2604.20496", "https://github.com/cedar-policy/cedar-spec"),
        ("2610.20437", "https://github.com/NVIDIA/garak"),
        ("2601.11893", "https://github.com/ethz-spylab/agentdojo"),
    ];

    for (aid, expected_url) in valid_cases {
        let item = ResearchExtractionItem {
            arxiv_id: Some(aid.to_string()),
            title: Some(format!("Paper {}", aid)),
            ..Default::default()
        };

        let (has_repo, resolved_url) = detect_verified_code_repo(&item);
        assert!(
            has_repo,
            "Baseline paper {} must resolve to verified repository",
            aid
        );
        assert_eq!(
            resolved_url, expected_url,
            "Baseline paper {} mapped to incorrect URL",
            aid
        );
        assert!(!resolved_url.contains("rlhf-poisoning-benchmark"));
        assert!(!resolved_url.contains("mac-agent-bench"));
    }

    // Case 1: Clean URL in text
    let item_text_clean = ResearchExtractionItem {
        arxiv_id: Some("2609.55555".to_string()),
        title: Some("Novel Container Defense".to_string()),
        source_quote: Some(
            "Code available at https://github.com/oyesanyf/OshoosiClaw in repo".to_string(),
        ),
        ..Default::default()
    };

    let (has_repo, resolved_url) = detect_verified_code_repo(&item_text_clean);
    assert!(has_repo, "Extracted repo URL must be detected from text");
    assert_eq!(resolved_url, "https://github.com/oyesanyf/OshoosiClaw");
}

#[test]
fn challenge_detect_verified_code_repo_trailing_punctuation_leak() {
    // Edge case: Sentence ending in parenthetical repo citation: (https://github.com/oyesanyf/OshoosiClaw).
    // Tests whether trim_repo_url_punctuation properly strips trailing '.' and ')' and resolves canonical URL.
    let item_punct = ResearchExtractionItem {
        arxiv_id: Some("2609.55556".to_string()),
        title: Some("Novel Container Defense".to_string()),
        source_quote: Some(
            "Code available at (https://github.com/oyesanyf/OshoosiClaw).".to_string(),
        ),
        ..Default::default()
    };

    let (has_repo, resolved_url) = detect_verified_code_repo(&item_punct);
    assert!(
        has_repo,
        "Extracted repo URL must be detected from parenthetical citation"
    );
    assert_eq!(
        resolved_url, "https://github.com/oyesanyf/OshoosiClaw",
        "Must strip trailing punctuation cleanly to canonical URL"
    );
    assert!(
        !resolved_url.ends_with('.') && !resolved_url.ends_with(')'),
        "Punctuation leak detected: '{}' ends with trailing punctuation!",
        resolved_url
    );
}
