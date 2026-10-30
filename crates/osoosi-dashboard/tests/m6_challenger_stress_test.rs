//! Empirical Adversarial Challenger Test Suite
//! Milestone M6: Research Ingestion, Verified Repos & SSRF Defense
//! Conducted by teamwork_challenger_m6_1 (Empirical Challenger)

use osoosi_dashboard::routes::research_ingest::{
    detect_verified_code_repo, is_valid_verified_repo_url, trim_repo_url_punctuation,
    ResearchExtractionItem,
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

#[test]
fn challenge_detect_verified_code_repo_boundary_stress_matrix() {
    // 1. Direct punctuation trimmer stress tests
    let trim_cases = [
        (
            "((https://github.com/owner/repo)).",
            "https://github.com/owner/repo",
        ),
        (
            "[[{https://github.com/owner/repo}]]",
            "https://github.com/owner/repo",
        ),
        (
            "<\"https://github.com/owner/repo\">,",
            "https://github.com/owner/repo",
        ),
        (
            "'https://github.com/owner/repo';",
            "https://github.com/owner/repo",
        ),
        (
            "`https://github.com/owner/repo`:",
            "https://github.com/owner/repo",
        ),
        (
            "https://github.com/owner/repo...",
            "https://github.com/owner/repo",
        ),
        (
            "https://github.com/owner/repo?!",
            "https://github.com/owner/repo",
        ),
        (
            ";;;https://github.com/owner/repo::: ",
            "https://github.com/owner/repo",
        ),
        (
            "  \t https://github.com/owner/repo \n ",
            "https://github.com/owner/repo",
        ),
    ];
    for (raw, expected) in trim_cases {
        let cleaned = trim_repo_url_punctuation(raw);
        assert_eq!(
            cleaned, expected,
            "trim_repo_url_punctuation failed on '{}': got '{}', expected '{}'",
            raw, cleaned, expected
        );
    }

    // 2. Strict URL validator boundary inputs
    let valid_urls = [
        "https://github.com/owner/repo",
        "https://gitlab.com/owner/repo",
        "https://github.com/owner/repo/",
        "https://github.com/owner/repo.git",
        "https://github.com/owner-name/repo_name-1.0",
        "https://github.com/owner.name/repo.name",
        "https://gitlab.com/group-a/project_b",
    ];
    for url in valid_urls {
        assert!(
            is_valid_verified_repo_url(url),
            "Valid repository URL rejected by validator: '{}'",
            url
        );
    }

    let invalid_urls = [
        // Query, hash, traversal
        "https://github.com/owner/repo?param=value",
        "https://github.com/owner/repo#section",
        "https://github.com/owner/repo/../evil",
        "https://github.com/owner/../repo",
        // Path counts and emptiness
        "https://github.com/owner/repo/extra/path",
        "https://github.com/owner",
        "https://github.com//repo",
        "https://github.com/owner/",
        "https://github.com/",
        "https://github.com",
        // Schemes
        "http://github.com/owner/repo",
        "ftp://github.com/owner/repo",
        "ssh://git@github.com/owner/repo",
        "git://github.com/owner/repo",
        "file:///github.com/owner/repo",
        // SSRF & lookalikes
        "https://127.0.0.1/owner/repo",
        "https://169.254.169.254/owner/repo",
        "https://[::1]/owner/repo",
        "https://localhost/owner/repo",
        "https://github.com@169.254.169.254/owner/repo",
        "https://github.com.evil.com/owner/repo",
        // Slug boundary and characters
        "https://github.com/-owner/repo",
        "https://github.com/owner-/repo",
        "https://github.com/owner/repo-",
        "https://github.com/owner/repo.",
        "https://github.com/dummy/repo",
        "https://github.com/owner/dummy",
    ];
    for url in invalid_urls {
        assert!(
            !is_valid_verified_repo_url(url),
            "CRITICAL SECURITY DEFECT: Invalid repository URL accepted by validator: '{}'",
            url
        );
    }

    // 3. Extraction from text with complex sentence boundary structures
    let sentence_cases = [
        (
            "See: https://github.com/oyesanyf/OshoosiClaw; also https://github.com/cedar-policy/cedar-spec.",
            "https://github.com/oyesanyf/OshoosiClaw",
        ),
        (
            "Code in [[{https://github.com/oyesanyf/OshoosiClaw}]] is public.",
            "https://github.com/oyesanyf/OshoosiClaw",
        ),
        (
            "Clone at <\"https://github.com/oyesanyf/OshoosiClaw\">, for reproduction.",
            "https://github.com/oyesanyf/OshoosiClaw",
        ),
        (
            "Repository: 'https://github.com/oyesanyf/OshoosiClaw'; please verify.",
            "https://github.com/oyesanyf/OshoosiClaw",
        ),
        (
            "Check `https://github.com/oyesanyf/OshoosiClaw`: available today.",
            "https://github.com/oyesanyf/OshoosiClaw",
        ),
        (
            "Check https://github.com/oyesanyf/OshoosiClaw.git. now.",
            "https://github.com/oyesanyf/OshoosiClaw.git",
        ),
    ];

    for (text, expected_url) in sentence_cases {
        let item = ResearchExtractionItem {
            arxiv_id: Some("2609.77777".to_string()),
            title: Some("Sentence Boundary Test".to_string()),
            source_quote: Some(text.to_string()),
            ..Default::default()
        };
        let (has_repo, resolved_url) = detect_verified_code_repo(&item);
        assert!(
            has_repo,
            "Failed to extract valid repo from sentence: '{}'",
            text
        );
        assert_eq!(
            resolved_url, expected_url,
            "Resolved URL mismatch from sentence '{}': got '{}', expected '{}'",
            text, resolved_url, expected_url
        );
        assert!(
            !resolved_url.ends_with('.')
                && !resolved_url.ends_with(';')
                && !resolved_url.ends_with(':')
                && !resolved_url.ends_with(',')
                && !resolved_url.ends_with(']')
                && !resolved_url.ends_with('}')
                && !resolved_url.ends_with('>')
                && !resolved_url.ends_with('"')
                && !resolved_url.ends_with('\''),
            "Punctuation leak detected: '{}'",
            resolved_url
        );
    }
}
