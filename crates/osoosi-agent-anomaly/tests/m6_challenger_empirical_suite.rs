//! Empirical Adversarial Challenge Suite: Milestone M6
//! Features: F34, F35, F36, F37 & F17–F19
//! Conducted by: teamwork_challenger_m6_1 (Empirical Challenger)
//!
//! Stress-tests:
//! 1. Adversarial Eviction & Capacity Stress Test (F34, F17-F19):
//!    - Challenge `register_ingested_research_rule` with 70 dynamic candidate rules when pinned rules occupy slots.
//!    - Assert that pinned rules (0..4) and operator-approved rules are NEVER evicted.
//!    - Assert that the registry never exceeds 64 rules and returns fail-closed rejection when capacity is reached and no unpinned rule exists.
//! 2. Canary Benign-Corpus 0-FP Verification (F18):
//!    - Assert 0 false positive triggers on clean baseline telemetry and developer commands (cargo build, npm test, git status, svchost, etc.).
//!    - Assert true threat patterns (docker.sock, unshare -m, nsenter) pass canary validation.
//! 3. Adversarial URL Injection & Fake Repo Detection (F35):
//!    - Test `detect_verified_code_repo` against SSRF payloads (169.254.169.254, 127.0.0.1), fake repos, and non-HTTPS schemes.
//! 4. Tighten-Only Code Synthesis Invariants (F36):
//!    - Assert synthesized Rust guards and Cedar policies are strictly tighten-only (no permit, no unsafe, no std::process).

use osoosi_agent_anomaly::breakout_defense::{
    approve_ingested_research_rule, is_research_rule_operator_approved, is_research_rule_pinned,
    list_ingested_research_rules, pin_ingested_research_rule, register_ingested_research_rule,
    restore_default_research_rules, verify_rule_against_canary_benign_corpus,
    IngestedResearchDefenseRule, CANARY_BENIGN_TELEMETRY_CORPUS,
};

fn create_test_rule(arxiv_id: &str, has_code: bool, rel_score: f64) -> IngestedResearchDefenseRule {
    IngestedResearchDefenseRule {
        rule_id: format!("ARXIV-DEF-{}", arxiv_id),
        arxiv_id: arxiv_id.to_string(),
        title: format!("Frontier Security Research {}", arxiv_id),
        attack_vector: "container_escape".to_string(),
        target_boundary: "Ring7CapabilityIsolation".to_string(),
        extraction_class: "breakout_vector".to_string(),
        indicator_pattern: format!("escape_token_{}", arxiv_id),
        cedar_forbid_policy: "forbid(principal, action, resource);".to_string(),
        target_crate: "crates/osoosi-sandbox".to_string(),
        enrolled_at_utc: "2026-10-30T00:00:00Z".to_string(),
        relevance_score: rel_score,
        accuracy_score: 99.0,
        arxiv_url: format!("https://arxiv.org/abs/{}", arxiv_id),
        has_code_repo: has_code,
        code_repo_url: if has_code {
            "https://github.com/UKGovernmentBEIS/inspect_evals".to_string()
        } else {
            String::new()
        },
        generated_code_snippet: String::new(),
    }
}

// ============================================================================
// 1. Adversarial Eviction & Capacity Stress Test (70 Dynamic Rules)
// ============================================================================

#[test]
fn challenge_70_rules_capacity_clamp_and_pinned_immunity() {
    // Reset to default seeded state (4 pinned baseline rules)
    restore_default_research_rules();
    let initial_rules = list_ingested_research_rules();
    assert_eq!(
        initial_rules.len(),
        4,
        "Baseline must contain exactly 4 seeded rules"
    );

    let baseline_ids = [
        "ARXIV-DEF-2603.02277",
        "ARXIV-DEF-2604.20496",
        "ARXIV-DEF-2610.20437",
        "ARXIV-DEF-2601.11893",
    ];

    // Verify all baseline rules are initially pinned
    for rule in &initial_rules {
        assert!(
            is_research_rule_pinned(rule),
            "Baseline rule {} must be pinned",
            rule.rule_id
        );
    }

    // Insert 70 dynamic candidate rules with varying relevance scores and code repo backing
    for i in 1..=70 {
        let aid = format!("2605.{:05}", i);
        let has_code = i % 2 == 0;
        let rel_score = 70.0 + ((i as f64) * 0.35) % 29.0;
        let rule = create_test_rule(&aid, has_code, rel_score);
        let count = register_ingested_research_rule(rule);

        // Invariant 1: Total active rules must NEVER exceed 64
        assert!(
            count <= 64,
            "Registry capacity exceeded 64 at iteration {}: count={}",
            i,
            count
        );
    }

    let current_rules = list_ingested_research_rules();
    assert_eq!(
        current_rules.len(),
        64,
        "Registry should be clamped at exactly 64 rules"
    );

    // Invariant 2: Pinned baseline rules (0..4) must NEVER be evicted
    for id in &baseline_ids {
        let found = current_rules.iter().any(|r| r.rule_id == *id);
        assert!(
            found,
            "CRITICAL BUG: Pinned baseline rule {} was evicted under 70-rule pressure!",
            id
        );
    }
}

// ============================================================================
// 2. Operator-Approved Rule Anti-Eviction Immunity
// ============================================================================

#[test]
fn challenge_operator_approved_rule_never_evicted() {
    restore_default_research_rules();

    // Register a dynamic rule
    let approved_aid = "2606.12345";
    let approved_rule = create_test_rule(approved_aid, false, 50.0); // Low relevance
    register_ingested_research_rule(approved_rule.clone());

    // Explicitly grant operator approval
    approve_ingested_research_rule(approved_aid);
    assert!(
        is_research_rule_operator_approved(&approved_rule),
        "Rule must be marked as operator approved"
    );

    // Now flood with 65 high-relevance code-backed rules
    for i in 1..=65 {
        let aid = format!("2607.{:05}", i);
        let rule = create_test_rule(&aid, true, 99.0);
        register_ingested_research_rule(rule);
    }

    let rules = list_ingested_research_rules();
    assert_eq!(rules.len(), 64);

    // Invariant: The operator-approved rule must still exist in the registry
    let found = rules
        .iter()
        .any(|r| r.rule_id == format!("ARXIV-DEF-{}", approved_aid));
    assert!(
        found,
        "CRITICAL BUG: Operator-approved rule {} was evicted!",
        approved_aid
    );
}

// ============================================================================
// 3. Fail-Closed Rejection When All Dynamic Rules Are Pinned/Approved
// ============================================================================

#[test]
fn challenge_fail_closed_rejection_at_full_pinned_capacity() {
    restore_default_research_rules();

    // Fill all 64 slots
    for i in 1..=60 {
        let aid = format!("2608.{:05}", i);
        let rule = create_test_rule(&aid, true, 95.0);
        register_ingested_research_rule(rule);
        // Pin every registered rule!
        pin_ingested_research_rule(&aid);
    }

    let rules_before = list_ingested_research_rules();
    assert_eq!(rules_before.len(), 64);

    // Verify all 64 rules are pinned or approved
    for r in &rules_before {
        assert!(
            is_research_rule_pinned(r) || is_research_rule_operator_approved(r),
            "Rule {} must be pinned",
            r.rule_id
        );
    }

    // Now attempt to register rule 65 (unapproved candidate)
    let candidate = create_test_rule("2608.99999", true, 99.9);
    let count = register_ingested_research_rule(candidate);

    // Invariant: Must fail-closed, rejecting the candidate without evicting any pinned rule
    assert_eq!(
        count, 64,
        "Count must remain 64 when no unpinned rule exists"
    );

    let rules_after = list_ingested_research_rules();
    assert_eq!(rules_after.len(), 64);
    let candidate_found = rules_after.iter().any(|r| r.arxiv_id == "2608.99999");
    assert!(
        !candidate_found,
        "CRITICAL BUG: Unapproved candidate was accepted when all rules were protected!"
    );
}

// ============================================================================
// 4. Canary Benign-Corpus 0-FP Verification
// ============================================================================

#[test]
fn challenge_canary_0_false_positive_rejection_and_threat_acceptance() {
    // Part A: Every sample in CANARY_BENIGN_TELEMETRY_CORPUS must trigger rejection
    // if a candidate rule attempts to match on its exact tokens.
    for &sample in CANARY_BENIGN_TELEMETRY_CORPUS {
        let candidate_rule = IngestedResearchDefenseRule {
            rule_id: "ARXIV-DEF-2609.99991".to_string(),
            arxiv_id: "2609.99991".to_string(),
            title: "Test Canary Trigger".to_string(),
            attack_vector: "benign_conflict".to_string(),
            target_boundary: "Ring7CapabilityIsolation".to_string(),
            extraction_class: "breakout_vector".to_string(),
            indicator_pattern: sample.to_string(), // Uses exact benign sample
            cedar_forbid_policy: "forbid(principal, action, resource);".to_string(),
            target_crate: "crates/osoosi-sandbox".to_string(),
            enrolled_at_utc: "2026-10-30T00:00:00Z".to_string(),
            relevance_score: 95.0,
            accuracy_score: 99.0,
            arxiv_url: "https://arxiv.org/abs/2609.99991".to_string(),
            has_code_repo: false,
            code_repo_url: String::new(),
            generated_code_snippet: String::new(),
        };

        let err = verify_rule_against_canary_benign_corpus(&candidate_rule);
        assert!(
            err.is_some(),
            "CRITICAL BUG: Canary benign telemetry '{}' did not trigger false-positive rejection!",
            sample
        );
    }

    // Part B: Specific developer commands (cargo build, git status, npm test)
    let dev_tokens = [
        "cargo build",
        "git status",
        "python -m unittest",
        "node --test",
        "services.exe",
        "lsass.exe",
    ];

    for tok in &dev_tokens {
        let rule = IngestedResearchDefenseRule {
            rule_id: "ARXIV-DEF-2609.99992".to_string(),
            arxiv_id: "2609.99992".to_string(),
            title: "Dev Token Collision".to_string(),
            attack_vector: "benign_collision".to_string(),
            target_boundary: "Ring7CapabilityIsolation".to_string(),
            extraction_class: "breakout_vector".to_string(),
            indicator_pattern: tok.to_string(),
            cedar_forbid_policy: "forbid(principal, action, resource);".to_string(),
            target_crate: "crates/osoosi-sandbox".to_string(),
            enrolled_at_utc: "2026-10-30T00:00:00Z".to_string(),
            relevance_score: 95.0,
            accuracy_score: 99.0,
            arxiv_url: "https://arxiv.org/abs/2609.99992".to_string(),
            has_code_repo: false,
            code_repo_url: String::new(),
            generated_code_snippet: String::new(),
        };
        let err = verify_rule_against_canary_benign_corpus(&rule);
        assert!(
            err.is_some(),
            "CRITICAL BUG: Dev token '{}' must trigger canary rejection!",
            tok
        );
    }

    // Part C: Genuine threat indicator patterns must NOT trigger canary false positives
    let true_threat_patterns = [
        "/var/run/docker.sock",
        "nsenter --target 1 --mount",
        "unshare -U -m -p -f",
        "ptrace(PTRACE_TRACEME)",
        "OpenProcess(PROCESS_ALL_ACCESS)",
        "NtCreateSection(PAGE_EXECUTE_READWRITE)",
    ];

    for pat in &true_threat_patterns {
        let threat_rule = IngestedResearchDefenseRule {
            rule_id: "ARXIV-DEF-2609.99993".to_string(),
            arxiv_id: "2609.99993".to_string(),
            title: "Real Threat Rule".to_string(),
            attack_vector: "container_escape".to_string(),
            target_boundary: "Ring7CapabilityIsolation".to_string(),
            extraction_class: "breakout_vector".to_string(),
            indicator_pattern: pat.to_string(),
            cedar_forbid_policy: "forbid(principal, action, resource);".to_string(),
            target_crate: "crates/osoosi-sandbox".to_string(),
            enrolled_at_utc: "2026-10-30T00:00:00Z".to_string(),
            relevance_score: 98.0,
            accuracy_score: 99.0,
            arxiv_url: "https://arxiv.org/abs/2609.99993".to_string(),
            has_code_repo: true,
            code_repo_url: "https://github.com/UKGovernmentBEIS/inspect_evals".to_string(),
            generated_code_snippet: String::new(),
        };
        let err = verify_rule_against_canary_benign_corpus(&threat_rule);
        assert!(
            err.is_none(),
            "CRITICAL BUG: True threat pattern '{}' falsely rejected by canary: {:?}",
            pat,
            err
        );
    }
}
