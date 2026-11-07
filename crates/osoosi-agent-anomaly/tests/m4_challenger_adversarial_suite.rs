//! Milestone 4 Empirical Adversarial Challenge Suite (Challenger 1: OshoosiClaw)
//!
//! Rigorous empirical stress tests and edge-case verification for:
//! 1. Vector 1: Hook synonym permutations and malformed JSON-RPC payloads in `agent_hooks.rs`
//! 2. Vector 3: Obfuscated command parsing and shell unwrapping in `semantic_command.rs`
//! 3. Vector 4: Deal values edge cases and HIPAA checksums in `semantic_dlp.rs`
//! 4. Vector 5: Siquery recursive CTE read-only authorizer and 15s timeout in `siquery.rs`
//! 5. Vector 6: Sliding-window circumvention correlation across WSL2 boundaries in `circumvention.rs`

use osoosi_agent_anomaly::agent_hooks::{
    evaluate_hook_synchronously, format_claude_response, format_copilot_response,
    format_cursor_response, format_mcp_error_response, format_opencode_response,
    parse_claude_request, parse_copilot_request, parse_cursor_request, parse_mcp_call_request,
    parse_opencode_request, HookEventType, NormalizedHookRequest, SupportedAgentKind,
    GLOBAL_CORRELATOR,
};
use osoosi_agent_anomaly::circumvention::{
    classify_denial_pattern, DenialPatternKind, DynamicDenialSignal,
    TemporalCircumventionCorrelator,
};
use osoosi_agent_anomaly::semantic_command::{
    is_env_var_assignment, parse_semantic_command, tokenize_command, unwrap_env_invocation,
    unwrap_shell_invocation, PrivilegeEquivalenceClass,
};
use osoosi_agent_anomaly::siquery::SiqueryEngine;
use osoosi_dp::semantic_dlp::{
    DlpClassification, DlpPolicy, PresidioGlinerPiiZeroGuard, RedactXStructuredValidator,
    SemanticDlpEngine, SemanticEntityKind,
};
use std::time::{Duration, Instant};

// ============================================================================
// Vector 1: Hook Synonym Permutations & Malformed JSON-RPC Payloads
// ============================================================================

#[test]
fn test_challenger_hook_wire_synonyms_exhaustive() {
    // 1. Cursor wire format with cursor_command and cursor_trace_id
    let cursor_json = serde_json::json!({
        "cursor_command": "npm install",
        "cursor_trace_id": "trace-cursor-999",
        "context_paths": ["/workspace/package.json"]
    });
    let req = NormalizedHookRequest::from_json(&cursor_json);
    assert_eq!(req.agent, SupportedAgentKind::Cursor);
    assert_eq!(req.command.as_deref(), Some("npm install"));
    assert_eq!(req.session_id.as_deref(), Some("trace-cursor-999"));
    assert_eq!(req.file_path.as_deref(), Some("/workspace/package.json"));

    // 2. Copilot wire format with copilot_action and editor_context
    let copilot_json = serde_json::json!({
        "copilot_action": "refactor function",
        "editor_context": "/src/main.rs",
        "sessionId": "session-copilot-42"
    });
    let req = NormalizedHookRequest::from_json(&copilot_json);
    assert_eq!(req.agent, SupportedAgentKind::Copilot);
    assert_eq!(req.command.as_deref(), Some("refactor function"));
    assert_eq!(req.file_path.as_deref(), Some("/src/main.rs"));
    assert_eq!(req.session_id.as_deref(), Some("session-copilot-42"));

    // 3. OpenCode wire format with subcommand and working_file
    let opencode_json = serde_json::json!({
        "subcommand": "build --release",
        "working_file": "/crates/lib.rs",
        "type": "before"
    });
    let req = NormalizedHookRequest::from_json(&opencode_json);
    assert_eq!(req.agent, SupportedAgentKind::OpenCode);
    assert_eq!(req.command.as_deref(), Some("build --release"));
    assert_eq!(req.file_path.as_deref(), Some("/crates/lib.rs"));
    assert_eq!(req.event_type, HookEventType::Custom("before".to_string()));

    // Dedicated OpenCode parser maps "before" to PreToolUse
    let opencode_parsed = parse_opencode_request(&opencode_json.to_string()).unwrap();
    assert_eq!(opencode_parsed.agent, SupportedAgentKind::OpenCode);
    assert_eq!(opencode_parsed.event_type, HookEventType::PreToolUse);

    // 4. Claude Code format with tool_name and arguments
    let claude_json = serde_json::json!({
        "tool_name": "Bash",
        "arguments": {
            "command": "git status"
        }
    });
    let req = NormalizedHookRequest::from_json(&claude_json);
    assert_eq!(req.agent, SupportedAgentKind::Claude);
    assert_eq!(req.tool_name.as_deref(), Some("Bash"));
    assert_eq!(req.command.as_deref(), Some("git status"));

    // 5. Array of commands / paths
    let arr_json = serde_json::json!({
        "command": ["cargo", "test", "--workspace"],
        "context_paths": ["/src/a.rs", "/src/b.rs"]
    });
    let req = NormalizedHookRequest::from_json(&arr_json);
    assert_eq!(req.command.as_deref(), Some("cargo test --workspace"));
    assert_eq!(req.file_path.as_deref(), Some("/src/a.rs"));

    // 6. PostToolUse signals: exit_code and stderr
    let post_json = serde_json::json!({
        "exit_code": 1,
        "stderr": "sudo: a password is required"
    });
    let req = NormalizedHookRequest::from_json(&post_json);
    assert_eq!(req.event_type, HookEventType::PostToolUse);
    assert_eq!(req.exit_code, Some(1));
    assert_eq!(req.stderr.as_deref(), Some("sudo: a password is required"));
}

#[test]
fn test_challenger_mcp_jsonrpc_id_preservation_and_malformed() {
    // 1. String ID preservation
    let string_id = serde_json::json!("mcp-call-777");
    let decision = osoosi_agent_anomaly::agent_hooks::HookEvaluationDecision::deny(
        "Privileged execution blocked",
        Some("Layer 1"),
        Some("Use unprivileged commands"),
        15,
    );
    let resp_str = format_mcp_error_response(&string_id, &decision);
    let resp: serde_json::Value = serde_json::from_str(&resp_str).expect("Valid JSON");
    assert_eq!(resp["jsonrpc"], "2.0");
    assert_eq!(resp["id"], "mcp-call-777");
    assert_eq!(resp["error"]["code"], -32000);
    assert!(resp["error"]["message"].as_str().unwrap().contains("Privileged execution blocked"));

    // 2. Numeric ID preservation
    let num_id = serde_json::json!(42069);
    let resp_str = format_mcp_error_response(&num_id, &decision);
    let resp: serde_json::Value = serde_json::from_str(&resp_str).expect("Valid JSON");
    assert_eq!(resp["id"], 42069);

    // 3. Null ID preservation
    let null_id = serde_json::Value::Null;
    let resp_str = format_mcp_error_response(&null_id, &decision);
    let resp: serde_json::Value = serde_json::from_str(&resp_str).expect("Valid JSON");
    assert_eq!(resp["id"], serde_json::Value::Null);

    // 4. Malformed JSON parsing
    let malformed = "{ not a json";
    assert!(NormalizedHookRequest::from_json_str(malformed).is_err());
    assert!(parse_mcp_call_request(malformed).is_err());

    // 5. Wrong method (not tools/call)
    let non_tool_call = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {}
    }).to_string();
    assert!(parse_mcp_call_request(&non_tool_call).is_err());

    // 6. Valid tools/call method
    let valid_tool_call = serde_json::json!({
        "jsonrpc": "2.0",
        "id": "req-1",
        "method": "tools/call",
        "params": {
            "name": "execute_command",
            "arguments": {
                "command": "echo 'safe'"
            }
        }
    }).to_string();
    let parsed = parse_mcp_call_request(&valid_tool_call).expect("Should parse tools/call");
    assert_eq!(parsed.agent, SupportedAgentKind::Mcp);
    assert_eq!(parsed.tool_name.as_deref(), Some("execute_command"));
    assert_eq!(parsed.command.as_deref(), Some("echo 'safe'"));
    assert_eq!(parsed.rpc_id, Some(serde_json::json!("req-1")));
}

#[test]
fn test_challenger_hook_evaluation_6_layer_pipeline() {
    // Layer 1: Privilege Escalation Command AST Denied
    let mut req = NormalizedHookRequest::default();
    req.command = Some("sudo cat /etc/hosts".to_string());
    let dec = evaluate_hook_synchronously(&req);
    assert!(!dec.allowed, "sudo elevation must be blocked by Layer 1");
    assert_eq!(dec.denied_by_layer.as_deref(), Some("Layer 1: SemanticCommandAst"));

    // SensitiveSystemPathGuard: Access to /etc/shadow Denied
    let mut req = NormalizedHookRequest::default();
    req.file_path = Some("/etc/shadow".to_string());
    let dec = evaluate_hook_synchronously(&req);
    assert!(!dec.allowed, "Access to /etc/shadow must be blocked");
    assert_eq!(dec.denied_by_layer.as_deref(), Some("SensitiveSystemPathGuard"));

    // Layer 3: Semantic DLP Deal Value >= $1M Denied
    let mut req = NormalizedHookRequest::default();
    req.command = Some("echo 'The acquisition price is $5,000,000 in cash'".to_string());
    let dec = evaluate_hook_synchronously(&req);
    assert!(!dec.allowed, "Deal values >= $1M must be denied");
    assert_eq!(dec.denied_by_layer.as_deref(), Some("Layer 3: SemanticDlpEngine"));

    // Layer 3: Semantic DLP PHI (SSN) Denied
    let mut req = NormalizedHookRequest::default();
    req.command = Some("echo 'Patient record SSN 123-45-6789'".to_string());
    let dec = evaluate_hook_synchronously(&req);
    assert!(!dec.allowed, "Clinical PHI with SSN must be denied");
    assert_eq!(dec.denied_by_layer.as_deref(), Some("Layer 3: SemanticDlpEngine"));

    // Benign command Allowed
    let mut req = NormalizedHookRequest::default();
    req.command = Some("git log -n 5".to_string());
    let dec = evaluate_hook_synchronously(&req);
    assert!(dec.allowed, "Benign git log command must be allowed");

    // Formatter verification
    let (code, msg) = format_claude_response(&dec);
    assert_eq!(code, 0);
    assert!(msg.is_empty());

    let (code, msg) = format_cursor_response(&dec);
    assert_eq!(code, 0);
    let val: serde_json::Value = serde_json::from_str(&msg).unwrap();
    assert_eq!(val["permission"], "allow");

    let (code, msg) = format_copilot_response(&dec);
    assert_eq!(code, 0);
    let val: serde_json::Value = serde_json::from_str(&msg).unwrap();
    assert_eq!(val["permissionDecision"], "allow");

    let (code, msg) = format_opencode_response(&dec);
    assert_eq!(code, 0);
    let val: serde_json::Value = serde_json::from_str(&msg).unwrap();
    assert_eq!(val["allow"], true);
}

// ============================================================================
// Vector 3: Obfuscated Command Parsing and Shell Unwrapping
// ============================================================================

#[test]
fn test_challenger_nested_shell_and_env_unwrapping() {
    // 1. Nested sh -c inside bash -c
    let cmd1 = "sh -c \"bash -c 'sudo id'\"";
    let sem1 = parse_semantic_command(cmd1);
    assert_eq!(
        sem1.privilege_class,
        PrivilegeEquivalenceClass::RootOrAdminElevation,
        "Nested sh -c + bash -c sudo must be RootOrAdminElevation"
    );

    // 2. Windows cmd.exe /c wrapping powershell.exe -Command
    let cmd2 = "cmd.exe /c \"powershell.exe -Command sudo ls\"";
    let sem2 = parse_semantic_command(cmd2);
    assert_eq!(
        sem2.privilege_class,
        PrivilegeEquivalenceClass::RootOrAdminElevation,
        "cmd.exe /c powershell -Command sudo must be RootOrAdminElevation"
    );

    // 3. GNU env -S unnesting
    let cmd3 = "env -S \"sudo cat /etc/shadow\"";
    let sem3 = parse_semantic_command(cmd3);
    assert_eq!(
        sem3.privilege_class,
        PrivilegeEquivalenceClass::RootOrAdminElevation,
        "env -S sudo must be RootOrAdminElevation"
    );

    // 4. GNU env --split-string= unnesting
    let cmd4 = "env --split-string=\"sudo -u root whoami\"";
    let sem4 = parse_semantic_command(cmd4);
    assert_eq!(
        sem4.privilege_class,
        PrivilegeEquivalenceClass::RootOrAdminElevation,
        "env --split-string= sudo must be RootOrAdminElevation"
    );

    // 5. Environment variable assignments prior to execution
    let cmd5 = "SUDO_ASKPASS=/bin/false VAR=1 sudo id";
    let sem5 = parse_semantic_command(cmd5);
    assert_eq!(
        sem5.privilege_class,
        PrivilegeEquivalenceClass::RootOrAdminElevation,
        "VAR=1 sudo id must be RootOrAdminElevation"
    );
    assert!(sem5.env_vars.iter().any(|(k, v)| k == "SUDO_ASKPASS" && v == "/bin/false"));
    assert!(sem5.env_vars.iter().any(|(k, v)| k == "VAR" && v == "1"));
}

#[test]
fn test_challenger_privilege_equivalence_taxonomy() {
    // RootOrAdminElevation
    let roots = [
        "sudo whoami",
        "sudo -u root id",
        "sudo -u 0 id",
        "su",
        "su -",
        "su root",
        "doas whoami",
        "pkexec /bin/sh",
        "runas /user:Administrator cmd",
        "runas /user:admin powershell",
        "wsl -u root id",
        "wsl --user 0 id",
    ];
    for r in &roots {
        let sem = parse_semantic_command(r);
        assert_eq!(
            sem.privilege_class,
            PrivilegeEquivalenceClass::RootOrAdminElevation,
            "Command '{}' must be classified as RootOrAdminElevation",
            r
        );
    }

    // TargetUserDelegation
    let delegated = [
        "sudo -u nobody whoami",
        "su nobody",
        "runas /user:guest cmd",
        "wsl -u testuser id",
        "doas -u www-data /bin/sh",
    ];
    for d in &delegated {
        let sem = parse_semantic_command(d);
        assert_eq!(
            sem.privilege_class,
            PrivilegeEquivalenceClass::TargetUserDelegation,
            "Command '{}' must be classified as TargetUserDelegation",
            d
        );
    }

    // PrivilegeQueryOrBenign
    let queries = [
        "sudo -l",
        "sudo -V",
        "sudo -h",
        "pkexec --version",
        "wsl --status",
        "wsl -l -v",
        "su --help",
    ];
    for q in &queries {
        let sem = parse_semantic_command(q);
        assert_eq!(
            sem.privilege_class,
            PrivilegeEquivalenceClass::PrivilegeQueryOrBenign,
            "Command '{}' must be classified as PrivilegeQueryOrBenign",
            q
        );
    }

    // UnprivilegedStandard
    let standard = [
        "ls -la",
        "cat /tmp/notes.txt",
        "git status",
        "cargo test",
        "python -m http.server 8000",
    ];
    for s in &standard {
        let sem = parse_semantic_command(s);
        assert_eq!(
            sem.privilege_class,
            PrivilegeEquivalenceClass::UnprivilegedStandard,
            "Command '{}' must be classified as UnprivilegedStandard",
            s
        );
    }
}

// ============================================================================
// Vector 4: Semantic DLP Deal Values & HIPAA Checksums
// ============================================================================

#[test]
fn test_challenger_deal_values_boundaries_and_currencies() {
    let engine = SemanticDlpEngine::new();

    // Deal value >= $1M -> CrownJewel, Quarantine
    let high_deals = [
        "The acquisition price was $1,500,000 for the startup",
        "Deal size: EUR 2.5 million confirmed",
        "Valuation reached £10B in the latest merger",
        "purchase price: usd 5000000 cash",
        "deal value: $1,000,000 exactly",
    ];
    for d in &high_deals {
        let entities = engine.scan_payload(d);
        assert!(
            entities.iter().any(|e| e.kind == SemanticEntityKind::DealValue
                && e.classification == DlpClassification::CrownJewel
                && e.policy == DlpPolicy::Quarantine),
            "Payload '{}' MUST be detected as DealValue CrownJewel Quarantine",
            d
        );
    }

    // Deal value < $1M -> Confidential, Block
    let low_deals = [
        "deal value: $999,999 for the minor asset",
        "deal size: $500,000 in escrow",
        "acquisition price: $250k seed funding",
    ];
    for d in &low_deals {
        let entities = engine.scan_payload(d);
        assert!(
            entities.iter().any(|e| e.kind == SemanticEntityKind::DealValue
                && e.classification == DlpClassification::Confidential
                && e.policy == DlpPolicy::Block),
            "Payload '{}' MUST be detected as DealValue Confidential Block",
            d
        );
    }

    // Non-deal context: numbers should not trigger DealValue
    let non_deal = "The department spent $5,000,000 on software licenses this quarter";
    let entities = engine.scan_payload(non_deal);
    assert!(
        !entities.iter().any(|e| e.kind == SemanticEntityKind::DealValue),
        "Non-deal financial amount must NOT trigger DealValue"
    );
}

#[test]
fn test_challenger_hipaa_redactx_checksums() {
    // 1. Luhn NPI 80840 10-digit validation
    assert!(RedactXStructuredValidator::npi_valid("1234567893"));
    assert!(!RedactXStructuredValidator::npi_valid("1234567890"));
    assert!(!RedactXStructuredValidator::npi_valid("0000000000"));

    // 2. SSN validation: area 000, 666, 900+ forbidden
    assert!(RedactXStructuredValidator::ssn_valid("123", "45", "6789"));
    assert!(!RedactXStructuredValidator::ssn_valid("000", "45", "6789"));
    assert!(!RedactXStructuredValidator::ssn_valid("666", "45", "6789"));
    assert!(!RedactXStructuredValidator::ssn_valid("900", "45", "6789"));
    assert!(!RedactXStructuredValidator::ssn_valid("123", "00", "6789"));
    assert!(!RedactXStructuredValidator::ssn_valid("123", "45", "0000"));

    // 3. Clinical PHI scanning in payload
    let engine = SemanticDlpEngine::new();
    let phi_payload = "Patient John Doe, attending physician Dr. Smith, NPI 1234567893, SSN 123-45-6789";
    let entities = engine.scan_payload(phi_payload);
    assert!(
        entities.iter().any(|e| e.kind == SemanticEntityKind::PhiMedicalRecord),
        "Clinical payload must trigger PhiMedicalRecord entity"
    );

    // 4. Fail-closed unclassified containment
    let unclassified_payload = "Project Apollo architectural overview [CONFIDENTIAL]";
    let verdict = engine.evaluate_verdict_fail_closed(unclassified_payload);
    assert!(
        verdict.is_restricted() || verdict.is_deny(),
        "Fail-closed evaluation must restrict confidential payload"
    );
}

// ============================================================================
// Vector 5: Siquery Recursive CTE Read-Only Authorizer & 15s Timeout
// ============================================================================

#[test]
fn test_challenger_siquery_recursive_cte_read_only_allowed() {
    let engine = SiqueryEngine::new();

    // Recursive CTE generating sequence 1..10
    let query = "WITH RECURSIVE cnt(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM cnt WHERE x<10) SELECT x FROM cnt;";
    let rows = engine.execute_query(query).expect("Recursive CTE must be allowed by AuthAction::Recursive");
    assert_eq!(rows.len(), 10, "Recursive CTE must return exactly 10 rows");
    assert_eq!(rows[0].get("x"), Some(&serde_json::json!(1)));
    assert_eq!(rows[9].get("x"), Some(&serde_json::json!(10)));
}

#[test]
fn test_challenger_siquery_mutating_sql_forbidden() {
    let engine = SiqueryEngine::new();

    // 1. INSERT forbidden
    let res = engine.execute_query("INSERT INTO processes (pid) VALUES (9999);");
    assert!(res.is_err(), "INSERT statement must be rejected as mutating SQL");

    // 2. DROP TABLE forbidden
    let res = engine.execute_query("DROP TABLE processes;");
    assert!(res.is_err(), "DROP statement must be rejected");

    // 3. UPDATE forbidden
    let res = engine.execute_query("UPDATE processes SET name = 'evil' WHERE pid = 1;");
    assert!(res.is_err(), "UPDATE statement must be rejected");

    // 4. CREATE TABLE forbidden
    let res = engine.execute_query("CREATE TABLE malicious (id INT);");
    assert!(res.is_err(), "CREATE statement must be rejected");
}

#[test]
fn test_challenger_siquery_pragma_and_read_only_safety() {
    let engine = SiqueryEngine::new();

    // PRAGMA query allowed
    let pragma_query = "PRAGMA table_info(processes);";
    let rows = engine.execute_query(pragma_query).expect("PRAGMA table_info must be allowed");
    assert!(!rows.is_empty(), "PRAGMA table_info must return column metadata");
}

// ============================================================================
// Vector 6: Sliding-Window Circumvention Correlation Across WSL2 Boundaries
// ============================================================================

#[test]
fn test_challenger_circumvention_60s_sliding_window_wsl2() {
    let correlator = TemporalCircumventionCorrelator::new(Duration::from_secs(60));
    let session = "sess-challenger-circ-wsl2";
    let now = Instant::now();

    // Step 1: Initial failed elevation attempt (sudo -n id -> exit 1, permission denied)
    let denial = DynamicDenialSignal::new(
        "denial-001",
        session,
        None,
        5000,
        "sudo -n id",
        PrivilegeEquivalenceClass::RootOrAdminElevation,
        Some(1),
        true,
        Some("sudo: a password is required".to_string()),
        now,
    );
    correlator.record_denial(denial);
    assert_eq!(correlator.active_denial_count(), 1);

    // Step 2: Retry within 60s window across WSL2 boundary (`wsl -u root id`)
    let retry_time = now + Duration::from_secs(5);
    let alert = correlator.check_candidate(session, None, "wsl -u root id", retry_time);
    assert!(alert.is_some(), "WSL cross-boundary retry within 60s MUST trigger circumvention alert");

    let a = alert.unwrap();
    assert_eq!(a.session_id, session);
    assert_eq!(a.severity, "CRITICAL");
    assert_eq!(a.severity_code, 4);
    assert!(a.crossed_wsl_boundary, "Must flag crossed_wsl_boundary == true");
    assert_eq!(a.retry_command, "wsl -u root id");
    assert!(a.summary.contains("Incident A Circumvention Detected"));
}

#[test]
fn test_challenger_circumvention_window_expiry() {
    let correlator = TemporalCircumventionCorrelator::new(Duration::from_secs(60));
    let session = "sess-challenger-circ-expiry";
    let now = Instant::now();

    // Initial denial at t=0
    let denial = DynamicDenialSignal::new(
        "denial-002",
        session,
        None,
        5001,
        "sudo -n cat /etc/shadow",
        PrivilegeEquivalenceClass::RootOrAdminElevation,
        Some(1),
        true,
        Some("Permission denied".to_string()),
        now,
    );
    correlator.record_denial(denial);

    // Retry after 65s (window expired)
    let expired_time = now + Duration::from_secs(65);
    let alert = correlator.check_candidate(session, None, "wsl -u root cat /etc/shadow", expired_time);
    assert!(
        alert.is_none(),
        "Retry after 60s window expired must NOT trigger circumvention alert"
    );
}
