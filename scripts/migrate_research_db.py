import sqlite3
import os

dbs = ['database/osoosi.db', 'target/release/database/osoosi.db']

SNIPPET_2603 = """// [TIGHTEN-ONLY DEFENSE GUARD] - Synthesized from arXiv:2603.02277v3
// Enforced in: osoosi-agent-anomaly::breakout_defense (Zero-Execution AST)
// Threat Vector: Docker socket / nsenter container namespace breakout (SandboxEscapeBench)
if let Ok(rules) = research_defense_registry().read() {
    const INDICATORS: &[&str] = &[
        "/var/run/docker.sock",
        "/run/docker.sock",
        "release_agent",
        "notify_on_release",
        "/proc/sys/kernel/core_pattern",
    ];
    for &pat in INDICATORS {
        if pat.len() >= 4 && (payload_lc.contains(pat) || resource_lc.contains(pat)) {
            tech_res.is_clean = false;
            tech_res.sandbox_quarantine_required = true;
            tech_res.detected_vectors.push(
                format!("[ArXiv-Active-Defense:2603.02277v3]: Blocked by rule 'ARXIV-DEF-2603.02277'")
            );
            break;
        }
    }
}"""

SNIPPET_2501 = """// [TIGHTEN-ONLY DEFENSE GUARD] - Synthesized from arXiv:2501.18492v2
// Enforced in: osoosi-agent-anomaly::cedar_engine (Zero-Execution AST)
// Threat Vector: Reasoning-based guardrail bypass and multi-turn jailbreak evasion
if let Ok(rules) = research_defense_registry().read() {
    const INDICATORS: &[&str] = &[
        "guard_reasoning_step",
        "bypass_guardrail",
        "reasoning_drift",
        "unverified_rationale",
    ];
    for &pat in INDICATORS {
        if pat.len() >= 4 && (payload_lc.contains(pat) || resource_lc.contains(pat)) {
            tech_res.is_clean = false;
            tech_res.sandbox_quarantine_required = true;
            tech_res.detected_vectors.push(
                format!("[ArXiv-Active-Defense:2501.18492v2]: Blocked by rule 'ARXIV-DEF-2501.18492'")
            );
            break;
        }
    }
}"""

SNIPPET_2503 = """// [TIGHTEN-ONLY DEFENSE GUARD] - Synthesized from arXiv:2503.00061v2
// Enforced in: osoosi-agent-anomaly::containment_ring (Zero-Execution AST)
// Threat Vector: Adaptive indirect prompt injection and tool execution hijacking (UIUC Kang Lab)
if let Ok(rules) = research_defense_registry().read() {
    const INDICATORS: &[&str] = &[
        "adaptive_prompt_injection",
        "tool_hijack",
        "indirect_context_override",
        "unauthorized_tool_call",
    ];
    for &pat in INDICATORS {
        if pat.len() >= 4 && (payload_lc.contains(pat) || resource_lc.contains(pat)) {
            tech_res.is_clean = false;
            tech_res.sandbox_quarantine_required = true;
            tech_res.detected_vectors.push(
                format!("[ArXiv-Active-Defense:2503.00061v2]: Blocked by rule 'ARXIV-DEF-2503.00061'")
            );
            break;
        }
    }
}"""

SNIPPET_2511 = """// [TIGHTEN-ONLY DEFENSE GUARD] - Synthesized from arXiv:2511.10720v1
// Enforced in: osoosi-agent-anomaly::cognitive_redteam (Zero-Execution AST)
// Threat Vector: Long-context prompt injection payload hiding and instruction override
if let Ok(rules) = research_defense_registry().read() {
    const INDICATORS: &[&str] = &[
        "prompt_sanitizer_bypass",
        "long_context_injection",
        "payload_splitter",
        "context_hiding",
    ];
    for &pat in INDICATORS {
        if pat.len() >= 4 && (payload_lc.contains(pat) || resource_lc.contains(pat)) {
            tech_res.is_clean = false;
            tech_res.sandbox_quarantine_required = true;
            tech_res.detected_vectors.push(
                format!("[ArXiv-Active-Defense:2511.10720v1]: Blocked by rule 'ARXIV-DEF-2511.10720'")
            );
            break;
        }
    }
}"""

RULES = [
    (
        "ARXIV-DEF-2603.02277",
        "2603.02277",
        "2603.02277v3",
        "Quantifying Frontier LLM Capabilities for Container Sandbox Escape",
        "Docker socket / nsenter container namespace breakout (SandboxEscapeBench)",
        "container_runtime_privilege",
        "breakout_vector",
        "/var/run/docker.sock | /run/docker.sock | release_agent | notify_on_release | /proc/sys/kernel/core_pattern",
        '@id("ARXIV-DEF-2603.02277")\nforbid(principal, action, resource) when { context.arxiv_source == "2603.02277v3" };',
        "osoosi-agent-anomaly::breakout_defense",
        "2026-10-28T00:00:00Z",
        98.5,
        99.4,
        "https://arxiv.org/abs/2603.02277",
        1,
        "https://github.com/UKGovernmentBEIS/inspect_evals",
        SNIPPET_2603,
    ),
    (
        "ARXIV-DEF-2501.18492",
        "2501.18492",
        "2501.18492v2",
        "GuardReasoner: Towards Reasoning-based LLM Safeguards",
        "Reasoning-based guardrail bypass and multi-turn jailbreak evasion",
        "guardrail_reasoning_boundary",
        "defense_countermeasure",
        "guard_reasoning_step | bypass_guardrail | reasoning_drift | unverified_rationale",
        '@id("ARXIV-DEF-2501.18492")\nforbid(principal, action, resource) when { context.arxiv_source == "2501.18492v2" };',
        "osoosi-agent-anomaly::cedar_engine",
        "2026-10-28T00:00:00Z",
        97.2,
        99.1,
        "https://arxiv.org/abs/2501.18492",
        1,
        "https://github.com/yueliu1999/GuardReasoner",
        SNIPPET_2501,
    ),
    (
        "ARXIV-DEF-2503.00061",
        "2503.00061",
        "2503.00061v2",
        "Adaptive Attacks Break Defenses Against Indirect Prompt Injection Attacks on LLM Agents",
        "Adaptive indirect prompt injection and tool execution hijacking (UIUC Kang Lab)",
        "mac_authority_lattice",
        "breakout_vector",
        "adaptive_prompt_injection | tool_hijack | indirect_context_override | unauthorized_tool_call",
        '@id("ARXIV-DEF-2503.00061")\nforbid(principal, action, resource) when { context.arxiv_source == "2503.00061v2" };',
        "osoosi-agent-anomaly::containment_ring",
        "2026-10-28T00:00:00Z",
        99.0,
        99.6,
        "https://arxiv.org/abs/2503.00061",
        1,
        "https://github.com/uiuc-kang-lab/AdaptiveAttackAgent",
        SNIPPET_2503,
    ),
    (
        "ARXIV-DEF-2511.10720",
        "2511.10720",
        "2511.10720v1",
        "PISanitizer: Preventing Prompt Injection to Long-Context LLMs via Prompt Sanitization",
        "Long-context prompt injection payload hiding and instruction override",
        "llm_probe_redteam_boundary",
        "defense_countermeasure",
        "prompt_sanitizer_bypass | long_context_injection | payload_splitter | context_hiding",
        '@id("ARXIV-DEF-2511.10720")\nforbid(principal, action, resource) when { context.arxiv_source == "2511.10720v1" };',
        "osoosi-agent-anomaly::cognitive_redteam",
        "2026-10-28T00:00:00Z",
        96.8,
        98.9,
        "https://arxiv.org/abs/2511.10720",
        1,
        "https://github.com/sleeepeer/PISanitizer",
        SNIPPET_2511,
    ),
]

UPSERT_SQL = """INSERT INTO enforced_research_rules (
    rule_id, base_arxiv_id, arxiv_id, title, attack_vector, target_boundary,
    extraction_class, indicator_pattern, cedar_forbid_policy, target_crate, enrolled_at_utc,
    relevance_score, accuracy_score, arxiv_url, has_code_repo, code_repo_url, generated_code_snippet
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(base_arxiv_id) DO UPDATE SET
    rule_id = excluded.rule_id,
    arxiv_id = excluded.arxiv_id,
    title = excluded.title,
    attack_vector = excluded.attack_vector,
    target_boundary = excluded.target_boundary,
    extraction_class = excluded.extraction_class,
    indicator_pattern = excluded.indicator_pattern,
    cedar_forbid_policy = excluded.cedar_forbid_policy,
    target_crate = excluded.target_crate,
    enrolled_at_utc = excluded.enrolled_at_utc,
    relevance_score = excluded.relevance_score,
    accuracy_score = excluded.accuracy_score,
    arxiv_url = excluded.arxiv_url,
    has_code_repo = excluded.has_code_repo,
    code_repo_url = excluded.code_repo_url,
    generated_code_snippet = excluded.generated_code_snippet;"""

for db in dbs:
    if not os.path.exists(db):
        continue
    try:
        conn = sqlite3.connect(db)
        cur = conn.cursor()
        for col_def in [
            'ALTER TABLE enforced_research_rules ADD COLUMN relevance_score REAL NOT NULL DEFAULT 96.0;',
            'ALTER TABLE enforced_research_rules ADD COLUMN accuracy_score REAL NOT NULL DEFAULT 99.0;',
            'ALTER TABLE enforced_research_rules ADD COLUMN arxiv_url TEXT NOT NULL DEFAULT \'\';',
            'ALTER TABLE enforced_research_rules ADD COLUMN has_code_repo INTEGER NOT NULL DEFAULT 0;',
            'ALTER TABLE enforced_research_rules ADD COLUMN code_repo_url TEXT NOT NULL DEFAULT \'\';',
            'ALTER TABLE enforced_research_rules ADD COLUMN generated_code_snippet TEXT NOT NULL DEFAULT \'\';'
        ]:
            try:
                cur.execute(col_def)
            except Exception:
                pass

        # Clean all legacy 2024 and older rules and any non-canonical rules
        cur.execute("DELETE FROM enforced_research_rules WHERE base_arxiv_id LIKE '24%' OR CAST(SUBSTR(base_arxiv_id, 1, 2) AS INTEGER) < 25 OR base_arxiv_id NOT IN ('2603.02277', '2501.18492', '2503.00061', '2511.10720');")

        for rule in RULES:
            cur.execute(UPSERT_SQL, rule)

        conn.commit()

        cur.execute('SELECT rule_id, base_arxiv_id, has_code_repo, code_repo_url, length(generated_code_snippet) FROM enforced_research_rules')
        rows = cur.fetchall()
        print(f'{db} rows ({len(rows)}):')
        for r in rows:
            print('  ', r)
        conn.close()
    except Exception as e:
        print(f'Error migrating {db}: {e}')
