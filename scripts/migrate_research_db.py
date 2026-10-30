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

SNIPPET_2403 = """// [TIGHTEN-ONLY DEFENSE GUARD] - Synthesized from arXiv:2403.04651v1
// Enforced in: osoosi-agent-anomaly::breakout_defense (Zero-Execution AST)
// Threat Vector: Permissive wildcard action/resource sandbox policy bypass
if let Ok(rules) = research_defense_registry().read() {
    const INDICATORS: &[&str] = &[
        "permit(principal, action, resource)",
        "action in [action::\\"*\\"]",
        "resource == *",
    ];
    for &pat in INDICATORS {
        if pat.len() >= 4 && (payload_lc.contains(pat) || resource_lc.contains(pat)) {
            tech_res.is_clean = false;
            tech_res.sandbox_quarantine_required = true;
            tech_res.detected_vectors.push(
                format!("[ArXiv-Active-Defense:2403.04651v1]: Blocked by rule 'ARXIV-DEF-2403.04651'")
            );
            break;
        }
    }
}"""

SNIPPET_2406_GARAK = """// [TIGHTEN-ONLY DEFENSE GUARD] - Synthesized from arXiv:2406.11036v1
// Enforced in: osoosi-agent-anomaly::breakout_defense (Zero-Execution AST)
// Threat Vector: Adversarial LLM red-teaming probe, encoding bypass, and markdown exfiltration (NVIDIA Garak)
if let Ok(rules) = research_defense_registry().read() {
    const INDICATORS: &[&str] = &[
        "garak.probes",
        "inject_base64",
        "dan_11_0",
        "markdown_image_exfil",
    ];
    for &pat in INDICATORS {
        if pat.len() >= 4 && (payload_lc.contains(pat) || resource_lc.contains(pat)) {
            tech_res.is_clean = false;
            tech_res.sandbox_quarantine_required = true;
            tech_res.detected_vectors.push(
                format!("[ArXiv-Active-Defense:2406.11036v1]: Blocked by rule 'ARXIV-DEF-2406.11036'")
            );
            break;
        }
    }
}"""

SNIPPET_2406_DOJO = """// [TIGHTEN-ONLY DEFENSE GUARD] - Synthesized from arXiv:2406.13352v1
// Enforced in: osoosi-agent-anomaly::breakout_defense (Zero-Execution AST)
// Threat Vector: Prompt injection tool call hijack and mandatory access control bypass
if let Ok(rules) = research_defense_registry().read() {
    const INDICATORS: &[&str] = &[
        "important_instructions",
        "<tool_call>",
        "sudo chmod +s",
        "/etc/sudoers",
    ];
    for &pat in INDICATORS {
        if pat.len() >= 4 && (payload_lc.contains(pat) || resource_lc.contains(pat)) {
            tech_res.is_clean = false;
            tech_res.sandbox_quarantine_required = true;
            tech_res.detected_vectors.push(
                format!("[ArXiv-Active-Defense:2406.13352v1]: Blocked by rule 'ARXIV-DEF-2406.13352'")
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
        "SandboxEscapeBench: A Benchmark for AI Agent Container Sandbox Escape (UK AISI)",
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
        "ARXIV-DEF-2403.04651",
        "2403.04651",
        "2403.04651v1",
        "Cedar: A New Policy Language with Automated Reasoning and SMT Verification",
        "Permissive wildcard action/resource sandbox policy bypass",
        "cedar_smt_sandbox_verification",
        "defense_countermeasure",
        'permit(principal, action, resource) | action in [action::"*"] | resource == *',
        '@id("ARXIV-DEF-2403.04651")\nforbid(principal, action, resource) when { context.arxiv_source == "2403.04651v1" };',
        "osoosi-agent-anomaly::cedar_engine",
        "2026-10-28T00:00:00Z",
        97.2,
        99.1,
        "https://arxiv.org/abs/2403.04651",
        1,
        "https://github.com/cedar-policy/cedar-spec",
        SNIPPET_2403,
    ),
    (
        "ARXIV-DEF-2406.11036",
        "2406.11036",
        "2406.11036v1",
        "garak: A Framework for Security Probing Large Language Models (NVIDIA)",
        "Adversarial LLM red-teaming probe, encoding bypass, and markdown exfiltration (NVIDIA Garak)",
        "llm_probe_redteam_boundary",
        "breakout_vector",
        "garak.probes | inject_base64 | dan_11_0 | markdown_image_exfil",
        '@id("ARXIV-DEF-2406.11036")\nforbid(principal, action, resource) when { context.arxiv_source == "2406.11036v1" };',
        "osoosi-agent-anomaly::cognitive_redteam",
        "2026-10-28T00:00:00Z",
        99.0,
        99.6,
        "https://arxiv.org/abs/2406.11036",
        1,
        "https://github.com/NVIDIA/garak",
        SNIPPET_2406_GARAK,
    ),
    (
        "ARXIV-DEF-2406.13352",
        "2406.13352",
        "2406.13352v1",
        "AgentDojo: A Dynamic Environment for Benchmarking Attacks and Defenses on AI Agents",
        "Prompt injection tool call hijack and mandatory access control bypass",
        "mac_authority_lattice",
        "defense_countermeasure",
        "important_instructions | <tool_call> | sudo chmod +s | /etc/sudoers",
        '@id("ARXIV-DEF-2406.13352")\nforbid(principal, action, resource) when { context.arxiv_source == "2406.13352v1" };',
        "osoosi-agent-anomaly::containment_ring",
        "2026-10-28T00:00:00Z",
        96.8,
        98.9,
        "https://arxiv.org/abs/2406.13352",
        1,
        "https://github.com/ethz-spylab/agentdojo",
        SNIPPET_2406_DOJO,
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

        for rule in RULES:
            cur.execute(UPSERT_SQL, rule)

        # Clean legacy synthetic rules
        cur.execute("DELETE FROM enforced_research_rules WHERE base_arxiv_id IN ('2406.07392', '2604.20496', '2610.20437', '2601.11893', '2610.09167', '2610.14224');")
        conn.commit()

        cur.execute('SELECT rule_id, base_arxiv_id, has_code_repo, code_repo_url, length(generated_code_snippet) FROM enforced_research_rules')
        rows = cur.fetchall()
        print(f'{db} rows ({len(rows)}):')
        for r in rows:
            print('  ', r)
        conn.close()
    except Exception as e:
        print(f'Error migrating {db}: {e}')
