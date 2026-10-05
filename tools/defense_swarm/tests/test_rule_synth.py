import pytest
from defense_swarm.agents.rule_synth import run_rule_synthesis, validate_rule_syntax, synthesize_yara_rule, synthesize_sigma_rule
from defense_swarm.state import DefenseState


def test_rule_synthesis_valid_generation():
    state: DefenseState = {
        "incident_id": "INC-RULE-1",
        "target_pid": 5555,
        "target_process_name": "trojan_stealer.exe",
        "command_line": "trojan_stealer.exe /dump",
        "threat_intel": {"primary_technique": "T1003.001"},
    }
    yara = synthesize_yara_rule(state)
    sigma = synthesize_sigma_rule(state)
    passed, err = validate_rule_syntax(yara, sigma)
    assert passed is True
    assert err is None
    assert "rule Oshoosi_Swarm_trojan_stealer_exe_T1003_001" in yara
    assert "category: process_creation" in sigma


def test_rule_synthesis_invalid_syntax_detection():
    # Bad YARA: missing condition
    bad_yara = "rule bad_rule { strings: $a = \"foo\" }"
    valid_sigma = "title: Test\nlogsource:\n  category: process_creation\ndetection:\n  selection: 1\n  condition: selection"
    passed, err = validate_rule_syntax(bad_yara, valid_sigma)
    assert passed is False
    assert "missing 'condition:'" in err


def test_run_rule_synthesis_node():
    state: DefenseState = {
        "incident_id": "INC-RULE-2",
        "target_pid": 6666,
        "target_process_name": "beacon.exe",
        "command_line": "beacon.exe -server 10.0.0.1",
        "threat_intel": {"primary_technique": "T1055"},
        "rule_synth_retries": 0,
    }
    result = run_rule_synthesis(state)
    assert result["rule_compilation_passed"] is True
    assert result["rule_synth_retries"] == 1
    assert "synthesized_yara_rule" in result
    assert "synthesized_sigma_rule" in result
