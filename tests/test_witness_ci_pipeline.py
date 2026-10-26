"""
Integration and Unit Tests for Witness CI/CD Supply-Chain Pipeline.
"""

import os
import sys
import tempfile
import pytest

from scripts.witness_ci_pipeline import (
    run_selftest,
    evaluate_rego,
    make_dsse_pae,
    generate_keypair,
    sign_dsse,
    verify_dsse,
    compute_sha256,
    guess_mime_type,
    SignatureVerificationFailed
)


def test_witness_ci_pipeline_selftest():
    """Execute the complete positive and negative cryptographic verification suite."""
    result = run_selftest()
    assert result == 0, "Witness CI Pipeline self-test suite failed"


def test_rego_evaluations():
    """Verify OPA Rego rule evaluations for commandrun, git, and product."""
    # commandrun rule
    allow, denials = evaluate_rego("commandrun", "command-exit-zero", "", {"exitcode": 0})
    assert allow is True
    assert len(denials) == 0

    allow, denials = evaluate_rego("commandrun", "command-exit-zero", "", {"exitcode": 1})
    assert allow is False
    assert len(denials) > 0

    # git rule
    allow, denials = evaluate_rego("git", "git-clean-commit", "", {"commithash": "abcdef123456"})
    assert allow is True
    assert len(denials) == 0

    allow, denials = evaluate_rego("git", "git-clean-commit", "", {"commithash": "abc"})
    assert allow is False
    assert len(denials) > 0

    # product rule
    allow, denials = evaluate_rego("product", "artifact-chain", "", {"artifact.exe": {"sha256": "123"}})
    assert allow is True
    assert len(denials) == 0

    allow, denials = evaluate_rego("product", "artifact-chain", "", {})
    assert allow is False
    assert len(denials) > 0


def test_dsse_pae_and_tamper_detection():
    """Verify DSSE Pre-Authentication Encoding (PAE) and signature tamper detection."""
    priv, pub, keyid = generate_keypair()
    payload = {"greeting": "hello open-osoosi", "step": "unit-tests"}
    
    envelope = sign_dsse(payload, priv, keyid)
    assert envelope["payloadType"] == "application/vnd.in-toto+json"
    assert envelope["signatures"][0]["keyid"] == keyid
    
    # Verify valid envelope
    decoded = verify_dsse(envelope, pub)
    assert decoded["greeting"] == "hello open-osoosi"
    
    # Tamper with signature
    tampered_env = dict(envelope)
    tampered_env["signatures"] = [{"keyid": keyid, "sig": "dGFtcGVyZWQ="}]
    with pytest.raises(SignatureVerificationFailed):
        verify_dsse(tampered_env, pub)


def test_mime_and_sha256():
    """Verify file hashing and MIME type detection."""
    with tempfile.NamedTemporaryFile("wb", suffix=".exe", delete=False) as f:
        f.write(b"MZ\x90\x00DummyPE")
        path = f.name
    try:
        sha = compute_sha256(path)
        assert len(sha) == 64
        mime = guess_mime_type(path)
        assert "portable-executable" in mime or "octet-stream" in mime
    finally:
        if os.path.exists(path):
            os.remove(path)
