#!/usr/bin/env python3
"""
tests/adversarial_m6_stress_harness.py

Milestone M6 Empirical Adversarial Stress Harness:
Features F34 (Paper2Agent Ingestion & Repo Priority), F35 (Zero Fake Repos & SSRF Protection)
Conducted by teamwork_challenger_m6_1 (Empirical Challenger)

Stress-tests:
1. Adversarial URL & SSRF Injection against extract_code_repo_url.
2. Verified Allowlist Exact Mapping & Blocking of Fake Repos.
3. Factor 5 (+20.0pt) Code Repo Ranking Bonus Math & Clamping.
4. Declarative Ingestion Schema Completeness.
"""

import os
import sys
import unittest
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "scripts"))

from arxiv_langextract_feed import (
    extract_code_repo_url,
    compute_article_rank,
    normalize_arxiv_id,
    VERIFIED_REPO_ALLOWLIST,
    BLOCKED_REPO_URLS,
)


class AdversarialM6StressHarness(unittest.TestCase):
    """Empirical challenge suite for Milestone M6 Python feed and ranking."""

    def test_ssrf_and_malicious_scheme_rejection(self):
        """Challenge extract_code_repo_url with aggressive SSRF payloads and invalid schemes."""
        malicious_inputs = [
            # Cloud metadata and loopback IP addresses
            "Check code at http://169.254.169.254/latest/meta-data/",
            "Repo: http://169.254.169.254",
            "Clone http://127.0.0.1:8080/repo",
            "Listen on http://localhost:3000/repo",
            "Target http://0.0.0.0:22/admin",
            "IPv6 http://[::1]:8080/repo",
            # Invalid URI schemes
            "Code javascript:alert(document.cookie)",
            "Payload data:text/html,<script>alert(1)</script>",
            "File uri file:///etc/passwd",
            "FTP source ftp://github.com/evil/repo",
            # Fake/Incomplete GitHub URLs
            "Visit https://github.com",
            "Visit https://github.com/",
            "Only owner https://github.com/onlyowner",
            "Only owner slash https://github.com/onlyowner/",
            "Random site https://evil-site.com/repo/code",
            "Lookalike https://github.com.evil.com/owner/repo",
        ]

        for text in malicious_inputs:
            has_repo, url = extract_code_repo_url(text, "2605.99999")
            self.assertFalse(
                has_repo,
                f"CRITICAL BUG: Malicious SSRF / invalid input was accepted as code repo: {text} -> url={url}"
            )
            self.assertEqual(url, "")

    def test_zero_fake_repos_and_blocked_substring_rejection(self):
        """Assert that known 404/fabricated repos are completely blocked in any form."""
        blocked_candidates = [
            # Direct URLs
            "https://github.com/AlignmentResearch/rlhf-poisoning-benchmark",
            "https://github.com/oshoosiclaw/mac-agent-bench",
            # Substrings and variations embedded in text
            "Paper code available at https://github.com/AlignmentResearch/rlhf-poisoning-benchmark.",
            "Benchmarked on https://github.com/oshoosiclaw/mac-agent-bench/tree/main",
            "Fork at https://github.com/attacker/mac-agent-bench",
            "Mirror at https://github.com/attacker/rlhf-poisoning-benchmark",
            "Look at https://gitlab.com/victim/mac-agent-bench",
        ]

        for text in blocked_candidates:
            has_repo, url = extract_code_repo_url(text, "2605.88888")
            self.assertFalse(
                has_repo,
                f"CRITICAL BUG: Blocked fake repo pattern was accepted: {text} -> url={url}"
            )
            self.assertEqual(url, "")

    def test_verified_allowlist_exact_mappings(self):
        """Assert that baseline papers map ONLY to verified HTTP 200 live repositories."""
        expected_mappings = {
            "2603.02277": "https://github.com/UKGovernmentBEIS/inspect_evals",
            "2604.20496": "https://github.com/cedar-policy/cedar-spec",
            "2610.20437": "https://github.com/NVIDIA/garak",
            "2601.11893": "https://github.com/ethz-spylab/agentdojo",
        }

        for aid, expected_url in expected_mappings.items():
            has_repo, url = extract_code_repo_url("any arbitrary text without url", aid)
            self.assertTrue(has_repo, f"Allowlist lookup failed for {aid}")
            self.assertEqual(url, expected_url, f"Mismatched allowlist URL for {aid}")
            # Ensure none of the blocked strings appear in the URL
            self.assertNotIn("rlhf-poisoning-benchmark", url)
            self.assertNotIn("mac-agent-bench", url)

    def test_ranking_bonus_math_and_clamping(self):
        """Verify Factor 5 (+20.0 pt) code repo priority boost and 100.0 point saturation ceiling."""
        article_without_repo = {
            "arxiv_id": "2609.11111",
            "title": "Novel Breakout Vector Analysis",
            "summary": "Detailed container sandbox escape vector without code.",
            "published": "2026-09-01T00:00:00Z",
            "has_code_repo": False,
            "code_repo_url": "",
            "extracted_indicators": ["escape_token_1", "escape_token_2"],
        }

        article_with_repo = dict(article_without_repo)
        article_with_repo["has_code_repo"] = True
        article_with_repo["code_repo_url"] = "https://github.com/UKGovernmentBEIS/inspect_evals"

        extractions = [
            {
                "extraction_class": "breakout_vector",
                "severity_label": "HIGH",
                "target_crate_enhancement": "crates/osoosi-sandbox",
            }
        ]

        result_no_code = compute_article_rank(article_without_repo, extractions)
        result_code = compute_article_rank(article_with_repo, extractions)

        # Factor 5 bonus must be exactly +20.0 points (or clamped at 100.0)
        self.assertEqual(result_code.get("code_repo_bonus"), 20.0)
        self.assertEqual(result_no_code.get("code_repo_bonus"), 0.0)

        score_no_code = result_no_code["total_score"]
        score_code = result_code["total_score"]

        expected_diff = min(20.0, 100.0 - score_no_code)
        actual_diff = score_code - score_no_code
        self.assertAlmostEqual(actual_diff, expected_diff, places=1)
        self.assertLessEqual(score_code, 100.0)

    def test_punctuation_stripping_on_clean_repo_urls(self):
        """Assert that trailing punctuation around URLs in paper abstracts is stripped cleanly."""
        text_samples = [
            ("See https://github.com/UKGovernmentBEIS/inspect_evals.", "https://github.com/UKGovernmentBEIS/inspect_evals"),
            ("Code (https://github.com/cedar-policy/cedar-spec)", "https://github.com/cedar-policy/cedar-spec"),
            ("Repo: [https://github.com/NVIDIA/garak],", "https://github.com/NVIDIA/garak"),
            ("<https://github.com/ethz-spylab/agentdojo>", "https://github.com/ethz-spylab/agentdojo"),
        ]

        for text, expected in text_samples:
            has_repo, url = extract_code_repo_url(text, "")
            self.assertTrue(has_repo, f"Failed to extract URL from: {text}")
            self.assertEqual(url, expected, f"Failed punctuation stripping: {url} != {expected}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
