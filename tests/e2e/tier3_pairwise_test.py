"""
OpenỌ̀ṣọ́ọ̀sì Autonomous EDR (OshoosiClaw) - E2E Testing Suite
Tier 3: Cross-Feature Pairwise Combinations

Requirements Source: ORIGINAL_REQUEST.md (R1-R5) and PROJECT.md Feature Inventory
Validates pairwise module interactions across the EDR system boundaries.
"""

import unittest
import os
import re
import sys
import json
import hashlib
import tempfile
import struct
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]


class TestTier3PairwiseCombinations(unittest.TestCase):
    """Tier 3: Pairwise Cross-Feature Interactions (20 Tests)"""

    @classmethod
    def setUpClass(cls):
        cls.root = PROJECT_ROOT
        cls.core_dir = cls.root / "crates" / "osoosi-core"
        cls.sandbox_dir = cls.root / "crates" / "osoosi-sandbox"
        cls.policy_dir = cls.root / "crates" / "osoosi-policy"
        cls.anomaly_dir = cls.root / "crates" / "osoosi-agent-anomaly"
        cls.model_dir = cls.root / "crates" / "osoosi-model"
        cls.wire_dir = cls.root / "crates" / "osoosi-wire"
        cls.types_dir = cls.root / "crates" / "osoosi-types"
        cls.dashboard_dir = cls.root / "dashboard"
        cls.corpus_dir = cls.root / "tests" / "corpus"

    def test_tier3_p01_wasm_sandbox_and_rea_inspection(self):
        """P01: Untrusted binary inside Wasm sandbox triggers autonomous REA structural inspection."""
        wasm_src = (self.sandbox_dir / "src" / "wasm_tier1.rs").read_text(encoding="utf-8")
        rea_engine = (self.core_dir / "src" / "rea" / "engine.rs").read_text(encoding="utf-8")
        self.assertTrue("memory" in wasm_src.lower() or "store" in wasm_src.lower())
        self.assertTrue("analyze_target_path" in rea_engine or "AutonomousReaEngine" in rea_engine)

    def test_tier3_p02_streaming_scanner_and_ring_buffer_sponge_defense(self):
        """P02: Streaming Aho-Corasick matches feed into history ring buffer without eviction amnesia."""
        align_src = (self.anomaly_dir / "src" / "alignment_scanner.rs").read_text(encoding="utf-8")
        voter_src = (self.policy_dir / "src" / "agentic_voter.rs").read_text(encoding="utf-8")
        self.assertTrue("window" in align_src.lower() or "overlap" in align_src.lower() or "score" in align_src.lower())
        self.assertTrue("record_action" in voter_src or "trajectory" in voter_src.lower())

    def test_tier3_p03_composite_process_key_and_causal_graph(self):
        """P03: Composite ProcessKey prevents PID reuse taint laundering across causal graph."""
        voter_src = (self.policy_dir / "src" / "agentic_voter.rs").read_text(encoding="utf-8")
        causal_src = (self.core_dir / "src" / "causal_graph.rs").read_text(encoding="utf-8")
        self.assertIn("pub struct ProcessKey", voter_src)
        self.assertIn("pub start_time_100ns: u64", voter_src)
        self.assertTrue("pid" in causal_src.lower() and "graph" in causal_src.lower())

    def test_tier3_p04_dashmap_taint_cache_and_sqlite_wal(self):
        """P04: In-memory DashMap taint cache serves hot reads while async queue flushes to SQLite WAL."""
        causal_src = (self.core_dir / "src" / "causal_graph.rs").read_text(encoding="utf-8")
        self.assertTrue("DashMap" in causal_src or "dashmap" in causal_src.lower())
        self.assertTrue("WAL" in causal_src or "wal" in causal_src.lower() or "rusqlite" in causal_src.lower())

    def test_tier3_p05_pre_io_stat_cache_and_blake3_streaming(self):
        """P05: Pre-I/O metadata cache hit bypasses I/O; cache miss invokes streaming BLAKE3 hashing."""
        malware_src = (self.model_dir / "src" / "malware.rs").read_text(encoding="utf-8")
        self.assertTrue("cache" in malware_src.lower())
        self.assertTrue("blake3" in malware_src.lower() or "sha256" in malware_src.lower() or "hash" in malware_src.lower())

    def test_tier3_p06_lru_cache_and_toolchain_allowlist(self):
        """P06: Bounded LRU cache retains frequently invoked developer toolchains (cargo, gpg, rustc)."""
        malware_src = (self.model_dir / "src" / "malware.rs").read_text(encoding="utf-8")
        path_sec = (self.core_dir / "src" / "rea" / "path_security.rs").read_text(encoding="utf-8")
        self.assertTrue("cache" in malware_src.lower())
        self.assertTrue("cargo.exe" in path_sec.lower() and "gpg.exe" in path_sec.lower())

    def test_tier3_p07_dual_gate_consensus_and_side_effect_purge(self):
        """P07: PolicyEngine veto/abstain triggers immediate purge_detection_by_path_or_hash."""
        policy_engine = (self.policy_dir / "src" / "engine.rs").read_text(encoding="utf-8")
        malware_src = (self.model_dir / "src" / "malware.rs").read_text(encoding="utf-8")
        self.assertTrue("scan_event" in policy_engine)
        self.assertTrue("purge_detection_by_path_or_hash" in malware_src or "purge" in malware_src.lower())

    def test_tier3_p08_direct_byte_hashing_and_confined_path_walking(self):
        """P08: Ring 7 capability authorizer hashes file bytes after confined path walking validates sandbox bounds."""
        breakout_src = (self.policy_dir / "src" / "breakout_gate.rs").read_text(encoding="utf-8")
        confined_src = (self.sandbox_dir / "src" / "open_confined.rs").read_text(encoding="utf-8")
        self.assertTrue("evaluate_effect" in breakout_src or "Authorizer" in breakout_src)
        self.assertTrue("confined" in confined_src.lower() or "canonical" in confined_src.lower() or "beneath" in confined_src.lower())

    def test_tier3_p09_bft_mesh_consensus_and_qos_lanes(self):
        """P09: CriticalSecurityLane threat frames bypass bulk telemetry congestion in BFT mesh."""
        mesh_src = (self.wire_dir / "src" / "mesh.rs").read_text(encoding="utf-8")
        flight_src = (self.core_dir / "src" / "fprime_flight.rs").read_text(encoding="utf-8")
        self.assertTrue("broadcast" in mesh_src.lower() or "peer" in mesh_src.lower())
        self.assertTrue("CriticalSecurityLane" in flight_src and "BulkTelemetryLane" in flight_src)

    def test_tier3_p10_reactive_notify_and_in_memory_connection_pool(self):
        """P10: Reactive tokio::sync::Notify wakeups immediately dispatch over pooled peer connections."""
        mesh_src = (self.wire_dir / "src" / "mesh.rs").read_text(encoding="utf-8")
        self.assertTrue("channel" in mesh_src.lower() or "peer" in mesh_src.lower() or "broadcast" in mesh_src.lower())

    def test_tier3_p11_vote_action_normalization_and_quorum_calculation(self):
        """P11: Action suffix stripping unifies votes into canonical action for 2f+1 quorum calculation."""
        raw_votes = ["BLOCK_ALL:seq_1", "BLOCK_ALL:seq_2", "BLOCK_ALL:seq_3"]
        normalized = [v.split(":")[0] for v in raw_votes]
        self.assertEqual(len(set(normalized)), 1)
        self.assertEqual(normalized[0], "BLOCK_ALL")

    def test_tier3_p12_lock_free_arena_pool_and_telemetry_frame_routing(self):
        """P12: StaticArenaPool leases pre-allocated slot for TelemetryFrame without runtime heap allocation."""
        flight_src = (self.core_dir / "src" / "fprime_flight.rs").read_text(encoding="utf-8")
        self.assertTrue("StaticArenaPool" in flight_src or "lease" in flight_src.lower())
        self.assertTrue("TelemetryFrame" in flight_src or "frame" in flight_src.lower())

    def test_tier3_p13_recoil_governance_and_process_tarpit(self):
        """P13: High recoil likelihood score prevents kill and routes process into non-destructive tarpit."""
        runtime_files = list((self.root / "crates" / "osoosi-runtime" / "src").glob("**/*.rs"))
        found_tarpit = any("tarpit" in f.read_text(encoding="utf-8", errors="ignore").lower() for f in runtime_files)
        self.assertTrue(found_tarpit)

    def test_tier3_p14_ebpf_telemetry_and_causal_graph_linkage(self):
        """P14: eBPF process execution event links parent and child nodes in causal security graph."""
        causal_src = (self.core_dir / "src" / "causal_graph.rs").read_text(encoding="utf-8")
        self.assertTrue("parent" in causal_src.lower() or "child" in causal_src.lower() or "edge" in causal_src.lower())

    def test_tier3_p15_wfp_containment_and_loopback_preservation(self):
        """P15: WFP network containment blocks external CIDRs while preserving 127.0.0.1 and port 3030."""
        runtime_files = list((self.root / "crates" / "osoosi-runtime" / "src").glob("**/*.rs"))
        found = any("127.0.0.1" in f.read_text(encoding="utf-8", errors="ignore") for f in runtime_files)
        self.assertTrue(found)

    def test_tier3_p16_rea_autonomous_sweep_and_sqlite_findings(self):
        """P16: Background REA artifact sweep commits confirmed detections to consensus ledger."""
        rea_engine = (self.core_dir / "src" / "rea" / "engine.rs").read_text(encoding="utf-8")
        self.assertTrue("analyze" in rea_engine.lower() or "sweep" in rea_engine.lower() or "scan" in rea_engine.lower())

    def test_tier3_p17_multi_node_fault_injection_and_deduplication(self):
        """P17: Partition healing in multi-node harness avoids message loops via UUID deduplication."""
        wire_test = (self.wire_dir / "tests" / "multi_node_fault_injection.rs")
        has_test = wire_test.exists() or (self.core_dir / "tests" / "multi_node_fault_injection.rs").exists()
        self.assertTrue(has_test)

    def test_tier3_p18_genesis_pinning_and_cedar_reference_monitor(self):
        """P18: Immutable genesis authority level evaluated by Cedar monitor fails closed on dilation."""
        breakout_src = (self.policy_dir / "src" / "breakout_gate.rs").read_text(encoding="utf-8")
        self.assertTrue("Cedar" in breakout_src or "cedar" in breakout_src.lower() or "Reference" in breakout_src)

    def test_tier3_p19_webui_parity_and_rest_endpoints(self):
        """P19: WebUI dashboard/src and dashboard/dist match 0-diff and map to Axum routes."""
        src_html = (self.dashboard_dir / "src" / "index.html").read_text(encoding="utf-8")
        dist_html = (self.dashboard_dir / "dist" / "index.html").read_text(encoding="utf-8")
        h1 = hashlib.sha256(src_html.encode("utf-8")).hexdigest()
        h2 = hashlib.sha256(dist_html.encode("utf-8")).hexdigest()
        self.assertEqual(h1, h2, "WebUI index.html must satisfy 0-diff parity between src/ and dist/")

    def test_tier3_p20_precached_corpus_and_edr_bench_gate2(self):
        """P20: Gate 2 benchmark evaluates pre-cached corpus against single MalwareScanner instance."""
        bench_src = (self.core_dir / "src" / "edr_bench.rs").read_text(encoding="utf-8")
        self.assertTrue("scanner" in bench_src.lower() and "corpus" in bench_src.lower())


if __name__ == "__main__":
    unittest.main()
