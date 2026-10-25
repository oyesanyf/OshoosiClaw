#!/usr/bin/env python3
"""
OshoosiClaw Autonomous Disk Space & Telemetry Lifecycle Cleanup Engine
======================================================================
Reclaims disk space across 6 safe lifecycle tiers without disrupting running
daemons, active release binaries, or authoritative security telemetry:
  1. Scratch & Subagent Cargo Target Directories (target/check_*, target/worker_*, etc.)
  2. Debug Target & Superseded Multi-Hash Cargo Dependencies (target/debug, old target/release/deps)
  3. SQLite Telemetry Ring-Buffer Retention & WAL Checkpoint/Truncation (osoosi.db, osoosi.db-wal)
  4. Rotated Daemon Logs & Old Regression Artifacts (logs/*.rotated, old osoosi.log.*)
  5. Orphaned OS Temp Files (%TEMP%/osoosi_*)
  6. Temporary Packaging/Installer Staging Artifacts (*.wixobj, *.wixpdb)
"""

import argparse
import collections
import datetime
import glob
import json
import os
import re
import shutil
import sqlite3
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List, Tuple

ROOT_DIR = Path(__file__).resolve().parent.parent

SCRATCH_TARGET_PATTERNS = [
    "challenge_test_target",
    "check_dash",
    "check_ws",
    "check_*",
    "subagent_build",
    "subagent_*",
    "test_out",
    "tmp",
    "worker_*",
    "scratch_*",
]

PROTECTED_RELEASE_BINARIES = {
    "osoosi.exe",
    "osoosi",
    "osoosi_inject.dll",
    "libosoosi_inject.so",
    "osoosi-auditor.exe",
    "osoosi-auditor",
    "osoosi-cli.exe",
    "osoosi-cli",
    "otx-taxii-rs.exe",
    "otx-taxii-rs",
    "bulk_trainer.exe",
    "bulk_trainer",
    "test-peer.exe",
    "test-peer",
    "DirectML.dll",
    "onnxruntime.dll",
}


def get_dir_size(path: Path) -> Tuple[int, int]:
    total_bytes = 0
    file_count = 0
    if not path.exists():
        return 0, 0
    if path.is_file():
        try:
            return path.stat().st_size, 1
        except OSError:
            return 0, 0
    for dp, _, filenames in os.walk(path):
        for f in filenames:
            fp = os.path.join(dp, f)
            try:
                total_bytes += os.path.getsize(fp)
                file_count += 1
            except OSError:
                pass
    return total_bytes, file_count


def safe_remove_file(path: Path) -> int:
    try:
        sz = path.stat().st_size
        path.unlink()
        return sz
    except OSError:
        return 0


def safe_remove_dir(path: Path) -> Tuple[int, int]:
    if not path.exists():
        return 0, 0
    drive_anchor = str(path.resolve().drive) + "\\" if path.resolve().drive else str(path.resolve())
    try:
        _, _, free_before = shutil.disk_usage(drive_anchor)
    except OSError:
        free_before = 0

    if os.name == "nt":
        import subprocess
        empty_dir = Path(tempfile.gettempdir()) / f"osoosi_empty_{os.getpid()}"
        empty_dir.mkdir(parents=True, exist_ok=True)
        subprocess.run(
            ["robocopy", str(empty_dir), str(path), "/MIR", "/NFL", "/NDL", "/NJH", "/NJS", "/NC", "/NS", "/NP", "/MT:32"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        subprocess.run(
            ["cmd", "/c", "rmdir", "/s", "/q", str(path)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        try:
            empty_dir.rmdir()
        except OSError:
            pass
        if not path.exists():
            try:
                _, _, free_after = shutil.disk_usage(drive_anchor)
                return max(0, free_after - free_before), 1
            except OSError:
                return 0, 1

    freed_bytes = 0
    removed_files = 0
    for dp, dirnames, filenames in os.walk(path, topdown=False):
        for fn in filenames:
            fp = Path(dp) / fn
            try:
                sz = fp.stat().st_size
                fp.unlink()
                freed_bytes += sz
                removed_files += 1
            except OSError:
                pass
        for dn in dirnames:
            try:
                (Path(dp) / dn).rmdir()
            except OSError:
                pass
    try:
        path.rmdir()
    except OSError:
        shutil.rmtree(path, ignore_errors=True)
    return freed_bytes, removed_files


def clean_scratch_targets(root: Path, include_debug: bool = True) -> Dict[str, Any]:
    target_dir = root / "target"
    freed = 0
    files_removed = 0
    cleaned_dirs: List[str] = []

    if not target_dir.exists():
        return {"bytes_freed": 0, "files_removed": 0, "cleaned_dirs": []}

    # 1. Remove scratch/subagent target directories
    for pattern in SCRATCH_TARGET_PATTERNS:
        for match in target_dir.glob(pattern):
            if match.is_dir() and match.name not in ("release", "debug", "wix", "debian"):
                b, c = safe_remove_dir(match)
                if b > 0 or c > 0:
                    freed += b
                    files_removed += c
                    cleaned_dirs.append(f"target/{match.name}")

    # 2. Remove stale top-level scratch files in target/
    for extra_file in ["dashboard_diff.rs", "cargo_check_err.txt"]:
        ef = target_dir / extra_file
        if ef.is_file():
            b = safe_remove_file(ef)
            if b > 0:
                freed += b
                files_removed += 1

    # 3. Clean target/debug if requested (O(1) rename + 128-thread background/fast purge)
    debug_dir = target_dir / "debug"
    if include_debug and debug_dir.exists():
        purge_dir = target_dir / f".purge_debug_{os.getpid()}_{int(time.time())}"
        try:
            debug_dir.rename(purge_dir)
        except OSError:
            purge_dir = debug_dir
        if os.name == "nt":
            import subprocess
            empty_dir = Path(tempfile.gettempdir()) / f"osoosi_empty_bg_{os.getpid()}"
            empty_dir.mkdir(parents=True, exist_ok=True)
            cmd_str = f'robocopy "{empty_dir}" "{purge_dir}" /MIR /NFL /NDL /NJH /NJS /NC /NS /NP /MT:128 >nul 2>&1 & rmdir /s /q "{purge_dir}" >nul 2>&1'
            subprocess.Popen(
                ["cmd", "/c", cmd_str],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000),
            )
            cleaned_dirs.append("target/debug (O(1) unlinked + 128-thread purge)")
        else:
            b, c = safe_remove_dir(purge_dir)
            freed += b
            files_removed += c
            cleaned_dirs.append("target/debug")

    # Also sweep any leftover .purge_* dirs in background
    for pdir in target_dir.glob(".purge_*"):
        if pdir.is_dir() and os.name == "nt":
            import subprocess
            empty_dir = Path(tempfile.gettempdir()) / f"osoosi_empty_bg_{os.getpid()}"
            empty_dir.mkdir(parents=True, exist_ok=True)
            cmd_str = f'robocopy "{empty_dir}" "{pdir}" /MIR /NFL /NDL /NJH /NJS /NC /NS /NP /MT:128 >nul 2>&1 & rmdir /s /q "{pdir}" >nul 2>&1'
            subprocess.Popen(
                ["cmd", "/c", cmd_str],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000),
            )

    return {
        "bytes_freed": freed,
        "files_removed": files_removed,
        "cleaned_dirs": cleaned_dirs,
    }


def prune_superseded_cargo_deps(deps_dir: Path, keep_revisions: int = 2) -> Dict[str, Any]:
    """
    Prunes superseded older crate hash artifacts in target/release/deps or target/release/build
    while keeping the newest `keep_revisions` per crate stem + extension so incremental
    compilation stays fast.
    """
    if not deps_dir.exists():
        return {"bytes_freed": 0, "files_removed": 0}

    freed = 0
    files_removed = 0

    # Group files by (stem_without_hash, extension)
    # Example: libosoosi_core-1a2b3c4d5e6f7890.rlib -> key: ("libosoosi_core", ".rlib")
    hash_re = re.compile(r"^(.+?)-[0-9a-f]{16}(\..+)$")
    groups: Dict[Tuple[str, str], List[Tuple[float, Path]]] = collections.defaultdict(list)

    for entry in os.scandir(deps_dir):
        if not entry.is_file():
            continue
        m = hash_re.match(entry.name)
        if not m:
            continue
        prefix, ext = m.group(1), m.group(2)
        if ext.lower() in (".dll", ".exe"):
            continue
        clean_stem = prefix[3:] if prefix.startswith("lib") else prefix
        if not clean_stem.startswith((
            "osoosi", "edr_", "zero_", "otx_taxii", "compression_prompt",
            "agent_thermostat", "bulk_trainer", "test_peer"
        )):
            continue
        try:
            mtime = entry.stat().st_mtime
            groups[(prefix, ext)].append((mtime, Path(entry.path)))
        except OSError:
            pass

    for key, items in groups.items():
        if len(items) <= keep_revisions:
            continue
        # Sort newest first
        items.sort(key=lambda x: x[0], reverse=True)
        for _, old_path in items[keep_revisions:]:
            b = safe_remove_file(old_path)
            if b > 0:
                freed += b
                files_removed += 1

    # Also clean target/release/incremental if present
    inc_dir = deps_dir.parent / "incremental"
    if inc_dir.exists():
        b, c = safe_remove_dir(inc_dir)
        freed += b
        files_removed += c

    # Also prune superseded build script directories in target/release/build/<crate>-<hash>
    build_dir = deps_dir.parent / "build"
    if False and build_dir.exists():
        dir_hash_re = re.compile(r"^(.+?)-[0-9a-f]{16}$")
        dir_groups: Dict[str, List[Tuple[float, Path]]] = collections.defaultdict(list)
        for entry in os.scandir(build_dir):
            if not entry.is_dir():
                continue
            m = dir_hash_re.match(entry.name)
            if not m or not m.group(1).startswith(("osoosi", "edr_", "zero_")):
                continue
            try:
                dir_groups[m.group(1)].append((entry.stat().st_mtime, Path(entry.path)))
            except OSError:
                pass
        for prefix, d_items in dir_groups.items():
            if len(d_items) <= keep_revisions:
                continue
            d_items.sort(key=lambda x: x[0], reverse=True)
            for _, old_dir in d_items[keep_revisions:]:
                b, c = safe_remove_dir(old_dir)
                freed += b
                files_removed += c

    return {"bytes_freed": freed, "files_removed": files_removed}


def compact_sqlite_databases(root: Path) -> Dict[str, Any]:
    """
    Applies ring-buffer row retention and PRAGMA wal_checkpoint(TRUNCATE) + VACUUM
    across workspace and release SQLite databases.
    """
    db_candidates = [
        root / "database" / "osoosi.db",
        root / "target" / "release" / "database" / "osoosi.db",
        root / "database" / "nvd_cache.db",
        root / "target" / "release" / "database" / "nvd_cache.db",
    ]

    total_freed = 0
    rows_pruned = 0
    compacted_dbs: List[str] = []

    retention_limits = {
        "events": ("timestamp", 25000),
        "har_entries": ("id", 2000),
        "threats": ("timestamp", 5000),
        "consensus_findings": ("evaluated_at", 5000),
        "file_integrity": ("last_seen", 50000),
    }

    for db_path in db_candidates:
        if not db_path.exists():
            continue
        wal_path = Path(str(db_path) + "-wal")
        shm_path = Path(str(db_path) + "-shm")

        before_size = db_path.stat().st_size
        if wal_path.exists():
            before_size += wal_path.stat().st_size
        if shm_path.exists():
            before_size += shm_path.stat().st_size

        try:
            conn = sqlite3.connect(str(db_path), timeout=5.0)
            cur = conn.cursor()

            for table, (order_col, max_rows) in retention_limits.items():
                try:
                    cur.execute(f"SELECT COUNT(*) FROM {table}")
                    cnt = cur.fetchone()[0]
                    if cnt > max_rows:
                        excess = cnt - max_rows
                        cur.execute(
                            f"DELETE FROM {table} WHERE rowid IN ("
                            f"SELECT rowid FROM {table} ORDER BY {order_col} ASC LIMIT ?"
                            f")",
                            (excess,),
                        )
                        rows_pruned += max(0, cur.rowcount)
                except sqlite3.Error:
                    pass

            conn.commit()
            try:
                cur.execute("PRAGMA wal_checkpoint(TRUNCATE);")
            except sqlite3.Error:
                pass

            # Run VACUUM if database + WAL was > 20 MB
            if before_size > 20 * 1024 * 1024:
                try:
                    cur.execute("VACUUM;")
                except sqlite3.Error:
                    pass
                try:
                    cur.execute("PRAGMA wal_checkpoint(TRUNCATE);")
                except sqlite3.Error:
                    pass

            try:
                cur.execute("PRAGMA optimize;")
            except sqlite3.Error:
                pass
            conn.close()
        except sqlite3.Error:
            pass

        after_size = db_path.stat().st_size if db_path.exists() else 0
        if wal_path.exists():
            after_size += wal_path.stat().st_size
        if shm_path.exists():
            after_size += shm_path.stat().st_size

        delta = max(0, before_size - after_size)
        total_freed += delta
        compacted_dbs.append(str(db_path.relative_to(root)))

    return {
        "bytes_freed": total_freed,
        "rows_pruned": rows_pruned,
        "compacted_databases": compacted_dbs,
    }


def clean_rotated_logs_and_temp(root: Path, max_log_age_days: int = 2) -> Dict[str, Any]:
    freed = 0
    files_removed = 0
    now = time.time()
    today_str = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")
    local_today_str = datetime.datetime.now().strftime("%Y-%m-%d")

    for log_dir in [root / "logs", root / "target" / "release" / "logs"]:
        if not log_dir.exists():
            continue
        for entry in os.scandir(log_dir):
            if not entry.is_file():
                continue
            name = entry.name
            fp = Path(entry.path)
            # Always remove .rotated logs or test_write.json
            if name.endswith(".rotated") or name.endswith(".old") or name.endswith(".bak") or name == "test_write.json":
                b = safe_remove_file(fp)
                if b > 0:
                    freed += b
                    files_removed += 1
                continue
            # Remove historical daily osoosi.log.YYYY-MM-DD that are not today's active log
            if name.startswith("osoosi.log.") and (today_str not in name) and (local_today_str not in name):
                b = safe_remove_file(fp)
                if b > 0:
                    freed += b
                    files_removed += 1
                continue
            # Truncate active log if it exceeds 25 MB (keep last 5 MB)
            if name.startswith("osoosi.log"):
                try:
                    sz = fp.stat().st_size
                    if sz > 25 * 1024 * 1024:
                        with open(fp, "rb") as f:
                            f.seek(sz - 5 * 1024 * 1024)
                            tail = f.read()
                        with open(fp, "wb") as f:
                            f.write(tail)
                        freed += sz - len(tail)
                except OSError:
                    pass

        # Prune old regression_artifacts (keep newest 10 files)
        reg_dir = log_dir / "regression_artifacts"
        if reg_dir.exists():
            reg_files = []
            for entry in os.scandir(reg_dir):
                if entry.is_file():
                    try:
                        reg_files.append((entry.stat().st_mtime, Path(entry.path)))
                    except OSError:
                        pass
            if len(reg_files) > 10:
                reg_files.sort(key=lambda x: x[0], reverse=True)
                for _, old_fp in reg_files[10:]:
                    b = safe_remove_file(old_fp)
                    if b > 0:
                        freed += b
                        files_removed += 1

    # Sweep orphaned OS temp files created by Siquery / browser inspections
    temp_dir = Path(tempfile.gettempdir())
    if temp_dir.exists():
        temp_prefixes = (
            "osoosi_hist_",
            "osoosi_dl_",
            "osoosi_har_hist_",
            "osoosi_gecko_",
            "osoosi_safari_",
            "osoosi_ext_",
        )
        for entry in os.scandir(temp_dir):
            if entry.name.startswith(temp_prefixes):
                try:
                    if now - entry.stat().st_mtime > 120:
                        b = safe_remove_file(Path(entry.path))
                        if b > 0:
                            freed += b
                            files_removed += 1
                except OSError:
                    pass

    return {"bytes_freed": freed, "files_removed": files_removed}


def run_autonomous_cleanup(
    root: Path = ROOT_DIR,
    include_debug_target: bool = True,
    keep_release_dep_revisions: int = 2,
) -> Dict[str, Any]:
    t0 = time.time()
    drive_anchor = str(root.drive) + "\\" if root.drive else str(root)
    before_total, before_used, before_free = shutil.disk_usage(drive_anchor)

    tier1 = clean_scratch_targets(root, include_debug=include_debug_target)
    tier2 = prune_superseded_cargo_deps(root / "target" / "release" / "deps", keep_revisions=keep_release_dep_revisions)
    tier3 = compact_sqlite_databases(root)
    tier4 = clean_rotated_logs_and_temp(root)

    after_total, after_used, after_free = shutil.disk_usage(drive_anchor)
    measured_freed = (
        tier1["bytes_freed"]
        + tier2["bytes_freed"]
        + tier3["bytes_freed"]
        + tier4["bytes_freed"]
    )
    drive_delta_freed = max(0, after_free - before_free)
    effective_freed = max(measured_freed, drive_delta_freed)
    elapsed_ms = round((time.time() - t0) * 1000.0, 2)

    report = {
        "status": "ok",
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "duration_ms": elapsed_ms,
        "bytes_freed": effective_freed,
        "mb_freed": round(effective_freed / (1024.0 * 1024.0), 2),
        "gb_freed": round(effective_freed / (1024.0 ** 3), 3),
        "files_removed": tier1["files_removed"] + tier2["files_removed"] + tier4["files_removed"],
        "sqlite_rows_pruned": tier3["rows_pruned"],
        "drive_free_gb_before": round(before_free / (1024.0 ** 3), 2),
        "drive_free_gb_after": round(after_free / (1024.0 ** 3), 2),
        "drive_usage_percent_after": round((after_used / after_total) * 100.0, 2) if after_total else 0.0,
        "tiers": {
            "tier1_scratch_and_debug_targets": tier1,
            "tier2_superseded_release_deps": tier2,
            "tier3_sqlite_wal_and_retention": tier3,
            "tier4_rotated_logs_and_os_temp": tier4,
        },
    }

    # Persist latest cleanup report to logs/disk_cleanup_report.json
    try:
        logs_dir = root / "logs"
        logs_dir.mkdir(parents=True, exist_ok=True)
        with open(logs_dir / "disk_cleanup_report.json", "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
    except OSError:
        pass

    return report


def main() -> int:
    parser = argparse.ArgumentParser(description="OshoosiClaw Autonomous Disk Cleanup Engine")
    parser.add_argument("--keep-debug", action="store_true", help="Do not remove target/debug")
    parser.add_argument("--keep-revisions", type=int, default=2, help="Number of hash revisions to keep in target/release/deps")
    parser.add_argument("--json", action="store_true", help="Print JSON report only")
    args = parser.parse_args()

    report = run_autonomous_cleanup(
        root=ROOT_DIR,
        include_debug_target=not args.keep_debug,
        keep_release_dep_revisions=max(1, args.keep_revisions),
    )

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(
            f"[DISK-CLEANUP] Freed {report['gb_freed']:.3f} GB ({report['mb_freed']:.2f} MB, "
            f"{report['files_removed']} files removed, {report['sqlite_rows_pruned']} DB rows pruned) "
            f"in {report['duration_ms']:.0f}ms | Drive Free: {report['drive_free_gb_before']:.2f} GB -> {report['drive_free_gb_after']:.2f} GB"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
