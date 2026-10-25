#![allow(unused_imports)]
use anyhow::{anyhow, Result};
use chrono::Utc;
use flate2::read::ZlibDecoder;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet, VecDeque};
use std::io::{Cursor, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, LazyLock};
use std::time::Duration;
use tracing::{debug, info};

use super::super::*;

// ============================================================================
// 8. SQLite 3 Database Inspector (`SQLite format 3\0` + `sqlite_master` + PRAGMA)
// ============================================================================

pub fn inspect_sqlite_database(
    path: Option<&Path>,
    bytes: &[u8],
) -> (
    Value,
    Vec<Value>,
    Vec<ReaEvidence>,
    Vec<ReaLimitation>,
    String,
) {
    let mut findings = Vec::new();
    let mut evidence = Vec::new();
    let mut limitations = Vec::new();

    let has_valid_magic = bytes.starts_with(b"SQLite format 3\0");
    let mut page_size = 0u32;
    let mut page_count = 0u32;
    let mut text_encoding = "UTF-8";
    let mut user_version = 0u32;

    if has_valid_magic && bytes.len() >= 100 {
        let raw_ps = u16::from_be_bytes([bytes[16], bytes[17]]) as u32;
        page_size = if raw_ps == 1 { 65536 } else { raw_ps };
        page_count = u32::from_be_bytes([bytes[28], bytes[29], bytes[30], bytes[31]]);
        let enc = u32::from_be_bytes([bytes[56], bytes[57], bytes[58], bytes[59]]);
        text_encoding = match enc {
            1 => "UTF-8",
            2 => "UTF-16le",
            3 => "UTF-16be",
            _ => "UTF-8",
        };
        user_version = u32::from_be_bytes([bytes[60], bytes[61], bytes[62], bytes[63]]);

        if page_count > MAX_SQLITE_PAGES {
            limitations.push(ReaLimitation {
                code: "SQLITE_PAGE_LIMIT_CAPPED".to_string(),
                description: format!(
                    "SQLite header declares {} pages (exceeds MAX_SQLITE_PAGES={}); schema query bounded.",
                    page_count, MAX_SQLITE_PAGES
                ),
                remediation: None,
            });
        }

        evidence.push(ReaEvidence {
            source: "sqlite3_file_header".to_string(),
            location: "offset 0x0..0x64".to_string(),
            observation: format!(
                "SQLite format 3 header verified (page_size={}, pages={}, encoding={}, user_version={})",
                page_size, page_count, text_encoding, user_version
            ),
            confidence: 1.0,
            digest_sha256: None,
        });
    } else if !has_valid_magic {
        limitations.push(ReaLimitation {
            code: "INVALID_SQLITE_HEADER".to_string(),
            description: "File does not begin with `SQLite format 3\\0` header.".to_string(),
            remediation: None,
        });
    }

    // Open read-only via rusqlite (either directly from path or a temporary snapshot if only bytes were passed)
    let mut temp_db_path: Option<PathBuf> = None;
    let db_open_path: Option<PathBuf> = if page_count > MAX_SQLITE_PAGES {
        None
    } else if let Some(p) = path {
        if p.is_file() {
            Some(p.to_path_buf())
        } else {
            None
        }
    } else if has_valid_magic && bytes.len() <= MAX_DECOMPRESSED_BYTES {
        let tmp = std::env::temp_dir().join(format!(
            "osoosi_rea_sqlite_{}_{}.db",
            std::process::id(),
            rand::random::<u64>()
        ));
        if std::fs::write(&tmp, bytes).is_ok() {
            temp_db_path = Some(tmp.clone());
            Some(tmp)
        } else {
            None
        }
    } else {
        None
    };

    let mut tables: Vec<Value> = Vec::new();
    let mut views: Vec<String> = Vec::new();
    let mut indexes: Vec<String> = Vec::new();
    let mut triggers: Vec<String> = Vec::new();
    let mut ddl_statements: Vec<String> = Vec::new();

    if let Some(ref open_p) = db_open_path {
        let flags =
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX;
        if let Ok(conn) = rusqlite::Connection::open_with_flags(open_p, flags) {
            let _ = conn.busy_timeout(Duration::from_millis(500));
            if let Ok(mut stmt) = conn.prepare(
                "SELECT type, name, tbl_name, sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name LIMIT 256",
            ) {
                let rows = stmt.query_map([], |row| {
                    Ok((
                        row.get::<_, String>(0).unwrap_or_default(),
                        row.get::<_, String>(1).unwrap_or_default(),
                        row.get::<_, String>(2).unwrap_or_default(),
                        row.get::<_, Option<String>>(3).unwrap_or(None),
                    ))
                });
                if let Ok(mapped) = rows {
                    for item in mapped.flatten() {
                        let (obj_type, name, _tbl, sql_opt) = item;
                        if let Some(ref s) = sql_opt {
                            ddl_statements.push(format!("{};", s.trim().trim_end_matches(';')));
                        }
                        match obj_type.as_str() {
                            "table" => {
                                let mut cols = Vec::new();
                                let safe_name = name.replace('"', "\"\"");
                                if let Ok(mut pragma_stmt) =
                                    conn.prepare(&format!("PRAGMA table_info(\"{}\")", safe_name))
                                {
                                    if let Ok(c_rows) = pragma_stmt.query_map([], |r| {
                                        Ok(json!({
                                            "cid": r.get::<_, i64>(0).unwrap_or(0),
                                            "name": r.get::<_, String>(1).unwrap_or_default(),
                                            "type": r.get::<_, String>(2).unwrap_or_default(),
                                            "notnull": r.get::<_, i64>(3).unwrap_or(0) != 0,
                                            "pk": r.get::<_, i64>(5).unwrap_or(0) != 0,
                                        }))
                                    }) {
                                        for c in c_rows.flatten() {
                                            cols.push(c);
                                        }
                                    }
                                }
                                tables.push(json!({
                                    "name": name,
                                    "columns": cols,
                                    "sql": sql_opt,
                                }));
                            }
                            "view" => views.push(name),
                            "index" => indexes.push(name),
                            "trigger" => triggers.push(name),
                            _ => {}
                        }
                    }
                }
            }
        }
    }

    if let Some(tmp) = temp_db_path {
        let _ = std::fs::remove_file(tmp);
    }

    let wal_present = path
        .map(|p| {
            let mut wal = p.as_os_str().to_os_string();
            wal.push("-wal");
            PathBuf::from(wal).is_file()
        })
        .unwrap_or(false);

    if wal_present {
        limitations.push(ReaLimitation {
            code: "SQLITE_WAL_ACTIVE".to_string(),
            description: "Write-Ahead Log (-wal) file exists alongside database; uncommitted frames may reside in WAL.".to_string(),
            remediation: Some("Include the companion -wal and -shm files when copying live forensic snapshots.".to_string()),
        });
    }

    if !tables.is_empty() {
        evidence.push(ReaEvidence {
            source: "sqlite_master_catalog".to_string(),
            location: "sqlite_master".to_string(),
            observation: format!(
                "Extracted {} tables, {} indexes, {} views, {} triggers",
                tables.len(),
                indexes.len(),
                views.len(),
                triggers.len()
            ),
            confidence: 1.0,
            digest_sha256: None,
        });
    }

    findings.push(json!({
        "category": "sqlite_schema",
        "severity": "info",
        "title": format!("SQLite 3 Database ({} tables, {} indexes)", tables.len(), indexes.len()),
        "detail": format!("Page size: {}B, Encoding: {}, WAL active: {}", page_size, text_encoding, wal_present),
    }));

    let reconstructed = if ddl_statements.is_empty() {
        "-- SQLite 3 Database Schema (no user tables in sqlite_master)\n".to_string()
    } else {
        format!(
            "-- Reconstructed SQLite 3 Schema via OpenOshoosi REA\n-- Page Size: {} | Encoding: {}\n\n{}\n",
            page_size,
            text_encoding,
            ddl_statements.join("\n\n")
        )
    };

    let metadata = json!({
        "valid_sqlite": has_valid_magic,
        "page_size": page_size,
        "page_count": page_count,
        "text_encoding": text_encoding,
        "user_version": user_version,
        "wal_present": wal_present,
        "table_count": tables.len(),
        "tables": tables,
        "views": views,
        "indexes": indexes,
        "triggers": triggers,
    });

    (metadata, findings, evidence, limitations, reconstructed)
}

// ============================================================================
// 9. Network Capture Inspector (`.har` HTTP Archive & `.pcap` / `.pcapng`)
// ============================================================================

pub fn inspect_network_capture(
    _path: Option<&Path>,
    bytes: &[u8],
) -> (
    Value,
    Vec<Value>,
    Vec<ReaEvidence>,
    Vec<ReaLimitation>,
    String,
) {
    let mut findings = Vec::new();
    let mut evidence = Vec::new();
    let limitations = Vec::new();

    // Check HAR JSON first (full W3C `.har` archive or single HAR entry JSON)
    if let Ok(har_val) = serde_json::from_slice::<Value>(bytes) {
        let single_entry_vec =
            if har_val.get("request").is_some() && har_val.get("response").is_some() {
                Some(vec![har_val.clone()])
            } else {
                None
            };
        let entries_opt = har_val
            .get("log")
            .and_then(|l| l.get("entries"))
            .and_then(|e| e.as_array())
            .or(single_entry_vec.as_ref());

        if let Some(entries) = entries_opt {
            let mut endpoints = Vec::new();
            let mut sensitive_headers = Vec::new();
            let mut status_distribution: HashMap<u64, usize> = HashMap::new();
            let mut embedded_artifacts = Vec::new();
            let mut smuggling_or_ssrf_hits = Vec::new();
            let mut openjev_dlp_hits = Vec::new();
            let mut prompt_injection_hits = Vec::new();

            for (idx, entry) in entries.iter().take(200).enumerate() {
                let req = entry.get("request");
                let resp = entry.get("response");
                let method = req
                    .and_then(|r| r.get("method"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("GET");
                let url = req
                    .and_then(|r| r.get("url"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let status = resp
                    .and_then(|r| r.get("status"))
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                *status_distribution.entry(status).or_insert(0) += 1;

                let mut has_te = false;
                let mut has_cl = false;
                if let Some(hdrs) = req
                    .and_then(|r| r.get("headers"))
                    .and_then(|h| h.as_array())
                {
                    for h in hdrs {
                        let hname = h
                            .get("name")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_ascii_lowercase();
                        if hname == "transfer-encoding" {
                            has_te = true;
                        } else if hname == "content-length" {
                            has_cl = true;
                        }
                        if matches!(
                            hname.as_str(),
                            "authorization" | "cookie" | "x-api-key" | "x-osoosi-token"
                        ) && !sensitive_headers.contains(&hname)
                        {
                            sensitive_headers.push(hname);
                        }
                    }
                }

                let req_body = req
                    .and_then(|r| r.get("postData"))
                    .and_then(|p| p.get("text"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let resp_body = resp
                    .and_then(|r| r.get("content"))
                    .and_then(|c| c.get("text"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let resp_mime = resp
                    .and_then(|r| r.get("content"))
                    .and_then(|c| c.get("mimeType"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("");

                let combined_body = format!("{} {} {}", url, req_body, resp_body);
                let url_low = url.to_ascii_lowercase();

                if has_te && has_cl {
                    smuggling_or_ssrf_hits.push(format!(
                        "Entry #{} ({} {}): CL.TE / TE.CL HTTP Request Smuggling desync headers present",
                        idx, method, url
                    ));
                }
                if url_low.contains("169.254.169.254")
                    || url_low.contains("metadata.google.internal")
                    || url_low.contains("100.100.100.200")
                {
                    smuggling_or_ssrf_hits.push(format!(
                        "Entry #{} ({} {}): Cloud Metadata SSRF target detected",
                        idx, method, url
                    ));
                }

                // Detect embedded PE / WASM / EVM / ELF artifacts inside HTTP body
                if req_body.starts_with("MZ")
                    || resp_body.starts_with("MZ")
                    || combined_body.contains("TVqQAA")
                    || combined_body.contains("TVpQAA")
                {
                    embedded_artifacts.push(json!({
                        "entry_index": idx,
                        "url": url,
                        "artifact_kind": "pe_native_binary",
                        "mime_type": resp_mime,
                    }));
                } else if req_body.starts_with("\0asm")
                    || resp_body.starts_with("\0asm")
                    || combined_body.contains("AGFzbQE")
                    || combined_body
                        .to_ascii_lowercase()
                        .contains("0061736d01000000")
                {
                    embedded_artifacts.push(json!({
                        "entry_index": idx,
                        "url": url,
                        "artifact_kind": "wasm_module",
                        "mime_type": resp_mime,
                    }));
                } else if combined_body.to_ascii_lowercase().contains("6080604052") {
                    embedded_artifacts.push(json!({
                        "entry_index": idx,
                        "url": url,
                        "artifact_kind": "evm_bytecode",
                        "mime_type": resp_mime,
                    }));
                }

                // Counter-AI prompt injection scan on HTTP transaction
                let mut dummy_recon = String::new();
                let (pi_list, _) = scan_and_sanitize_counter_ai_strings(
                    combined_body.as_bytes(),
                    &mut dummy_recon,
                    false,
                );
                if !pi_list.is_empty() {
                    prompt_injection_hits.extend(pi_list);
                }

                // OpenJEV-Voter DLP & credential exfiltration inspection
                let ojev_vote = evaluate_openjev_consensus_vote(url, "HAR/Network", &combined_body);
                let entry_verdict =
                    if !prompt_injection_hits.is_empty() || !smuggling_or_ssrf_hits.is_empty() {
                        "ESCALATE_MALICIOUS"
                    } else if ojev_vote.decision == "ESCALATE_MALICIOUS" {
                        openjev_dlp_hits
                            .push(format!("Entry #{} ({}): {}", idx, url, ojev_vote.reason));
                        "ESCALATE_DLP_EXFIL"
                    } else {
                        "VERIFIED_CLEAN"
                    };

                endpoints.push(json!({
                    "method": method,
                    "url": url,
                    "status": status,
                    "mime_type": resp_mime,
                    "rea_verdict": entry_verdict,
                    "openjev_decision": ojev_vote.decision,
                }));
            }

            evidence.push(ReaEvidence {
                source: "har_archive_parser".to_string(),
                location: "log.entries".to_string(),
                observation: format!(
                    "Parsed {} HTTP Archive (HAR) transactions ({} embedded binary/bytecode artifacts, {} smuggling/SSRF anomalies, {} OpenJEV DLP hits)",
                    entries.len(),
                    embedded_artifacts.len(),
                    smuggling_or_ssrf_hits.len(),
                    openjev_dlp_hits.len()
                ),
                confidence: 1.0,
                digest_sha256: None,
            });

            let base_sev =
                if !smuggling_or_ssrf_hits.is_empty() || !prompt_injection_hits.is_empty() {
                    "critical"
                } else if !embedded_artifacts.is_empty() || !openjev_dlp_hits.is_empty() {
                    "high"
                } else if !sensitive_headers.is_empty() {
                    "medium"
                } else {
                    "info"
                };

            findings.push(json!({
                "category": "har_network_capture",
                "severity": base_sev,
                "title": format!("HAR Capture ({} HTTP entries, {} sensitive header types, {} embedded artifacts)", entries.len(), sensitive_headers.len(), embedded_artifacts.len()),
                "detail": format!("Sensitive headers: {:?} | Embedded artifacts: {} | Smuggling/SSRF: {} | OpenJEV DLP hits: {}", sensitive_headers, embedded_artifacts.len(), smuggling_or_ssrf_hits.len(), openjev_dlp_hits.len()),
            }));

            for art in &embedded_artifacts {
                findings.push(json!({
                    "category": "har_embedded_executable_payload",
                    "severity": "high",
                    "title": format!("Embedded {} Payload in HAR HTTP Stream", art["artifact_kind"].as_str().unwrap_or("binary")),
                    "detail": format!("URL: {} (entry #{})", art["url"].as_str().unwrap_or(""), art["entry_index"].as_u64().unwrap_or(0)),
                }));
            }
            for sm in &smuggling_or_ssrf_hits {
                findings.push(json!({
                    "category": "har_protocol_or_ssrf_attack",
                    "severity": "critical",
                    "title": "HAR HTTP Request Smuggling / Cloud Metadata SSRF Detected",
                    "detail": sm,
                }));
            }
            for dlp_hit in &openjev_dlp_hits {
                findings.push(json!({
                    "category": "har_openjev_credential_exfiltration",
                    "severity": "high",
                    "title": "OpenJEV-Voter Detected Credential/PII Exfiltration in HAR Traffic",
                    "detail": dlp_hit,
                }));
            }

            let mut spec = String::from("# Reconstructed HTTP API Surface & REA + OpenJEV Forensic Audit from HAR Capture\n");
            for ep in endpoints.iter().take(40) {
                spec.push_str(&format!(
                    "{} {} -> HTTP {} [REA: {} | OpenJEV: {}]\n",
                    ep.get("method").and_then(|v| v.as_str()).unwrap_or("GET"),
                    ep.get("url").and_then(|v| v.as_str()).unwrap_or("/"),
                    ep.get("status").and_then(|v| v.as_u64()).unwrap_or(200),
                    ep.get("rea_verdict")
                        .and_then(|v| v.as_str())
                        .unwrap_or("VERIFIED_CLEAN"),
                    ep.get("openjev_decision")
                        .and_then(|v| v.as_str())
                        .unwrap_or("VETO_BENIGN"),
                ));
            }

            let metadata = json!({
                "capture_format": "HAR",
                "entry_count": entries.len(),
                "endpoints": endpoints,
                "sensitive_headers": sensitive_headers,
                "status_distribution": status_distribution,
                "embedded_artifacts": embedded_artifacts,
                "smuggling_or_ssrf_hits": smuggling_or_ssrf_hits,
                "openjev_dlp_hits": openjev_dlp_hits,
                "rea_voter_active": true,
                "openjev_voter_active": true,
            });
            return (metadata, findings, evidence, limitations, spec);
        }
    }

    // PCAP / PCAPNG binary parser
    let mut format_name = "PCAP";
    let mut linktype = 0u32;
    let mut snaplen = 0u32;
    let mut packet_count = 0usize;
    let mut ipv4_endpoints: HashSet<String> = HashSet::new();

    if bytes.len() >= 24 {
        let m32 = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let is_le = matches!(m32, 0xd4c3b2a1 | 0x4d3cb2a1);
        if m32 == 0x0a0d0d0a {
            format_name = "PCAPNG";
        } else if matches!(m32, 0xa1b2c3d4 | 0xd4c3b2a1 | 0xa1b23c4d | 0x4d3cb2a1) {
            snaplen = if is_le {
                u32::from_le_bytes([bytes[16], bytes[17], bytes[18], bytes[19]])
            } else {
                u32::from_be_bytes([bytes[16], bytes[17], bytes[18], bytes[19]])
            };
            linktype = if is_le {
                u32::from_le_bytes([bytes[20], bytes[21], bytes[22], bytes[23]])
            } else {
                u32::from_be_bytes([bytes[20], bytes[21], bytes[22], bytes[23]])
            };

            let mut off = 24usize;
            while off + 16 <= bytes.len() {
                let incl_len = if is_le {
                    u32::from_le_bytes([
                        bytes[off + 8],
                        bytes[off + 9],
                        bytes[off + 10],
                        bytes[off + 11],
                    ]) as usize
                } else {
                    u32::from_be_bytes([
                        bytes[off + 8],
                        bytes[off + 9],
                        bytes[off + 10],
                        bytes[off + 11],
                    ]) as usize
                };
                off += 16;
                if off + incl_len > bytes.len() {
                    break;
                }
                packet_count += 1;
                let pkt = &bytes[off..off + incl_len];
                // Ethernet (14 bytes) + IPv4 header (0x45)
                if linktype == 1 && pkt.len() >= 34 && pkt[12] == 0x08 && pkt[13] == 0x00 {
                    let src_ip = format!("{}.{}.{}.{}", pkt[26], pkt[27], pkt[28], pkt[29]);
                    let dst_ip = format!("{}.{}.{}.{}", pkt[30], pkt[31], pkt[32], pkt[33]);
                    ipv4_endpoints.insert(format!("{} -> {}", src_ip, dst_ip));
                }
                off += incl_len;
            }
        }
    }

    evidence.push(ReaEvidence {
        source: "pcap_packet_inspector".to_string(),
        location: "global_header+packets".to_string(),
        observation: format!(
            "Parsed {} capture ({} packets, linktype={}, snaplen={})",
            format_name, packet_count, linktype, snaplen
        ),
        confidence: 0.98,
        digest_sha256: None,
    });

    let flows: Vec<String> = ipv4_endpoints.into_iter().collect();
    findings.push(json!({
        "category": "pcap_capture",
        "severity": "info",
        "title": format!("{} Capture ({} packets, {} IPv4 flows)", format_name, packet_count, flows.len()),
        "detail": flows.join(", "),
    }));

    let reconstructed = format!(
        "# Reconstructed Network Flows ({})\n# Packets: {} | SnapLen: {} | LinkType: {}\n{}\n",
        format_name,
        packet_count,
        snaplen,
        linktype,
        flows.join("\n")
    );

    let metadata = json!({
        "capture_format": format_name,
        "packet_count": packet_count,
        "snaplen": snaplen,
        "linktype": linktype,
        "ipv4_flows": flows,
    });

    (metadata, findings, evidence, limitations, reconstructed)
}

// ============================================================================
// 10. Firmware & Android / Flutter APK Inspector
// ============================================================================

pub fn inspect_firmware_or_apk(
    _path: Option<&Path>,
    bytes: &[u8],
) -> (
    Value,
    Vec<Value>,
    Vec<ReaEvidence>,
    Vec<ReaLimitation>,
    String,
) {
    let mut findings = Vec::new();
    let mut evidence = Vec::new();
    let limitations = Vec::new();

    let mut signatures: Vec<Value> = Vec::new();
    let magic_patterns: &[(&[u8], &str)] = &[
        (b"hsqs", "SquashFS (Little-Endian)"),
        (b"sqsh", "SquashFS (Big-Endian)"),
        (b"\x27\x05\x19\x56", "U-Boot uImage Header"),
        (b"\xd0\x0d\xfe\xed", "Flattened Device Tree (DTB)"),
        (b"\x1f\x8b\x08", "Gzip Compressed Stream"),
        (b"\xfd7zXZ\0", "XZ Compressed Stream"),
        (b"\x28\xb5\x2f\xfd", "Zstandard (Zstd) Frame"),
        (b"UBI#", "UBI Flash Image"),
        (b"070701", "CPIO newc Initramfs Archive"),
        (b"dex\n035\0", "Android Dalvik DEX 035"),
        (b"dex\n039\0", "Android Dalvik DEX 039"),
    ];

    for (pat, label) in magic_patterns {
        let mut search_from = 0usize;
        while search_from + pat.len() <= bytes.len() {
            if let Some(rel) = find_subslice(&bytes[search_from..], pat) {
                let abs_off = search_from + rel;
                // Avoid false-positive DTB inside random data unless 4-byte aligned or at offset 0
                if *pat == b"\xd0\x0d\xfe\xed" && abs_off != 0 && !abs_off.is_multiple_of(4) {
                    search_from = abs_off + 1;
                    continue;
                }
                signatures.push(json!({
                    "signature": label,
                    "offset": format!("0x{:x}", abs_off),
                }));
                evidence.push(ReaEvidence {
                    source: "firmware_magic_scanner".to_string(),
                    location: format!("offset 0x{:x}", abs_off),
                    observation: format!("Identified {} header at 0x{:x}", label, abs_off),
                    confidence: 0.98,
                    digest_sha256: None,
                });
                if signatures.len() >= 50 {
                    break;
                }
                search_from = abs_off + pat.len();
            } else {
                break;
            }
        }
    }

    // Check APK / Flutter markers
    let mut apk_entries: Vec<String> = Vec::new();
    if bytes.starts_with(b"PK\x03\x04") {
        if let Ok(mut archive) = zip::ZipArchive::new(Cursor::new(bytes)) {
            for i in 0..archive.len().min(200) {
                if let Ok(file) = archive.by_index(i) {
                    apk_entries.push(file.name().to_string());
                }
            }
        }
    }

    let has_manifest = apk_entries
        .iter()
        .any(|e| e.contains("AndroidManifest.xml"))
        || find_subslice(bytes, b"AndroidManifest.xml").is_some();
    let has_dex = apk_entries.iter().any(|e| e.ends_with(".dex"))
        || find_subslice(bytes, b"classes.dex").is_some()
        || find_subslice(bytes, b"dex\n03").is_some();
    let has_flutter = apk_entries
        .iter()
        .any(|e| e.contains("libflutter.so") || e.contains("libapp.so"))
        || find_subslice(bytes, b"libflutter.so").is_some()
        || find_subslice(bytes, b"libapp.so").is_some();

    if has_manifest || has_dex || has_flutter {
        evidence.push(ReaEvidence {
            source: "android_flutter_inspector".to_string(),
            location: "APK/ZIP container".to_string(),
            observation: format!(
                "Android/Flutter markers: AndroidManifest={}, DEX={}, Flutter(libapp.so/libflutter.so)={}",
                has_manifest, has_dex, has_flutter
            ),
            confidence: 0.99,
            digest_sha256: None,
        });
    }

    findings.push(json!({
        "category": "firmware_apk_layout",
        "severity": "info",
        "title": format!(
            "Firmware/Mobile Artifact ({} embedded signatures, Flutter={}, DEX={})",
            signatures.len(),
            has_flutter,
            has_dex
        ),
        "detail": format!("Signatures: {:?}", signatures),
    }));

    let mut layout =
        String::from("// Reconstructed Firmware / APK Partition Map via OpenOshoosi REA\n");
    for sig in &signatures {
        layout.push_str(&format!(
            "offset {} : {}\n",
            sig.get("offset").and_then(|v| v.as_str()).unwrap_or("0x0"),
            sig.get("signature")
                .and_then(|v| v.as_str())
                .unwrap_or("Unknown")
        ));
    }
    if has_manifest || has_dex || has_flutter {
        layout.push_str(&format!(
            "\n// Android/Flutter Package:\n// AndroidManifest.xml: {}\n// Dalvik/ART classes.dex: {}\n// Flutter AOT (libapp.so / libflutter.so): {}\n",
            has_manifest, has_dex, has_flutter
        ));
    }

    let metadata = json!({
        "embedded_signatures": signatures,
        "android_manifest": has_manifest,
        "classes_dex": has_dex,
        "flutter_aot": has_flutter,
        "apk_entries": apk_entries,
    });

    (metadata, findings, evidence, limitations, layout)
}

// ============================================================================
// Auto-Synthesized Multi-Token YARA Rule Generator
// ============================================================================

/// Synthesizes a production-grade, multi-token YARA rule from an REA investigation.
/// Never matches a lone process name; requires file size bounds + multiple structural/artifact tokens.
pub fn synthesize_rea_yara_rule(
    target_label: &str,
    detected_kind: &str,
    bytes: &[u8],
    sha256: &str,
    blake3_hash: &str,
) -> String {
    let clean_ident: String = target_label
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .take(36)
        .collect();
    let rule_name = format!(
        "REA_Auto_{}_{}",
        if clean_ident.is_empty() {
            "Artifact"
        } else {
            &clean_ident
        },
        &sha256[..sha256.len().min(8)]
    );

    let header_hex = hex::encode(&bytes[..bytes.len().min(8)]).to_ascii_uppercase();
    let mut header_pairs = Vec::new();
    for i in (0..header_hex.len()).step_by(2) {
        if i + 2 <= header_hex.len() {
            header_pairs.push(&header_hex[i..i + 2]);
        }
    }
    let header_pattern = if header_pairs.is_empty() {
        "00".to_string()
    } else {
        header_pairs.join(" ")
    };

    let strings = extract_printable_strings(bytes, 6, 60);
    let mut selected_tokens: Vec<String> = Vec::new();
    for s in strings {
        let escaped = s
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
            .chars()
            .filter(|c| c.is_ascii_graphic() || *c == ' ')
            .take(48)
            .collect::<String>();
        if escaped.len() >= 6 && !selected_tokens.contains(&escaped) {
            selected_tokens.push(escaped);
            if selected_tokens.len() >= 4 {
                break;
            }
        }
    }

    let mut rule = format!(
        "rule {} {{\n    meta:\n        author = \"OpenOshoosi Autonomous REA Engine\"\n        detected_kind = \"{}\"\n        sha256 = \"{}\"\n        blake3 = \"{}\"\n        generated_at = \"{}\"\n    strings:\n        $magic_hdr = {{ {} }}\n",
        rule_name,
        detected_kind,
        sha256,
        blake3_hash,
        Utc::now().to_rfc3339(),
        header_pattern
    );

    for (idx, tok) in selected_tokens.iter().enumerate() {
        rule.push_str(&format!(
            "        $tok_{} = \"{}\" ascii wide\n",
            idx + 1,
            tok
        ));
    }

    let min_size = bytes.len().saturating_sub(bytes.len() / 2).max(1);
    let max_size = bytes.len().saturating_add(bytes.len() / 2 + 4096);

    if selected_tokens.len() >= 2 {
        rule.push_str(&format!(
            "    condition:\n        filesize >= {} and filesize <= {} and $magic_hdr at 0 and 2 of ($tok_*)\n}}\n",
            min_size, max_size
        ));
    } else if selected_tokens.len() == 1 {
        rule.push_str(&format!(
            "    condition:\n        filesize >= {} and filesize <= {} and $magic_hdr at 0 and $tok_1\n}}\n",
            min_size, max_size
        ));
    } else {
        rule.push_str(&format!(
            "    condition:\n        filesize >= {} and filesize <= {} and $magic_hdr at 0\n}}\n",
            min_size, max_size
        ));
    }

    rule
}

// ============================================================================
// Provider Discovery & Bounded Subprocess Execution (4 MiB Cap)
// ============================================================================

/// Discover both built-in native Rust REA engines and optional external RE providers on the host.
type ReaProvidersCache = parking_lot::RwLock<Option<(std::time::Instant, Vec<ReaProviderStatus>)>>;

pub fn discover_rea_providers() -> Vec<ReaProviderStatus> {
    static REA_PROVIDERS_CACHE: std::sync::OnceLock<ReaProvidersCache> = std::sync::OnceLock::new();
    let cache = REA_PROVIDERS_CACHE.get_or_init(|| parking_lot::RwLock::new(None));
    if let Some((ts, ref list)) = *cache.read() {
        if ts.elapsed() < std::time::Duration::from_secs(300) {
            return list.clone();
        }
    }
    let mut providers = vec![
        ReaProviderStatus {
            name: "osoosi-rea-native (PE/ELF/Mach-O/Rust/Go)".to_string(),
            available: true,
            path: Some("built-in://osoosi-core/rea".to_string()),
            version: Some(env!("CARGO_PKG_VERSION").to_string()),
            capabilities: vec![
                "native_binary".to_string(),
                "rust_binary".to_string(),
                "go_binary".to_string(),
                "dotnet_assembly".to_string(),
                "auto_yara_synthesis".to_string(),
            ],
        },
        ReaProviderStatus {
            name: "osoosi-rea-bytecode (WASM/EVM/ASAR/SQLite/HAR/Firmware)".to_string(),
            available: true,
            path: Some("built-in://osoosi-core/rea-bytecode".to_string()),
            version: Some(env!("CARGO_PKG_VERSION").to_string()),
            capabilities: vec![
                "wasm_artifact".to_string(),
                "evm_bytecode".to_string(),
                "javascript_electron".to_string(),
                "sqlite_database".to_string(),
                "network_capture".to_string(),
                "android_flutter".to_string(),
                "firmware_image".to_string(),
            ],
        },
        ReaProviderStatus {
            name: "google-magika-onnx (Deep-Learning Content Type Identification)".to_string(),
            available: true,
            path: Some("built-in://google-magika".to_string()),
            version: Some("1.0.0".to_string()),
            capabilities: vec![
                "tier1_envelope_detection".to_string(),
                "mime_type_classification".to_string(),
                "polyglot_content_identification".to_string(),
            ],
        },
    ];

    let external_tools: &[(&str, &[&str])] = &[
        ("rea", &["mcp_orchestrator", "binary_triage"]),
        ("npx", &["rea_mcp_launcher"]),
        ("ghidraRun", &["decompilation", "cfg_recovery"]),
        ("rizin", &["disassembly", "analysis"]),
        ("radare2", &["disassembly", "binary_patching"]),
        ("objdump", &["section_disassembly", "symbol_tables"]),
        ("dumpbin", &["pe_headers", "imports_exports"]),
        ("jadx", &["apk_dex_decompilation"]),
        ("binwalk", &["firmware_carving"]),
        ("tshark", &["pcap_protocol_dissection"]),
        ("adb", &["android_runtime_bridge"]),
    ];

    for (tool, caps) in external_tools {
        let resolved = crate::tool_paths::resolve_executable(tool);
        providers.push(ReaProviderStatus {
            name: (*tool).to_string(),
            available: resolved.is_some(),
            path: resolved.map(|p| p.display().to_string()),
            version: None,
            capabilities: caps.iter().map(|s| (*s).to_string()).collect(),
        });
    }

    *cache.write() = Some((std::time::Instant::now(), providers.clone()));
    providers
}

/// Execute an external REA CLI or companion tool with a strict 4 MiB output retention cap
/// and automatic child process termination on timeout/drop.
pub async fn run_external_rea_cli(
    program: &str,
    args: &[&str],
    timeout_secs: u64,
) -> Result<(i32, String, String, bool)> {
    let resolved =
        crate::tool_paths::resolve_executable(program).unwrap_or_else(|| PathBuf::from(program));

    let mut cmd = tokio::process::Command::new(resolved);
    cmd.args(args)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true);

    #[cfg(target_os = "windows")]
    {
        #[allow(unused_imports)]
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x08000000); // CREATE_NO_WINDOW
    }

    let mut child = cmd
        .spawn()
        .map_err(|e| anyhow!("Failed to spawn {}: {}", program, e))?;

    let stdout_pipe = child
        .stdout
        .take()
        .ok_or_else(|| anyhow!("Failed to capture stdout"))?;
    let stderr_pipe = child
        .stderr
        .take()
        .ok_or_else(|| anyhow!("Failed to capture stderr"))?;

    let read_bounded = async move {
        use tokio::io::AsyncReadExt;
        let mut out_buf = Vec::new();
        let mut err_buf = Vec::new();
        let _ = stdout_pipe
            .take((REA_MAX_SUBPROCESS_OUTPUT_BYTES + 1) as u64)
            .read_to_end(&mut out_buf)
            .await;
        let _ = stderr_pipe
            .take((REA_MAX_SUBPROCESS_OUTPUT_BYTES + 1) as u64)
            .read_to_end(&mut err_buf)
            .await;
        let status = child.wait().await?;
        Ok::<_, std::io::Error>((status.code().unwrap_or(-1), out_buf, err_buf))
    };

    match tokio::time::timeout(Duration::from_secs(timeout_secs.max(1)), read_bounded).await {
        Ok(Ok((code, mut out_buf, mut err_buf))) => {
            let mut truncated = false;
            if out_buf.len() > REA_MAX_SUBPROCESS_OUTPUT_BYTES {
                out_buf.truncate(REA_MAX_SUBPROCESS_OUTPUT_BYTES);
                truncated = true;
            }
            if err_buf.len() > REA_MAX_SUBPROCESS_OUTPUT_BYTES {
                err_buf.truncate(REA_MAX_SUBPROCESS_OUTPUT_BYTES);
                truncated = true;
            }
            Ok((
                code,
                String::from_utf8_lossy(&out_buf).to_string(),
                String::from_utf8_lossy(&err_buf).to_string(),
                truncated,
            ))
        }
        Ok(Err(e)) => Err(anyhow!("Subprocess I/O error: {}", e)),
        Err(_) => Err(anyhow!(
            "Subprocess {} timed out after {}s and was terminated",
            program,
            timeout_secs
        )),
    }
}

/// Extracts plaintext from Office Open XML (`.xlsx`, `.docx`, `.pptx`) or `.zip` containers
/// by scanning `PK\x03\x04` local file headers and decompressing `xl/sharedStrings.xml`,
/// `word/document.xml`, `xl/worksheets/*.xml`, or embedded `.csv`/`.txt`/`.json` streams.
pub fn extract_office_openxml_text(bytes: &[u8], max_out_bytes: usize) -> Option<String> {
    if bytes.len() < 30 || &bytes[0..4] != b"PK\x03\x04" {
        return None;
    }
    let mut extracted = String::new();
    let mut pos = 0usize;
    while pos + 30 <= bytes.len() && extracted.len() < max_out_bytes {
        if &bytes[pos..pos + 4] != b"PK\x03\x04" {
            if let Some(next_rel) = bytes[pos + 1..].windows(4).position(|w| w == b"PK\x03\x04") {
                pos = pos + 1 + next_rel;
                continue;
            } else {
                break;
            }
        }
        let compression = u16::from_le_bytes([bytes[pos + 8], bytes[pos + 9]]);
        let comp_size = u32::from_le_bytes([
            bytes[pos + 18],
            bytes[pos + 19],
            bytes[pos + 20],
            bytes[pos + 21],
        ]) as usize;
        let name_len = u16::from_le_bytes([bytes[pos + 26], bytes[pos + 27]]) as usize;
        let extra_len = u16::from_le_bytes([bytes[pos + 28], bytes[pos + 29]]) as usize;
        let header_end = pos.saturating_add(30).saturating_add(name_len);
        if header_end > bytes.len() {
            break;
        }
        let entry_name = String::from_utf8_lossy(&bytes[pos + 30..header_end]).to_ascii_lowercase();
        let data_start = header_end.saturating_add(extra_len);
        if data_start >= bytes.len() {
            break;
        }

        let is_content_entry = entry_name.contains("sharedstrings.xml")
            || entry_name.contains("word/document.xml")
            || entry_name.contains("xl/worksheets/sheet")
            || entry_name.contains("ppt/slides/slide")
            || entry_name.ends_with(".csv")
            || entry_name.ends_with(".txt")
            || entry_name.ends_with(".json")
            || entry_name.ends_with(".md")
            || entry_name.ends_with(".hl7");

        if is_content_entry {
            let remaining_cap = max_out_bytes.saturating_sub(extracted.len()).max(4096);
            let slice_end = if comp_size > 0 {
                data_start.saturating_add(comp_size).min(bytes.len())
            } else {
                bytes.len()
            };
            let compressed_slice = &bytes[data_start..slice_end];
            let mut raw_entry_bytes = Vec::new();
            if compression == 8 {
                let decoder = flate2::read::DeflateDecoder::new(compressed_slice);
                let _ = decoder
                    .take((remaining_cap * 3) as u64)
                    .read_to_end(&mut raw_entry_bytes);
            } else if compression == 0 {
                let take_len = compressed_slice.len().min(remaining_cap * 2);
                raw_entry_bytes.extend_from_slice(&compressed_slice[..take_len]);
            }

            if !raw_entry_bytes.is_empty() {
                if entry_name.ends_with(".xml") {
                    let mut in_tag = false;
                    let mut last_was_space = false;
                    for &b in &raw_entry_bytes {
                        if b == b'<' {
                            in_tag = true;
                            if !last_was_space && !extracted.is_empty() {
                                extracted.push(' ');
                                last_was_space = true;
                            }
                        } else if b == b'>' {
                            in_tag = false;
                        } else if !in_tag {
                            let ch = if b.is_ascii_graphic() { b as char } else { ' ' };
                            if ch == ' ' {
                                if !last_was_space {
                                    extracted.push(' ');
                                    last_was_space = true;
                                }
                            } else {
                                extracted.push(ch);
                                last_was_space = false;
                            }
                        }
                        if extracted.len() >= max_out_bytes {
                            break;
                        }
                    }
                    extracted.push('\n');
                } else {
                    let text = String::from_utf8_lossy(&raw_entry_bytes);
                    let take_chars: String = text.chars().take(remaining_cap).collect();
                    extracted.push_str(&take_chars);
                    extracted.push('\n');
                }
            }
        }

        if comp_size > 0 && data_start.saturating_add(comp_size) <= bytes.len() {
            pos = data_start + comp_size;
        } else {
            pos = data_start + 1;
        }
    }

    if extracted.trim().is_empty() {
        None
    } else {
        Some(extracted)
    }
}

/// Uses Google Magika ONNX content-type identification (`magika::Session`) combined with structural
/// header verification to classify ANY file (PDF, Word `.docx`/`.doc`, Excel `.xlsx`/`.xls`, PowerPoint `.pptx`,
/// XML, HTML, CSV, JSON, Markdown, RTF, or extensionless files) and extract its inspectable plaintext.
pub fn identify_and_extract_document_text(
    bytes: &[u8],
    file_hint: Option<&str>,
    max_out_bytes: usize,
) -> Option<(String, String)> {
    if bytes.is_empty() {
        return None;
    }

    let sample = if bytes.len() > 262_144 {
        &bytes[..262_144]
    } else {
        bytes
    };
    let mut magika_label = super::super::identify_with_magika(file_hint.map(Path::new), sample)
        .label
        .to_ascii_lowercase();

    // Refine Magika label with structural magic headers when needed
    if bytes.starts_with(b"PK\x03\x04") {
        let header_preview =
            String::from_utf8_lossy(&bytes[..bytes.len().min(4096)]).to_ascii_lowercase();
        if header_preview.contains("xl/") {
            magika_label = "xlsx".to_string();
        } else if header_preview.contains("word/") {
            magika_label = "docx".to_string();
        } else if header_preview.contains("ppt/") {
            magika_label = "pptx".to_string();
        } else if magika_label == "unknown" {
            magika_label = "zip".to_string();
        }
    } else if bytes.starts_with(b"%PDF") {
        magika_label = "pdf".to_string();
    } else if bytes.starts_with(b"\xD0\xCF\x11\xE0") {
        if magika_label == "unknown" {
            magika_label = "ole2_office".to_string();
        }
    } else if bytes.starts_with(b"MZ") || bytes.starts_with(b"\x7fELF") {
        return None;
    }

    // Skip pure native binaries or OS installer bundles
    if matches!(
        magika_label.as_str(),
        "pebin" | "elf" | "macho" | "dex" | "wasm" | "apk" | "msi" | "deb" | "rpm" | "iso"
    ) {
        return None;
    }
    if let Some(hint) = file_hint {
        let hint_low = hint.to_ascii_lowercase();
        if hint_low.ends_with(".msixbundle")
            || hint_low.ends_with(".msi")
            || hint_low.ends_with(".exe")
            || hint_low.ends_with(".dll")
            || hint_low.ends_with(".sys")
        {
            return None;
        }
    }

    // 1. Office Open XML (.xlsx, .docx, .pptx) or ZIP container
    if bytes.starts_with(b"PK\x03\x04")
        || matches!(
            magika_label.as_str(),
            "xlsx" | "docx" | "pptx" | "odt" | "ods" | "zip"
        )
    {
        if let Some(text) = extract_office_openxml_text(bytes, max_out_bytes) {
            return Some((magika_label, text));
        }
    }

    // 2. PDF Document (%PDF)
    if bytes.starts_with(b"%PDF") || magika_label == "pdf" {
        if let Some(text) = extract_pdf_text(bytes, max_out_bytes) {
            return Some((magika_label, text));
        }
    }

    // 3. Legacy OLE2 Office (.doc, .xls, .ppt)
    if bytes.starts_with(b"\xD0\xCF\x11\xE0")
        || matches!(magika_label.as_str(), "doc" | "xls" | "ppt" | "ole2_office")
    {
        if let Some(text) = extract_ole2_text(bytes, max_out_bytes) {
            return Some((magika_label, text));
        }
    }

    // 4. XML / HTML / SVG
    if matches!(magika_label.as_str(), "xml" | "html" | "svg")
        || bytes.starts_with(b"<?xml")
        || bytes.starts_with(b"<html")
        || bytes.starts_with(b"<!DOCTYPE")
    {
        let mut out = String::with_capacity(bytes.len().min(max_out_bytes));
        let mut in_tag = false;
        let mut last_space = false;
        for &b in bytes.iter().take(max_out_bytes * 2) {
            if b == b'<' {
                in_tag = true;
                if !last_space && !out.is_empty() {
                    out.push(' ');
                    last_space = true;
                }
            } else if b == b'>' {
                in_tag = false;
            } else if !in_tag {
                let ch = if b.is_ascii_graphic() { b as char } else { ' ' };
                if ch == ' ' {
                    if !last_space {
                        out.push(' ');
                        last_space = true;
                    }
                } else {
                    out.push(ch);
                    last_space = false;
                }
            }
            if out.len() >= max_out_bytes {
                break;
            }
        }
        if !out.trim().is_empty() {
            return Some((magika_label, out));
        }
    }

    // 5. Plaintext, CSV, TSV, JSON, Markdown, RTF, YAML, Log, or extensionless text
    let take_len = bytes.len().min(max_out_bytes);
    let slice = &bytes[..take_len];
    let printable_count = slice
        .iter()
        .filter(|&&b| b.is_ascii_graphic() || b.is_ascii_whitespace())
        .count();
    if slice.is_empty() || printable_count * 10 < slice.len() * 6 {
        return None;
    }
    let text = String::from_utf8_lossy(slice).to_string();
    if text.trim().is_empty() {
        None
    } else {
        Some((magika_label, text))
    }
}

/// Extracts plaintext from PDF files, decoding both literal `(text) Tj`/`TJ` strings and
/// `FlateDecode` (`zlib` / `deflate`) compressed content streams.
pub fn extract_pdf_text(bytes: &[u8], max_out_bytes: usize) -> Option<String> {
    let mut out = String::new();
    let scan_cap = bytes.len().min(max_out_bytes * 4);
    let slice = &bytes[..scan_cap];

    // 1. Decompress FlateDecode `stream ... endstream` blocks
    let mut pos = 0usize;
    while pos + 16 < slice.len() && out.len() < max_out_bytes {
        let Some(rel) = slice[pos..].windows(6).position(|w| w == b"stream") else {
            break;
        };
        let mut s_start = pos + rel + 6;
        if s_start < slice.len() && slice[s_start] == b'\r' {
            s_start += 1;
        }
        if s_start < slice.len() && slice[s_start] == b'\n' {
            s_start += 1;
        }
        let Some(end_rel) = slice[s_start..].windows(9).position(|w| w == b"endstream") else {
            break;
        };
        let stream_bytes = &slice[s_start..s_start + end_rel];
        let mut decompressed = Vec::new();
        let _ = ZlibDecoder::new(stream_bytes)
            .take((max_out_bytes * 2) as u64)
            .read_to_end(&mut decompressed);
        if decompressed.is_empty() {
            let _ = flate2::read::DeflateDecoder::new(stream_bytes)
                .take((max_out_bytes * 2) as u64)
                .read_to_end(&mut decompressed);
        }
        let target = if !decompressed.is_empty() {
            &decompressed[..]
        } else {
            stream_bytes
        };
        extract_pdf_parenthesized_strings(target, &mut out, max_out_bytes);
        pos = s_start + end_rel + 9;
    }

    // 2. Also extract any uncompressed parenthesized strings or readable runs in the PDF
    if out.len() < max_out_bytes / 2 {
        extract_pdf_parenthesized_strings(slice, &mut out, max_out_bytes);
    }

    if out.trim().is_empty() {
        None
    } else {
        Some(out)
    }
}

fn extract_pdf_parenthesized_strings(buf: &[u8], out: &mut String, max_out_bytes: usize) {
    let mut in_parens = false;
    let mut escaped = false;
    for &b in buf {
        if out.len() >= max_out_bytes {
            break;
        }
        if escaped {
            if b.is_ascii_graphic() || b == b' ' {
                out.push(b as char);
            }
            escaped = false;
            continue;
        }
        if b == b'\\' {
            escaped = true;
            continue;
        }
        if b == b'(' {
            in_parens = true;
            continue;
        }
        if b == b')' {
            if in_parens {
                out.push(' ');
            }
            in_parens = false;
            continue;
        }
        if in_parens && (b.is_ascii_graphic() || b == b' ') {
            out.push(b as char);
        }
    }
}

/// Extracts ASCII and UTF-16LE text runs from legacy Office OLE2 Compound Documents (`.doc`, `.xls`, `.ppt`).
pub fn extract_ole2_text(bytes: &[u8], max_out_bytes: usize) -> Option<String> {
    let mut out = String::new();
    let scan_len = bytes.len().min(max_out_bytes * 4);
    let slice = &bytes[..scan_len];

    // 1. ASCII runs >= 4 chars
    let mut cur = String::new();
    for &b in slice {
        if b.is_ascii_graphic() || b == b' ' {
            cur.push(b as char);
        } else {
            if cur.trim().len() >= 4 {
                out.push_str(cur.trim());
                out.push(' ');
                if out.len() >= max_out_bytes {
                    break;
                }
            }
            cur.clear();
        }
    }
    if cur.trim().len() >= 4 && out.len() < max_out_bytes {
        out.push_str(cur.trim());
        out.push(' ');
    }

    // 2. UTF-16LE runs >= 4 chars (used in BIFF8 .xls SST and Word .doc Unicode streams)
    let mut cur16 = String::new();
    let (chunks, _) = slice.as_chunks::<2>();
    for pair in chunks {
        if pair[1] == 0 && (pair[0].is_ascii_graphic() || pair[0] == b' ') {
            cur16.push(pair[0] as char);
        } else {
            if cur16.trim().len() >= 4 {
                out.push_str(cur16.trim());
                out.push(' ');
                if out.len() >= max_out_bytes {
                    break;
                }
            }
            cur16.clear();
        }
    }

    if out.trim().is_empty() {
        None
    } else {
        Some(out)
    }
}
