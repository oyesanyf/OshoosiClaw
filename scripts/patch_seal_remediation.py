#!/usr/bin/env python3
"""
scripts/patch_seal_remediation.py
Applies the 4-part .env seal remediation roadmap to crates/osoosi-core and crates/osoosi-dashboard:
1. ShadowVaultOnly default (zero disk mutation in production unless in_place_disk_seal: true)
2. Verified Atomic Revert Gate (refuse to shred vault if any file/registry still has stand-in tokens)
3. Persistent per-file exclusion on unseal-file
4. Standin Recovery Ledger (database/standin_recovery.vault) and unconditional WM_SETTINGCHANGE broadcast
5. Multi-vault discovery (scanning database/ for all *.vault files including protected_security_posture.vault)
"""

from pathlib import Path
import re
import sys

def patch_protected_env_backup():
    path = Path("crates/osoosi-core/src/protected_env_backup.rs")
    content = path.read_text(encoding="utf-8")

    # 1. Update add_excluded_file_to_config to auto-create config if missing,
    # and add the Standin Recovery Ledger methods.
    old_marker = '    pub fn add_excluded_file_to_config(file_path: &Path) {'
    if old_marker not in content:
        print("[ERROR] add_excluded_file_to_config not found")
        sys.exit(1)

    # Find the end of add_excluded_file_to_config
    pattern_add_ex = re.compile(
        r'(    pub fn add_excluded_file_to_config\(file_path: &Path\) \{[\s\S]*?if let Ok\(out\) = serde_json::to_vec_pretty\(&val\) \{\s*let _ = std::fs::write\(&p, out\);\s*\}\s*\}\s*\}\s*\}\s*\}\s*\}\s*\})',
        re.MULTILINE
    )
    m = pattern_add_ex.search(content)
    if not m:
        print("[ERROR] Could not match add_excluded_file_to_config body")
        sys.exit(1)

    new_add_excluded = """    pub fn add_excluded_file_to_config(file_path: &Path) {
        if std::env::var_os("RUST_TEST_THREADS").is_some() {
            return;
        }
        let canon_str = file_path
            .canonicalize()
            .unwrap_or_else(|_| file_path.to_path_buf())
            .to_string_lossy()
            .to_string();
        let norm_target = Self::normalize_file_key(file_path);
        let mut updated_any = false;

        for p in Self::candidate_env_seal_config_paths() {
            if p.is_file() {
                if let Ok(bytes) = std::fs::read(&p) {
                    if let Ok(mut val) = serde_json::from_slice::<serde_json::Value>(&bytes) {
                        if let Some(obj) = val.as_object_mut() {
                            let mut list: Vec<String> = obj
                                .get("excluded_files")
                                .and_then(|v| v.as_array())
                                .map(|arr| {
                                    arr.iter()
                                        .filter_map(|x| x.as_str().map(|s| s.to_string()))
                                        .collect()
                                })
                                .unwrap_or_default();
                            let already = list.iter().any(|existing| {
                                Self::normalize_file_key(Path::new(existing)) == norm_target
                            });
                            if !already {
                                list.push(canon_str.clone());
                            }
                            obj.insert(
                                "excluded_files".to_string(),
                                serde_json::to_value(list)
                                    .unwrap_or(serde_json::Value::Array(vec![])),
                            );
                            if let Ok(out) = serde_json::to_vec_pretty(&val) {
                                let _ = std::fs::write(&p, out);
                                updated_any = true;
                            }
                        }
                    }
                }
            }
        }

        if !updated_any {
            let default_path = PathBuf::from(DEFAULT_ENV_SEAL_CONFIG_PATH);
            if let Some(parent) = default_path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            let initial = serde_json::json!({
                "enabled": true,
                "experimental": true,
                "in_place_disk_seal": false,
                "excluded_files": [canon_str],
            });
            let _ = std::fs::write(&default_path, serde_json::to_vec_pretty(&initial).unwrap_or_default());
        }
    }

    /// Persistent cross-vault stand-in recovery ledger file path (`database/standin_recovery.vault`).
    pub const RECOVERY_LEDGER_PATH: &'static str = "database/standin_recovery.vault";

    /// Resolves the canonical path to the standin recovery ledger.
    pub fn recovery_ledger_path() -> PathBuf {
        let default_p = PathBuf::from(Self::RECOVERY_LEDGER_PATH);
        if default_p.parent().map(|p| p.exists()).unwrap_or(false) || default_p.exists() {
            return default_p;
        }
        if let Ok(exe) = std::env::current_exe() {
            if let Some(p) = exe.parent() {
                let candidate = p.join(Self::RECOVERY_LEDGER_PATH);
                if candidate.parent().map(|d| d.exists()).unwrap_or(false) || candidate.exists() {
                    return candidate;
                }
            }
        }
        default_p
    }

    /// Loads the persistent cross-vault stand-in recovery ledger as a dictionary mapping:
    /// `standin_token -> (key_name, plaintext_secret)`
    pub fn load_standin_recovery_ledger() -> Result<std::collections::HashMap<String, (String, String)>, VaultError> {
        let p = Self::recovery_ledger_path();
        if !p.exists() {
            return Ok(std::collections::HashMap::new());
        }
        let (payload, _) = Self::read_vault_payload(&p)?;
        let mut map = std::collections::HashMap::new();
        for (k, standin) in payload.standin_mappings {
            if let Some((_, orig_v)) = payload.original_env_vars.iter().find(|(ok, _)| ok.eq_ignore_ascii_case(&k)) {
                if !orig_v.starts_with("OSHOOSI_STANDIN_") && !orig_v.is_empty() {
                    map.insert(standin, (k, orig_v.clone()));
                }
            }
        }
        Ok(map)
    }

    /// Appends newly generated stand-in token mappings to the persistent recovery ledger
    /// so that any stand-in token ever issued remains recoverable even across vault shred cycles.
    pub fn record_in_standin_recovery_ledger(
        new_mappings: &[(String, String)],
        new_secrets: &[(String, String)],
    ) {
        if new_mappings.is_empty() {
            return;
        }
        let p = Self::recovery_ledger_path();
        let mut existing_payload = Self::read_vault_payload(&p).ok().map(|(payload, _)| payload).unwrap_or_else(|| {
            VaultPayload {
                target_path: "standin_recovery".to_string(),
                epoch: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
                sealed_variables: Vec::new(),
                original_bytes: Vec::new(),
                standin_mappings: Vec::new(),
                original_env_vars: Vec::new(),
                original_hkcu_vars: Vec::new(),
                target_existed_before: true,
                original_sha256: None,
                files: Vec::new(),
                user_sid_env: std::collections::HashMap::new(),
                dpapi_wrapped_key: None,
            }
        });

        let mut changed = false;
        for (k, standin) in new_mappings {
            if !existing_payload.standin_mappings.iter().any(|(_, s)| s == standin) {
                existing_payload.standin_mappings.push((k.clone(), standin.clone()));
                if !existing_payload.sealed_variables.contains(k) {
                    existing_payload.sealed_variables.push(k.clone());
                }
                changed = true;
            }
        }
        for (k, sec) in new_secrets {
            if !sec.starts_with("OSHOOSI_STANDIN_") && !sec.is_empty() {
                if let Some(entry) = existing_payload.original_env_vars.iter_mut().find(|(ek, _)| ek.eq_ignore_ascii_case(k)) {
                    if entry.1.is_empty() || entry.1.starts_with("OSHOOSI_STANDIN_") {
                        entry.1 = sec.clone();
                        changed = true;
                    }
                } else {
                    existing_payload.original_env_vars.push((k.clone(), sec.clone()));
                    changed = true;
                }
            }
        }

        if changed {
            let _ = Self::write_vault_payload(&p, &existing_payload);
        }
    }"""
    content = content[:m.start()] + new_add_excluded + content[m.end():]

    # 2. Update scrub_bytes_with_mappings to consult load_standin_recovery_ledger()
    scrub_pattern = re.compile(
        r'(if let Some\(\(_, orig_v\)\) = original_env_vars[\s\S]*?scrubbed = scrubbed\.replace\(standin, orig_v\);\s*\}\s*\})',
        re.MULTILINE
    )
    scrub_match = scrub_pattern.search(content)
    if not scrub_match:
        print("[ERROR] Could not match scrub_bytes_with_mappings inner block")
        sys.exit(1)

    new_scrub_inner = """if let Some((_, orig_v)) = original_env_vars
                    .iter()
                    .find(|(ok, ov)| {
                        ok.eq_ignore_ascii_case(k) && !ov.starts_with("OSHOOSI_STANDIN_")
                    })
                    .or_else(|| {
                        original_hkcu_vars.iter().find(|(ok, ov)| {
                            ok.eq_ignore_ascii_case(k) && !ov.starts_with("OSHOOSI_STANDIN_")
                        })
                    })
                {
                    scrubbed = scrubbed.replace(standin, orig_v);
                }
            }
            // Consult persistent cross-vault standin recovery ledger if tokens remain
            if scrubbed.contains("OSHOOSI_STANDIN_") {
                if let Ok(ledger) = Self::load_standin_recovery_ledger() {
                    for (s_tok, (_k, orig_sec)) in &ledger {
                        if scrubbed.contains(s_tok) {
                            scrubbed = scrubbed.replace(s_tok, orig_sec);
                        }
                    }
                }
            }"""
    content = content[:scrub_match.start()] + new_scrub_inner + content[scrub_match.end():]

    # Also update line-by-line fallback in scrub_bytes_with_mappings
    line_fallback_marker = 'fixed_lines.push(replaced_line.unwrap_or_else(|| line.to_string()));'
    old_line_fallback = """                        fixed_lines.push(replaced_line.unwrap_or_else(|| line.to_string()));"""
    new_line_fallback = """                        if replaced_line.is_none() {
                            if let Ok(ledger) = Self::load_standin_recovery_ledger() {
                                for (_s_tok, (k_name, sec_val)) in &ledger {
                                    if !sec_val.starts_with("OSHOOSI_STANDIN_") && !sec_val.is_empty() {
                                        if let Some(rep) = Self::replace_env_var_in_line(line, k_name, sec_val) {
                                            replaced_line = Some(rep);
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                        fixed_lines.push(replaced_line.unwrap_or_else(|| line.to_string()));"""
    if old_line_fallback in content:
        content = content.replace(old_line_fallback, new_line_fallback, 1)

    # 3. In seal_and_backup: call record_in_standin_recovery_ledger
    seal_and_backup_marker = 'Self::write_vault_payload(vault_path, &payload)?;'
    if seal_and_backup_marker in content:
        # replace occurrences with recording in recovery ledger
        content = content.replace(
            seal_and_backup_marker,
            "Self::write_vault_payload(vault_path, &payload)?;\n        Self::record_in_standin_recovery_ledger(&payload.standin_mappings, &payload.original_env_vars);",
            1
        )

    # 4. In remove_backup: Implement Verified Atomic Revert Gate
    rem_bak_pattern = re.compile(
        r'(pub fn remove_backup\(vault_path: &Path, confirm: bool\) -> Result<\(\), VaultError> \{\s*if !confirm \{\s*return Err\(VaultError::ConfirmationRequired\);\s*\}\s*if !vault_path\.exists\(\) \{\s*return Ok\(\(\)\);\s*\}\s*)',
        re.MULTILINE
    )
    rem_bak_match = rem_bak_pattern.search(content)
    if not rem_bak_match:
        print("[ERROR] remove_backup start not found")
        sys.exit(1)

    new_rem_bak = """pub fn remove_backup(vault_path: &Path, confirm: bool) -> Result<(), VaultError> {
        if !confirm {
            return Err(VaultError::ConfirmationRequired);
        }

        if !vault_path.exists() {
            return Ok(());
        }

        // VERIFIED ATOMIC REVERT GATE:
        // Refuse to delete or shred the vault if any tracked file or HKCU registry key
        // still contains an un-reverted OSHOOSI_STANDIN_* token.
        if let Ok((payload, _)) = Self::read_vault_payload(vault_path) {
            for file_entry in &payload.files {
                let p = Path::new(&file_entry.path);
                if p.is_file() {
                    if let Ok(bytes) = std::fs::read(p) {
                        if bytes.windows(16).any(|w| w == b"OSHOOSI_STANDIN_") {
                            return Err(VaultError::TargetError(format!(
                                "Refusing to shred vault '{}': residual stand-in tokens remain in '{}'. The file must be cleanly restored before vault deletion.",
                                vault_path.display(),
                                p.display()
                            )));
                        }
                    }
                }
            }
            let target = Path::new(&payload.target_path);
            if target.is_file() {
                if let Ok(bytes) = std::fs::read(target) {
                    if bytes.windows(16).any(|w| w == b"OSHOOSI_STANDIN_") {
                        return Err(VaultError::TargetError(format!(
                            "Refusing to shred vault '{}': residual stand-in tokens remain in '{}'. The file must be cleanly restored before vault deletion.",
                            vault_path.display(),
                            target.display()
                        )));
                    }
                }
            }
        }

        #[cfg(windows)]
        if is_production_vault_path(vault_path) {
            for (k, v) in read_hkcu_environment_vars() {
                if v.starts_with("OSHOOSI_STANDIN_") && !k.eq_ignore_ascii_case("PATH") {
                    return Err(VaultError::TargetError(format!(
                        "Refusing to shred vault '{}': residual stand-in token remains in HKCU\\\\Environment for '{}'. Registry must be cleanly restored before vault deletion.",
                        vault_path.display(),
                        k
                    )));
                }
            }
        }
"""
    content = content[:rem_bak_match.start()] + new_rem_bak + content[rem_bak_match.end():]

    # 5. In auto_revert: merge from recovery ledger and broadcast WM_SETTINGCHANGE
    revert_hkcu_marker = 'restore_hkcu_original_vars(&merged_hkcu)?;'
    if revert_hkcu_marker in content:
        content = content.replace(
            revert_hkcu_marker,
            """if let Ok(ledger) = Self::load_standin_recovery_ledger() {
                for (k, v) in ledger.values() {
                    if !v.starts_with("OSHOOSI_STANDIN_")
                        && !merged_hkcu.iter().any(|(mk, _)| mk.eq_ignore_ascii_case(k))
                    {
                        merged_hkcu.push((k.clone(), v.clone()));
                    }
                }
            }
            restore_hkcu_original_vars(&merged_hkcu)?;
            broadcast_wm_settingchange_environment();""",
            1
        )

    # In auto_revert: unconditional broadcast at end
    auto_revert_end_marker = 'Ok(())\n    }'
    # We will find the end of fn auto_revert
    pattern_ar = re.compile(
        r'(if all_temporary \{\s*let _ = Self::remove_backup\(vault_path, true\);\s*\}\s*Ok\(\(\)\s*\})',
        re.MULTILINE
    )
    ar_match = pattern_ar.search(content)
    if ar_match:
        new_ar_end = """if all_temporary {
            let _ = Self::remove_backup(vault_path, true);
        }

        #[cfg(windows)]
        broadcast_wm_settingchange_environment();

        Ok(())
    }"""
        content = content[:ar_match.start()] + new_ar_end + content[ar_match.end():]

    # 6. In seal_and_register_internal:
    # A) allow_in_place_disk_rewrite: strictly require in_place_disk_seal for production vaults
    old_allow_in_place = """        let allow_in_place_disk_rewrite =
            !is_production_vault_path(vault_path) || Self::is_in_place_disk_seal_enabled();"""
    new_allow_in_place = """        let allow_in_place_disk_rewrite = if is_production_vault_path(vault_path) {
            Self::is_in_place_disk_seal_enabled()
        } else {
            true
        };"""
    if old_allow_in_place in content:
        content = content.replace(old_allow_in_place, new_allow_in_place, 1)

    # B) write_vault_payload in seal_and_register_internal: record to standin recovery ledger
    second_write = 'Self::write_vault_payload(vault_path, &verified_payload)?;'
    if second_write in content:
        content = content.replace(
            second_write,
            "Self::write_vault_payload(vault_path, &verified_payload)?;\n        Self::record_in_standin_recovery_ledger(&verified_payload.standin_mappings, &verified_payload.original_env_vars);",
            1
        )

    # C) HKCU reading fallback from standin recovery ledger:
    old_hkcu_standin_read = """                if v.starts_with("OSHOOSI_STANDIN_") {
                    if let Some(ref ex) = existing_vault {
                        if let Some((_, orig_v)) = ex
                            .original_hkcu_vars
                            .iter()
                            .find(|(orig_k, _)| orig_k == &k)
                            .or_else(|| {
                                ex.original_env_vars.iter().find(|(orig_k, _)| orig_k == &k)
                            })
                        {
                            v = orig_v.clone();
                        }
                    }
                }"""
    new_hkcu_standin_read = """                if v.starts_with("OSHOOSI_STANDIN_") {
                    if let Some(ref ex) = existing_vault {
                        if let Some((_, orig_v)) = ex
                            .original_hkcu_vars
                            .iter()
                            .find(|(orig_k, _)| orig_k == &k)
                            .or_else(|| {
                                ex.original_env_vars.iter().find(|(orig_k, _)| orig_k == &k)
                            })
                        {
                            v = orig_v.clone();
                        }
                    }
                    if v.starts_with("OSHOOSI_STANDIN_") {
                        if let Ok(ledger) = Self::load_standin_recovery_ledger() {
                            if let Some((_, sec)) = ledger.get(&v) {
                                v = sec.clone();
                            } else if let Some((_, sec)) = ledger.values().find(|(lk, _)| lk.eq_ignore_ascii_case(&k)) {
                                v = sec.clone();
                            }
                        }
                    }
                }"""
    if old_hkcu_standin_read in content:
        content = content.replace(old_hkcu_standin_read, new_hkcu_standin_read, 1)

    # 7. In locate_all_active_vault_paths: scan candidate directories for all *.vault files
    pattern_locate = re.compile(
        r'(pub fn locate_all_active_vault_paths\(custom_path: Option<&Path>\) -> Vec<PathBuf> \{[\s\S]*?paths\s*\})',
        re.MULTILINE
    )
    loc_match = pattern_locate.search(content)
    if loc_match:
        new_locate = """pub fn locate_all_active_vault_paths(custom_path: Option<&Path>) -> Vec<PathBuf> {
        let mut paths = Vec::new();
        let mut seen = std::collections::HashSet::new();

        let mut add_if_exists = |p: PathBuf| {
            if p.exists() {
                let key = p
                    .canonicalize()
                    .unwrap_or_else(|_| p.clone())
                    .to_string_lossy()
                    .to_ascii_lowercase();
                if seen.insert(key) {
                    paths.push(p);
                }
            }
        };

        if let Some(p) = custom_path {
            add_if_exists(p.to_path_buf());
        }
        add_if_exists(Self::default_vault_path());

        let mut scan_dir_for_vaults = |dir: &Path| {
            if let Ok(entries) = std::fs::read_dir(dir) {
                for entry in entries.flatten() {
                    let p = entry.path();
                    if p.is_file() {
                        if let Some(ext) = p.extension() {
                            if ext.eq_ignore_ascii_case("vault") {
                                add_if_exists(p);
                            }
                        }
                    }
                }
            }
            let db_dir = dir.join("database");
            if db_dir.is_dir() {
                if let Ok(entries) = std::fs::read_dir(&db_dir) {
                    for entry in entries.flatten() {
                        let p = entry.path();
                        if p.is_file() {
                            if let Some(ext) = p.extension() {
                                if ext.eq_ignore_ascii_case("vault") {
                                    add_if_exists(p);
                                }
                            }
                        }
                    }
                }
            }
        };

        if let Ok(cwd) = std::env::current_dir() {
            scan_dir_for_vaults(&cwd);
        }
        scan_dir_for_vaults(Path::new("."));

        if let Ok(exe) = std::env::current_exe() {
            let mut cur = exe.parent();
            for _ in 0..6 {
                if let Some(dir) = cur {
                    scan_dir_for_vaults(dir);
                    cur = dir.parent();
                } else {
                    break;
                }
            }
        }

        #[cfg(windows)]
        {
            if let Ok(pd) = std::env::var("ProgramData") {
                scan_dir_for_vaults(&PathBuf::from(pd).join("OshoosiClaw"));
            }
            scan_dir_for_vaults(Path::new(r"C:\\ProgramData\\OshoosiClaw"));
            scan_dir_for_vaults(Path::new(r"C:\\Program Files\\OshoosiClaw"));
        }

        #[cfg(unix)]
        {
            scan_dir_for_vaults(Path::new("/var/lib/oshoosi"));
            scan_dir_for_vaults(Path::new("/etc/oshoosi"));
        }

        paths
    }"""
        content = content[:loc_match.start()] + new_locate + content[loc_match.end():]

    # 8. In is_production_vault_path: match any production vault in database/
    old_prod_check = """        s == "database\\\\protected_env_backup.vault"
            || s.ends_with("\\\\database\\\\protected_env_backup.vault")"""
    new_prod_check = """        s.ends_with(".vault")
            && (s == "database\\\\protected_env_backup.vault"
                || s.ends_with("\\\\database\\\\protected_env_backup.vault")
                || s.contains("\\\\database\\\\")
                || s.starts_with("database\\\\")
                || s.contains("protected_"))"""
    if old_prod_check in content:
        content = content.replace(old_prod_check, new_prod_check, 1)

    # 9. Make broadcast_wm_settingchange_environment public
    old_broadcast_fn = "fn broadcast_wm_settingchange_environment() {"
    new_broadcast_fn = "pub fn broadcast_wm_settingchange_environment() {"
    if old_broadcast_fn in content:
        content = content.replace(old_broadcast_fn, new_broadcast_fn, 1)

    # 10. In restore_hkcu_original_vars: check recovery ledger if fallback_secrets missing
    old_reg_check = """            if val.starts_with("OSHOOSI_STANDIN_") && !k.eq_ignore_ascii_case("PATH") {
                if let Some(clean_sec) = fallback_secrets.get(&k.to_ascii_uppercase()) {
                    let _ = env_key.set_value(&k, clean_sec);
                    std::env::set_var(&k, clean_sec);
                    any_restored = true;
                }
            }"""
    new_reg_check = """            if val.starts_with("OSHOOSI_STANDIN_") && !k.eq_ignore_ascii_case("PATH") {
                if let Some(clean_sec) = fallback_secrets.get(&k.to_ascii_uppercase()) {
                    let _ = env_key.set_value(&k, clean_sec);
                    std::env::set_var(&k, clean_sec);
                    any_restored = true;
                } else if let Ok(ledger) = ProtectedEnvBackupVault::load_standin_recovery_ledger() {
                    if let Some((_, sec)) = ledger.get(&val) {
                        let _ = env_key.set_value(&k, sec);
                        std::env::set_var(&k, sec);
                        any_restored = true;
                    } else if let Some((_, sec)) = ledger.values().find(|(lk, _)| lk.eq_ignore_ascii_case(&k)) {
                        let _ = env_key.set_value(&k, sec);
                        std::env::set_var(&k, sec);
                        any_restored = true;
                    }
                }
            }"""
    if old_reg_check in content:
        content = content.replace(old_reg_check, new_reg_check, 1)

    # Write patched file back with utf-8 encoding
    path.write_text(content, encoding="utf-8")
    print("[SUCCESS] Patched crates/osoosi-core/src/protected_env_backup.rs")


def patch_env_gateway():
    path = Path("crates/osoosi-dashboard/src/routes/env_gateway.rs")
    content = path.read_text(encoding="utf-8")

    # In post_env_gateway_revert: ensure single file revert adds to cfg.excluded_files and saves cfg
    old_revert_single = """        if let Some(fp) = req.file_path {
            ProtectedEnvBackupVault::revert_single_file_across_all_vaults(
                v_path.as_deref(),
                Path::new(&fp),
            )
            .map_err(|e| format!("Revert failed: {}", e))?;
            push_watcher_event(WatcherEventRecord {
                timestamp: chrono::Utc::now().to_rfc3339(),
                file_path: fp.clone(),
                magika_label: None,
                magika_mime_type: None,
                magika_score: None,
                action_taken: "reverted_single_file".to_string(),
            });
            Ok(json!({
                "status": "success",
                "file_path": fp,
                "message": "Target environment file restored from vault and excluded from background re-sealing.",
            }))"""
    new_revert_single = """        if let Some(fp) = req.file_path {
            ProtectedEnvBackupVault::revert_single_file_across_all_vaults(
                v_path.as_deref(),
                Path::new(&fp),
            )
            .map_err(|e| format!("Revert failed: {}", e))?;
            let norm_target = ProtectedEnvBackupVault::normalize_file_key(Path::new(&fp));
            if !cfg.excluded_files.iter().any(|existing| {
                ProtectedEnvBackupVault::normalize_file_key(Path::new(existing)) == norm_target
            }) {
                cfg.excluded_files.push(fp.clone());
                let _ = cfg.save(None);
            }
            push_watcher_event(WatcherEventRecord {
                timestamp: chrono::Utc::now().to_rfc3339(),
                file_path: fp.clone(),
                magika_label: None,
                magika_mime_type: None,
                magika_score: None,
                action_taken: "reverted_single_file".to_string(),
            });
            Ok(json!({
                "status": "success",
                "file_path": fp,
                "message": "Target environment file restored from vault and excluded from background re-sealing.",
            }))"""
    if old_revert_single in content:
        content = content.replace(old_revert_single, new_revert_single, 1)

    # In post_env_gateway_unseal_file: ensure file is added to cfg.excluded_files and saves cfg
    old_unseal = """        ProtectedEnvBackupVault::revert_single_file_across_all_vaults(
            v_path.as_deref(),
            Path::new(&req.file_path),
        )
        .map_err(|e| format!("Revert failed: {}", e))?;

        push_watcher_event(WatcherEventRecord {"""
    new_unseal = """        ProtectedEnvBackupVault::revert_single_file_across_all_vaults(
            v_path.as_deref(),
            Path::new(&req.file_path),
        )
        .map_err(|e| format!("Revert failed: {}", e))?;

        let norm_target = ProtectedEnvBackupVault::normalize_file_key(Path::new(&req.file_path));
        if !cfg.excluded_files.iter().any(|existing| {
            ProtectedEnvBackupVault::normalize_file_key(Path::new(existing)) == norm_target
        }) {
            cfg.excluded_files.push(req.file_path.clone());
            let _ = cfg.save(None);
        }

        push_watcher_event(WatcherEventRecord {"""
    if old_unseal in content:
        content = content.replace(old_unseal, new_unseal, 1)

    path.write_text(content, encoding="utf-8")
    print("[SUCCESS] Patched crates/osoosi-dashboard/src/routes/env_gateway.rs")


if __name__ == "__main__":
    patch_protected_env_backup()
    patch_env_gateway()
