//! File quarantine for detected malware.
//! Moves files to a quarantine directory with a safe naming scheme.

use std::path::{Path, PathBuf};

/// Move a detected malware file to the quarantine directory.
/// Creates quarantine dir if needed. Preserves filename with hash prefix to avoid collisions.
pub fn quarantine_file(file_path: &str) -> anyhow::Result<PathBuf> {
    let src = Path::new(file_path);
    if !src.exists() {
        return Err(anyhow::anyhow!("File does not exist: {}", file_path));
    }

    // Check symlink to prevent quarantine symlink attacks
    if let Ok(meta) = std::fs::symlink_metadata(src) {
        if meta.file_type().is_symlink() {
            anyhow::bail!("Refusing to quarantine symlink: {}", file_path);
        }
    }

    // Self-protection: refuse to quarantine self infrastructure files
    let fname_lc = src
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    if fname_lc == "osoosi"
        || fname_lc == "osoosi.exe"
        || fname_lc == "osoosi-linux-x86_64"
        || fname_lc == "osoosi_probe.bpf.o"
        || fname_lc == "osoosi-ebpf.o"
        || fname_lc == "osoosi.db"
        || fname_lc == "osoosi.toml"
    {
        anyhow::bail!(
            "Refusing to quarantine self-infrastructure binary/file: {}",
            file_path
        );
    }
    if let Ok(cur_exe) = std::env::current_exe() {
        if let Some(parent) = cur_exe.parent() {
            if let Ok(canon_src) = src.canonicalize() {
                if let Ok(canon_parent) = parent.canonicalize() {
                    if canon_src.starts_with(&canon_parent) {
                        anyhow::bail!(
                            "Refusing to quarantine application directory file: {}",
                            file_path
                        );
                    }
                }
            }
        }
    }

    // System protection: refuse to quarantine Windows/Linux/macOS system binaries, shells, toolchains, or administrative LOLBins
    let normalized = osoosi_types::normalize_nt_device_path(file_path);
    let path_lc = normalized.to_ascii_lowercase();
    if osoosi_types::is_protected_os_shell_or_desktop_binary(&normalized)
        || crate::blocking_manager::is_protected_or_benign_system_path(&normalized)
        || path_lc.contains(r"\windows\")
        || path_lc.starts_with("c:\\windows\\")
        || path_lc.starts_with("/bin/")
        || path_lc.starts_with("/sbin/")
        || path_lc.starts_with("/usr/bin/")
        || path_lc.starts_with("/usr/sbin/")
        || path_lc.starts_with("/usr/libexec/")
        || path_lc.starts_with("/lib/")
        || path_lc.starts_with("/lib64/")
        || path_lc.starts_with("/usr/lib/")
        || path_lc.starts_with("/etc/systemd/")
        || path_lc.starts_with("/system/")
        || crate::system_check::is_administrative_lolbin(&normalized)
    {
        anyhow::bail!(
            "Refusing to quarantine protected OS/system binary or administrative LOLBin: {}",
            file_path
        );
    }

    let quarantine_dir = "quarantine";
    std::fs::create_dir_all(quarantine_dir)?;

    let filename = src
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unknown");
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let rand_suffix = uuid::Uuid::new_v4().simple().to_string();
    let unique_tag = &rand_suffix[..8];
    let dest = Path::new(quarantine_dir).join(format!("{}_{}_{}", nanos, unique_tag, filename));

    if std::fs::rename(src, &dest).is_err() {
        if !src.exists() {
            return Err(anyhow::anyhow!("File does not exist: {}", file_path));
        }
        match std::fs::copy(src, &dest) {
            Ok(_) => {
                let _ = std::fs::remove_file(src);
            }
            Err(e) => {
                if !src.exists() || e.kind() == std::io::ErrorKind::NotFound {
                    return Err(anyhow::anyhow!("File does not exist: {}", file_path));
                }
                return Err(e.into());
            }
        }
    }

    #[cfg(not(target_os = "windows"))]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(0o400));
    }

    Ok(dest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_quarantine_file() {
        let temp_dir = std::env::temp_dir();
        let test_file = temp_dir.join("osoosi_quarantine_test_file.txt");

        // Create a test file
        let mut f = std::fs::File::create(&test_file).unwrap();
        f.write_all(b"test content").unwrap();
        drop(f);

        let result = quarantine_file(test_file.to_str().unwrap());
        assert!(result.is_ok());
        let dest = result.unwrap();
        assert!(dest.exists());
        assert!(dest.to_string_lossy().contains("quarantine"));
        assert!(dest
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with(|c: char| c.is_ascii_digit()));

        // Cleanup
        let _ = std::fs::remove_file(&dest);
    }

    #[test]
    fn test_quarantine_nonexistent_fails() {
        let result = quarantine_file("/nonexistent/path/file.txt");
        assert!(result.is_err());
    }

    #[test]
    fn test_quarantine_refuses_protected_os_shell_and_search_binaries() {
        let temp_dir = std::env::temp_dir().join(format!(
            "osoosi_quarantine_protected_{}",
            uuid::Uuid::new_v4().simple()
        ));
        std::fs::create_dir_all(&temp_dir).unwrap();

        for protected_name in &[
            "SearchHost.exe",
            "sihost.exe",
            "explorer.exe",
            "gnome-shell",
            "tracker-miner-fs-3",
            "Finder",
            "Spotlight",
        ] {
            let p = temp_dir.join(protected_name);
            std::fs::write(&p, b"protected binary test").unwrap();
            let res = quarantine_file(p.to_str().unwrap());
            assert!(
                res.is_err(),
                "quarantine_file must refuse protected OS binary: {}",
                protected_name
            );
            assert!(
                p.exists(),
                "protected file must remain untouched on disk: {}",
                protected_name
            );
        }

        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}
