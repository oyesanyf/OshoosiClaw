//! File quarantine for detected malware.
//! Moves files to a quarantine directory with a safe naming scheme.

use std::path::{Path, PathBuf};

/// Move a detected malware file to the quarantine directory.
/// Creates quarantine dir if needed. Preserves filename with hash prefix to avoid collisions.
pub fn quarantine_file(file_path: &str, quarantine_dir: &str) -> anyhow::Result<PathBuf> {
    let src = Path::new(file_path);
    if !src.exists() {
        return Err(anyhow::anyhow!("File does not exist: {}", file_path));
    }
    if !src.is_file() {
        return Err(anyhow::anyhow!("Not a file: {}", file_path));
    }

    std::fs::create_dir_all(quarantine_dir)?;

    let filename = src
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unknown");
    let hash_suffix = format!(
        "{:x}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    );
    let safe_name = format!("{}_{}", hash_suffix, filename);
    let dest = Path::new(quarantine_dir).join(&safe_name);

    if std::fs::rename(src, &dest).is_err() {
        // Fallback: copy then remove (e.g. cross-device)
        std::fs::copy(src, &dest)?;
        let _ = std::fs::remove_file(src);
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
        let quarantine_dir = temp_dir.join("osoosi_quarantine_test_dir");
        let _ = std::fs::remove_dir_all(&quarantine_dir);

        // Create a test file
        let mut f = std::fs::File::create(&test_file).unwrap();
        f.write_all(b"test content").unwrap();
        drop(f);

        let result = quarantine_file(
            test_file.to_str().unwrap(),
            quarantine_dir.to_str().unwrap(),
        );
        assert!(result.is_ok());
        let dest = result.unwrap();
        assert!(dest.exists());
        assert!(dest.starts_with(&quarantine_dir));
        assert!(dest
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with(|c: char| c.is_ascii_hexdigit()));

        // Cleanup
        let _ = std::fs::remove_file(&dest);
        let _ = std::fs::remove_dir(&quarantine_dir);
    }

    #[test]
    fn test_quarantine_nonexistent_fails() {
        let result = quarantine_file("/nonexistent/path/file.txt", "/tmp/quarantine");
        assert!(result.is_err());
    }
}
