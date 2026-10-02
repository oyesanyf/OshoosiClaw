//! VQL (Velociraptor Query Language) query builders and strict input sanitizers.

use regex::Regex;
use std::sync::OnceLock;
use thiserror::Error;

#[derive(Error, Debug, PartialEq, Eq)]
pub enum VqlError {
    #[error("Invalid PID {0}: must be between 4 and 4194304")]
    InvalidPid(u32),
    #[error("Invalid or unsafe path: {0}")]
    InvalidPath(String),
    #[error("Invalid drive letter: {0}")]
    InvalidDrive(char),
    #[error("Sanitization error: {0}")]
    SanitizationFailure(String),
}

static SAFE_PATH_REGEX: OnceLock<Regex> = OnceLock::new();

fn get_safe_path_regex() -> &'static Regex {
    SAFE_PATH_REGEX.get_or_init(|| {
        Regex::new(r"^[a-zA-Z0-9_\\\/\-.: ]+$").expect("valid regex for safe path")
    })
}

/// Validates that a process ID falls within standard operating system bounds [4, 4194304].
pub fn validate_pid(pid: u32) -> Result<u32, VqlError> {
    if (4..=4194304).contains(&pid) {
        Ok(pid)
    } else {
        Err(VqlError::InvalidPid(pid))
    }
}

/// Validates that a drive letter is ASCII alphabetic.
pub fn validate_drive_letter(drive: char) -> Result<char, VqlError> {
    if drive.is_ascii_alphabetic() {
        Ok(drive.to_ascii_uppercase())
    } else {
        Err(VqlError::InvalidDrive(drive))
    }
}

/// Sanitizes and validates a filesystem path against strict character whitelists.
/// Explicitly rejects single quotes, double quotes, semicolons, backticks, and control characters.
pub fn validate_safe_path(path: &str) -> Result<String, VqlError> {
    let trimmed = path.trim();
    if trimmed.is_empty() {
        return Err(VqlError::InvalidPath("Path cannot be empty".to_string()));
    }

    // Reject dangerous syntax and control characters
    for c in trimmed.chars() {
        if c == '\'' || c == '"' || c == ';' || c == '`' || c.is_control() {
            return Err(VqlError::InvalidPath(format!(
                "Dangerous character '{}' detected in path '{}'",
                c, trimmed
            )));
        }
    }

    if !get_safe_path_regex().is_match(trimmed) {
        return Err(VqlError::InvalidPath(format!(
            "Path contains invalid characters not matching whitelist: '{}'",
            trimmed
        )));
    }

    Ok(trimmed.to_string())
}

/// Builds a safe VQL query for inspecting process Virtual Address Descriptor (VAD) regions.
pub fn build_process_vad_query(pid: u32) -> Result<String, VqlError> {
    let safe_pid = validate_pid(pid)?;
    Ok(format!(
        "SELECT Pid, Address, Size, Protection, MappingType, Filename FROM vad(pid={}) WHERE Protection =~ 'EXECUTE'",
        safe_pid
    ))
}

/// Builds a safe VQL query for scanning raw NTFS MFT entries starting from a directory prefix.
pub fn build_mft_scan_query(drive: char, dir_prefix: &str) -> Result<String, VqlError> {
    let safe_drive = validate_drive_letter(drive)?;
    let safe_prefix = validate_safe_path(dir_prefix)?;
    // Escape backslashes for regex pattern inside VQL query string
    let escaped_prefix = safe_prefix.replace('\\', "\\\\");
    Ok(format!(
        "SELECT EntryNumber, FullPath, InUse, Size, Created0x10, Modified0x10 FROM parse_mft(filename='\\\\.\\{}:') WHERE FullPath =~ '^{}' LIMIT 2000",
        safe_drive, escaped_prefix
    ))
}

/// Builds a safe VQL query for querying active network sockets.
pub fn build_network_connections_query(pid: Option<u32>) -> Result<String, VqlError> {
    if let Some(p) = pid {
        let safe_pid = validate_pid(p)?;
        Ok(format!(
            "SELECT Pid, ProcessName, LocalAddress, RemoteAddress, Status FROM netstat() WHERE Pid = {}",
            safe_pid
        ))
    } else {
        Ok("SELECT Pid, ProcessName, LocalAddress, RemoteAddress, Status FROM netstat()".to_string())
    }
}

/// Builds a query to inspect persistence mechanisms (e.g., Run keys in Registry).
pub fn build_persistence_query() -> String {
    "SELECT 'RegistryRun' as ArtifactType, Name, Path, Command as CommandLine, NULL as IsSigned FROM glob(globs=['HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\*'])".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pid_validation_bounds() {
        assert_eq!(validate_pid(4), Ok(4));
        assert_eq!(validate_pid(1234), Ok(1234));
        assert_eq!(validate_pid(4194304), Ok(4194304));

        assert_eq!(validate_pid(0), Err(VqlError::InvalidPid(0)));
        assert_eq!(validate_pid(1), Err(VqlError::InvalidPid(1)));
        assert_eq!(validate_pid(3), Err(VqlError::InvalidPid(3)));
        assert_eq!(validate_pid(4194305), Err(VqlError::InvalidPid(4194305)));
    }

    #[test]
    fn test_drive_letter_validation() {
        assert_eq!(validate_drive_letter('c'), Ok('C'));
        assert_eq!(validate_drive_letter('C'), Ok('C'));
        assert_eq!(validate_drive_letter('z'), Ok('Z'));

        assert_eq!(validate_drive_letter('1'), Err(VqlError::InvalidDrive('1')));
        assert_eq!(validate_drive_letter(':'), Err(VqlError::InvalidDrive(':')));
        assert_eq!(validate_drive_letter(';'), Err(VqlError::InvalidDrive(';')));
    }

    #[test]
    fn test_vql_sanitization_rejects_injection_characters() {
        assert!(validate_safe_path("C:\\Windows\\System32").is_ok());
        assert!(validate_safe_path("D:/harfile/OshoosiClaw/target").is_ok());
        assert!(validate_safe_path("C:\\Program Files\\My App").is_ok());

        // Rejections: quotes, semicolons, backticks, control chars
        assert!(validate_safe_path("C:\\Windows; SELECT * FROM vad()").is_err());
        assert!(validate_safe_path("C:\\Windows' OR '1'='1").is_err());
        assert!(validate_safe_path("C:\\Windows\" OR \"1\"=\"1").is_err());
        assert!(validate_safe_path("C:\\Windows`test`").is_err());
        assert!(validate_safe_path("C:\\Windows\ncalc.exe").is_err());
        assert!(validate_safe_path("").is_err());
    }

    #[test]
    fn test_vad_query_builder() {
        let q = build_process_vad_query(1024).expect("valid query");
        assert!(q.contains("vad(pid=1024)"));
        assert!(q.contains("Protection =~ 'EXECUTE'"));
        assert!(build_process_vad_query(2).is_err());
    }

    #[test]
    fn test_mft_scan_query_builder() {
        let q = build_mft_scan_query('c', "C:\\Windows\\System32").expect("valid query");
        assert!(q.contains("filename='\\\\.\\C:'"));
        assert!(q.contains("WHERE FullPath =~ '^C:\\\\Windows\\\\System32'"));
    }

    #[test]
    fn test_network_connections_query_builder() {
        let q_all = build_network_connections_query(None).expect("valid query");
        assert_eq!(q_all, "SELECT Pid, ProcessName, LocalAddress, RemoteAddress, Status FROM netstat()");

        let q_pid = build_network_connections_query(Some(4321)).expect("valid query");
        assert!(q_pid.contains("WHERE Pid = 4321"));
    }
}
