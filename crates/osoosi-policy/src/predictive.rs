//! Predictive remediation: model attack progression.
//! Maps detected TTPs to likely next steps (e.g. credential dumping → lateral movement).

/// Predict next attack step from process/command indicators.
/// Returns human-readable prediction for UI and response planning.
pub fn predict_next_step(process_name: Option<&str>, cmd_line: Option<&str>, cve_id: Option<&str>) -> Option<String> {
    let proc = process_name.unwrap_or("").to_lowercase();
    let cmd = cmd_line.unwrap_or("").to_lowercase();

    if proc.contains("vssadmin") && cmd.contains("delete shadows") {
        return Some("Volume shadow deletion often precedes credential dumping or ransomware encryption".to_string());
    }
    if proc.contains("mimikatz") || proc.contains("procdump") || proc.contains("lsass") {
        return Some("Credential dumping or LSASS access may lead to lateral movement".to_string());
    }
    if proc.contains("whoami") || proc.contains("net.exe") || cmd.contains("dir /s") {
        return Some("Discovery phase; may progress to credential access or lateral movement".to_string());
    }
    if proc.contains("wmic") || proc.contains("psexec") || proc.contains("winrm") {
        return Some("Lateral movement or remote execution likely".to_string());
    }
    if proc.contains("powershell") && (cmd.contains("invoke") || cmd.contains("download") || cmd.contains("bypass")) {
        return Some("Script execution; may download or execute additional payloads".to_string());
    }
    if cve_id.map(|c| c.contains("CVE")).unwrap_or(false) {
        return Some("Exploited CVE may enable privilege escalation or persistence".to_string());
    }
    None
}
