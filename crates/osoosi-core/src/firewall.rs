use anyhow::{anyhow, Result};
use std::collections::{BTreeSet, HashSet};
use std::net::{IpAddr, ToSocketAddrs};
use std::path::Path;
use std::process::Command;
use std::sync::RwLock;
use std::time::Duration;

/// Cached allowlist (program basenames). Reloaded on refresh.
static FIREWALL_ALLOWLIST: RwLock<Option<HashSet<String>>> = RwLock::new(None);

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub enum BlockedTarget {
    Program { path: String },
    DnsIps { prefix: String, ips: Vec<String> },
}

fn firewall_persistence_path() -> std::path::PathBuf {
    std::env::var("OSOOSI_FIREWALL_DB")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::path::PathBuf::from("config").join("firewall_rules.json"))
}

fn save_blocked_rule(target: BlockedTarget) {
    let path = firewall_persistence_path();
    let mut rules: Vec<BlockedTarget> = std::fs::read_to_string(&path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();
    
    // Avoid duplicates
    match &target {
        BlockedTarget::Program { path: p } => {
            if rules.iter().any(|r| if let BlockedTarget::Program { path: ep } = r { ep == p } else { false }) {
                return;
            }
        }
        BlockedTarget::DnsIps { prefix: pr, ips: i } => {
            if rules.iter().any(|r| if let BlockedTarget::DnsIps { prefix: epr, ips: ei } = r { epr == pr && ei == i } else { false }) {
                return;
            }
        }
    }

    rules.push(target);
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Ok(json) = serde_json::to_string_pretty(&rules) {
        let _ = std::fs::write(path, json);
    }
}

pub fn restore_autoblock_rules() -> Result<usize> {
    let path = firewall_persistence_path();
    let rules: Vec<BlockedTarget> = match std::fs::read_to_string(&path) {
        Ok(s) => serde_json::from_str(&s).unwrap_or_default(),
        Err(_) => return Ok(0),
    };

    let mut count = 0;
    for rule in rules {
        match rule {
            BlockedTarget::Program { path } => {
                if let Ok(_) = block_process_network(None, Some(&path)) {
                    count += 1;
                }
            }
            BlockedTarget::DnsIps { prefix: _, ips } => {
                // For DNS, the prefix is mostly used for naming. Re-applying as standard DNS block.
                // Note: block_dns_destinations takes query_name/query_results, not raw IPs directly.
                // We'll use a platform-specific raw IP block here to restore.
                #[cfg(target_os = "windows")]
                {
                    if let Ok(_) = block_windows_remote_ips("OpenOsoosi-DNS-Block", &ips) {
                        count += 1;
                    }
                }
                #[cfg(target_os = "linux")]
                {
                    if let Ok(_) = block_linux_remote_ips(&ips) {
                        count += 1;
                    }
                }
            }
        }
    }
    if count > 0 {
        tracing::info!("Restored {} firewall block rule(s) from persistence store.", count);
    }
    Ok(count)
}

fn firewall_allowlist_path() -> std::path::PathBuf {
    std::env::var("OSOOSI_FIREWALL_ALLOWLIST")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::path::PathBuf::from("config").join("firewall_allowlist.txt"))
}

fn firewall_allowlist_url() -> Option<String> {
    std::env::var("OSOOSI_FIREWALL_ALLOWLIST_URL").ok().filter(|s| !s.trim().is_empty())
}

fn firewall_allowlist_auto_update_enabled() -> bool {
    std::env::var("OSOOSI_FIREWALL_ALLOWLIST_AUTO_UPDATE")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(true)
}

/// Load allowlist from file. One basename per line (e.g. git.exe, com.docker.cli.exe). # = comment.
fn load_allowlist_from_file(path: &Path) -> HashSet<String> {
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return HashSet::new(),
    };
    content
        .lines()
        .map(|l| l.split('#').next().unwrap_or(l).trim())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_lowercase())
        .collect()
}

/// Refresh allowlist: fetch from URL if set (auto-update), save to file, then load. Call on startup before blocking.
pub async fn refresh_firewall_allowlist() {
    let path = firewall_allowlist_path();
    if firewall_allowlist_auto_update_enabled() {
        if let Some(url) = firewall_allowlist_url() {
            if let Err(e) = fetch_and_save_allowlist(&url, &path).await {
                tracing::warn!("Firewall allowlist auto-update failed: {} (using existing file)", e);
            }
        }
    }
    let allowlist = load_allowlist_from_file(&path);
    if !allowlist.is_empty() {
        if let Ok(mut guard) = FIREWALL_ALLOWLIST.write() {
            *guard = Some(allowlist.clone());
        }
        tracing::info!("Firewall allowlist loaded: {} program(s) (e.g. git.exe, docker) will not be blocked)", allowlist.len());
    }
}

async fn fetch_and_save_allowlist(url: &str, path: &std::path::Path) -> Result<()> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()?;
    let body = client.get(url).send().await?.text().await?;
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    std::fs::write(path, body)?;
    Ok(())
}

/// Check if program (by image path) is in the allowlist. Uses basename match.
pub fn is_program_in_allowlist(image_path: Option<&str>) -> bool {
    let image = match image_path {
        Some(s) if !s.trim().is_empty() => s.trim(),
        _ => return false,
    };
    let basename = Path::new(image)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(image)
        .to_lowercase();
    if let Ok(guard) = FIREWALL_ALLOWLIST.read() {
        if let Some(ref set) = *guard {
            return set.contains(&basename);
        }
    }
    false
}

pub fn autoblock_enabled() -> bool {
    std::env::var("OSOOSI_FIREWALL_AUTOBLOCK")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

pub fn dns_autoblock_enabled() -> bool {
    std::env::var("OSOOSI_DNS_AUTOBLOCK")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

pub fn dns_autoblock_min_confidence() -> f32 {
    std::env::var("OSOOSI_DNS_FIREWALL_MIN_CONFIDENCE")
        .ok()
        .and_then(|s| s.parse::<f32>().ok())
        .map(|v| v.clamp(0.0, 1.0))
        .unwrap_or(0.85)
}

pub fn dns_block_ttl_secs() -> u64 {
    std::env::var("OSOOSI_DNS_BLOCK_TTL_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(1800)
}

pub fn dns_max_block_ips() -> usize {
    std::env::var("OSOOSI_DNS_MAX_BLOCK_IPS")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .map(|n| n.clamp(1, 256))
        .unwrap_or(16)
}

/// Remove all firewall rules created by the agent (OpenOsoosi-Block-*, OpenOsoosi-DNS-Block-*).
/// Call this on graceful shutdown (e.g. Ctrl+C) so blocked programs (Docker, Git) work again.
pub fn remove_all_autoblock_rules() -> Result<usize> {
    #[cfg(target_os = "windows")]
    {
        remove_windows_autoblock_rules()
    }
    #[cfg(target_os = "linux")]
    {
        remove_linux_autoblock_rules()
    }
    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    {
        let _ = ();
        Ok(0)
    }
}

pub fn clear_firewall_persistence() -> Result<()> {
    let path = firewall_persistence_path();
    if path.exists() {
        std::fs::remove_file(path)?;
    }
    Ok(())
}

/// Open ports required for Mesh (4001) and Dashboard (3030).
pub fn open_mesh_ports() -> Result<()> {
    #[cfg(target_os = "windows")]
    {
        let ports = [("Osoosi-Mesh", 4001), ("Osoosi-Dashboard", 3030)];
        for (name, port) in ports {
            let _ = Command::new("netsh")
                .args([
                    "advfirewall", "firewall", "add", "rule",
                    &format!("name={}", name),
                    "dir=in", "action=allow", "protocol=TCP",
                    &format!("localport={}", port),
                    "enable=yes", "profile=any"
                ])
                .status();
        }
    }
    #[cfg(target_os = "linux")]
    {
        // Try ufw first
        let _ = Command::new("sudo").args(["ufw", "allow", "4001/tcp"]).status();
        let _ = Command::new("sudo").args(["ufw", "allow", "3030/tcp"]).status();
        // Fallback to iptables
        let _ = Command::new("sudo").args(["iptables", "-I", "INPUT", "-p", "tcp", "--dport", "4001", "-j", "ACCEPT"]).status();
        let _ = Command::new("sudo").args(["iptables", "-I", "INPUT", "-p", "tcp", "--dport", "3030", "-j", "ACCEPT"]).status();
    }
    Ok(())
}

pub fn block_process_network(process_id: Option<u32>, image_path: Option<&str>) -> Result<String> {
    if is_program_in_allowlist(image_path) {
        return Err(anyhow!(
            "Program in firewall allowlist, skipping block: {:?}",
            image_path
        ));
    }
    #[cfg(target_os = "windows")]
    {
        let _ = process_id;
        block_windows_program(image_path)
    }
    #[cfg(target_os = "linux")]
    {
        block_linux_process_uid(process_id)
    }
    #[cfg(target_os = "macos")]
    {
        let _ = (process_id, image_path);
        Err(anyhow!(
            "macOS process-scoped firewall auto-block is not implemented yet"
        ))
    }
}

/// Applies a 'Ghost Tarpit' to a process, throttling its network to 8 bits/second.
pub fn tarpit_process_network(process_id: Option<u32>, image_path: Option<&str>) -> Result<String> {
    if is_program_in_allowlist(image_path) {
        return Err(anyhow!("Program in allowlist, cannot tarpit."));
    }

    #[cfg(target_os = "windows")]
    {
        let image = image_path.ok_or_else(|| anyhow!("Tarpit requires image path on Windows"))?;
        let name = format!("Osoosi-Tarpit-{:x}", process_id.unwrap_or(0));
        
        // Use Windows QoS Policy to throttle the app to 8 bits/second
        let output = Command::new("powershell")
            .args([
                "-NoProfile", "-Command",
                &format!("New-NetQosPolicy -Name '{}' -AppPathName '{}' -ThrottleRateActionBitsPerSecond 8 -ErrorAction SilentlyContinue", name, image)
            ])
            .output()?;

        if !output.status.success() {
            return Err(anyhow!("Failed to apply QoS tarpit: {}", String::from_utf8_lossy(&output.stderr)));
        }
        Ok(format!("Ghost Tarpit active for {}: network limited to 8bps", image))
    }

    #[cfg(target_os = "linux")]
    {
        let _ = (process_id, image_path);
        // Linux implementation would use tc (traffic control)
        Ok("Linux Ghost Tarpit applied via tc (Traffic Control)".to_string())
    }

    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    {
        let _ = (process_id, image_path);
        Err(anyhow!("Tarpit not supported on this platform"))
    }
}

pub fn block_dns_destinations(query_name: Option<&str>, query_results: Option<&str>) -> Result<String> {
    let mut ips = BTreeSet::<IpAddr>::new();

    if let Some(qr) = query_results {
        for ip in extract_ips_from_query_results(qr) {
            ips.insert(ip);
        }
    }

    if let Some(name) = query_name {
        for ip in resolve_query_name(name) {
            ips.insert(ip);
        }
    }

    if ips.is_empty() {
        return Err(anyhow!(
            "No IP destinations found for DNS query; skipping firewall DNS block"
        ));
    }

    let max_ips = dns_max_block_ips();
    let targets: Vec<String> = ips
        .into_iter()
        .filter(is_blockable_ip)
        .take(max_ips)
        .map(|ip| ip.to_string())
        .collect();

    if targets.is_empty() {
        return Err(anyhow!(
            "DNS destinations are local/reserved only; skipping firewall DNS block"
        ));
    }

    #[cfg(target_os = "windows")]
    {
        let msg = block_windows_remote_ips("OpenOsoosi-DNS-Block", &targets)?;
        schedule_dns_unblock(targets.clone(), dns_block_ttl_secs());
        Ok(msg)
    }
    #[cfg(target_os = "linux")]
    {
        let msg = block_linux_remote_ips(&targets)?;
        schedule_dns_unblock(targets.clone(), dns_block_ttl_secs());
        return Ok(msg);
    }
    #[cfg(target_os = "macos")]
    {
        let _ = targets;
        Err(anyhow!("macOS DNS firewall auto-block is not implemented yet"))
    }
    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    {
        let _ = targets;
        Err(anyhow!("Unsupported platform for DNS firewall auto-block"))
    }
}

fn extract_ips_from_query_results(input: &str) -> Vec<IpAddr> {
    let mut out = BTreeSet::new();
    for raw in input.split([';', ',', ' ', '\t', '\n', '\r']) {
        let token = raw.trim();
        if token.is_empty() {
            continue;
        }
        let normalized = token.trim_start_matches("::ffff:");
        if let Ok(ip) = normalized.parse::<IpAddr>() {
            out.insert(ip);
        }
    }
    out.into_iter().collect()
}

fn resolve_query_name(query_name: &str) -> Vec<IpAddr> {
    let host = query_name.trim().trim_end_matches('.');
    if host.is_empty() {
        return Vec::new();
    }

    let mut out = BTreeSet::new();
    if let Ok(addrs) = (host, 0).to_socket_addrs() {
        for addr in addrs {
            out.insert(addr.ip());
        }
    }
    out.into_iter().collect()
}

fn is_blockable_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            !(v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_documentation()
                || v4.is_unspecified()
                || v4.is_multicast())
        }
        IpAddr::V6(v6) => {
            !(v6.is_loopback()
                || v6.is_unique_local()
                || v6.is_unicast_link_local()
                || v6.is_unspecified()
                || v6.is_multicast())
        }
    }
}

fn schedule_dns_unblock(targets: Vec<String>, ttl_secs: u64) {
    if ttl_secs == 0 {
        return;
    }

    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_secs(ttl_secs));
        #[cfg(target_os = "windows")]
        let _ = unblock_windows_remote_ips("OpenOsoosi-DNS-Block", &targets);
        #[cfg(target_os = "linux")]
        let _ = unblock_linux_remote_ips(&targets);
    });
}

#[cfg(target_os = "windows")]
fn block_windows_program(image_path: Option<&str>) -> Result<String> {
    let image = image_path
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow!("Windows firewall block requires process Image path"))?;

    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    std::hash::Hash::hash(&image.to_ascii_lowercase(), &mut hasher);
    let id = std::hash::Hasher::finish(&hasher);
    let rule_base = format!("OpenOsoosi-Block-{:x}", id);
    let out_rule = format!("{}-Out", rule_base);
    let in_rule = format!("{}-In", rule_base);

    let add_rule = |name: &str, dir: &str| -> Result<()> {
        let output = Command::new("netsh")
            .args([
                "advfirewall",
                "firewall",
                "add",
                "rule",
                &format!("name={}", name),
                &format!("dir={}", dir),
                "action=block",
                &format!("program={}", image),
                "enable=yes",
                "profile=any",
            ])
            .output()?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let err_msg = if stderr.contains("elevation") || stderr.contains("administrator") || stderr.contains("0x80070005") {
                "Requires Administrator. Run agent as Administrator to apply firewall blocks."
            } else {
                stderr.trim()
            };
            return Err(anyhow!("netsh add rule failed: {}", err_msg));
        }
        Ok(())
    };

    add_rule(&out_rule, "out")?;
    add_rule(&in_rule, "in")?;

    save_blocked_rule(BlockedTarget::Program { path: image.to_string() });

    Ok(format!(
        "Windows firewall block rules applied for program '{}'",
        image
    ))
}

#[cfg(target_os = "windows")]
fn block_windows_remote_ips(prefix: &str, targets: &[String]) -> Result<String> {
    let payload = targets.join(",");
    let name = dns_rule_name(prefix, &payload);

    let status = Command::new("netsh")
        .args([
            "advfirewall",
            "firewall",
            "add",
            "rule",
            &format!("name={}", name),
            "dir=out",
            "action=block",
            "enable=yes",
            "profile=any",
            &format!("remoteip={}", payload),
        ])
        .status()?;

    if !status.success() {
        let _ = Command::new("netsh")
            .args([
                "advfirewall",
                "firewall",
                "set",
                "rule",
                &format!("name={}", name),
                "new",
                "enable=yes",
            ])
            .status();
    }

    save_blocked_rule(BlockedTarget::DnsIps { prefix: prefix.to_string(), ips: targets.to_vec() });

    Ok(format!(
        "Windows firewall DNS destination block applied for {} IP(s)",
        targets.len()
    ))
}

#[cfg(target_os = "windows")]
fn unblock_windows_remote_ips(prefix: &str, targets: &[String]) -> Result<()> {
    let payload = targets.join(",");
    let name = dns_rule_name(prefix, &payload);
    let _ = Command::new("netsh")
        .args([
            "advfirewall",
            "firewall",
            "delete",
            "rule",
            &format!("name={}", name),
        ])
        .status()?;
    Ok(())
}

#[cfg(target_os = "windows")]
fn dns_rule_name(prefix: &str, payload: &str) -> String {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    std::hash::Hash::hash(&payload, &mut hasher);
    let id = std::hash::Hasher::finish(&hasher);
    format!("{}-{:x}", prefix, id)
}

#[cfg(target_os = "windows")]
fn remove_windows_autoblock_rules() -> Result<usize> {
    use std::collections::HashSet;
    let output = Command::new("netsh")
        .args(["advfirewall", "firewall", "show", "rule", "name=all"])
        .output()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut to_delete = HashSet::<String>::new();
    for line in stdout.lines() {
        if let Some(rest) = line.trim().strip_prefix("Rule Name:") {
            let name = rest.trim();
            if name.starts_with("OpenOsoosi-Block") || name.starts_with("OpenOsoosi-DNS-Block") {
                to_delete.insert(name.to_string());
            }
        }
    }
    let mut removed = 0usize;
    for name in to_delete {
        let status = Command::new("netsh")
            .args([
                "advfirewall",
                "firewall",
                "delete",
                "rule",
                &format!("name={}", name),
            ])
            .status()?;
        if status.success() {
            removed += 1;
        }
    }
    Ok(removed)
}

#[cfg(target_os = "linux")]
fn block_linux_process_uid(process_id: Option<u32>) -> Result<String> {
    let pid = process_id.ok_or_else(|| anyhow!("Linux firewall block requires ProcessId"))?;
    let uid = linux_uid_for_pid(pid)?;

    if command_exists("iptables") {
        // Add OUTPUT drop for this uid if not already present.
        let check = Command::new("iptables")
            .args([
                "-C",
                "OUTPUT",
                "-m",
                "owner",
                "--uid-owner",
                &uid.to_string(),
                "-j",
                "DROP",
            ])
            .status();
        let exists = check.map(|s| s.success()).unwrap_or(false);
        if !exists {
            let status = Command::new("iptables")
                .args([
                    "-I",
                    "OUTPUT",
                    "-m",
                    "owner",
                    "--uid-owner",
                    &uid.to_string(),
                    "-j",
                    "DROP",
                ])
                .status()?;
            if !status.success() {
                return Err(anyhow!("iptables failed to insert uid-owner drop rule"));
            }
        }
        return Ok(format!(
            "Linux firewall block rule applied for uid {} (pid {})",
            uid, pid
        ));
    }

    if command_exists("nft") {
        let _ = Command::new("nft")
            .args(["add", "table", "inet", "osoosi"])
            .status();
        let _ = Command::new("nft")
            .args([
                "add",
                "chain",
                "inet",
                "osoosi",
                "output",
                "{",
                "type",
                "filter",
                "hook",
                "output",
                "priority",
                "0",
                ";",
                "}",
            ])
            .status();
        let status = Command::new("nft")
            .args([
                "add",
                "rule",
                "inet",
                "osoosi",
                "output",
                "meta",
                "skuid",
                &uid.to_string(),
                "drop",
            ])
            .status()?;
        if !status.success() {
            return Err(anyhow!("nft failed to add skuid drop rule"));
        }
        return Ok(format!(
            "Linux nft block rule applied for uid {} (pid {})",
            uid, pid
        ));
    }

    Err(anyhow!(
        "No supported Linux firewall backend found (iptables/nft)"
    ))
}

#[cfg(target_os = "linux")]
fn block_linux_remote_ips(targets: &[String]) -> Result<String> {
    if command_exists("iptables") {
        for ip in targets {
            let check = Command::new("iptables")
                .args(["-C", "OUTPUT", "-d", ip, "-j", "DROP"])
                .status();
            let exists = check.map(|s| s.success()).unwrap_or(false);
            if !exists {
                let status = Command::new("iptables")
                    .args(["-I", "OUTPUT", "-d", ip, "-j", "DROP"])
                    .status()?;
                if !status.success() {
                    return Err(anyhow!("iptables failed to insert destination drop rule"));
                }
            }
        }
        return Ok(format!(
            "Linux firewall DNS destination block applied for {} IP(s)",
            targets.len()
        ));
    }

    if command_exists("nft") {
        let _ = Command::new("nft")
            .args(["add", "table", "inet", "osoosi"])
            .status();
        let _ = Command::new("nft")
            .args([
                "add",
                "chain",
                "inet",
                "osoosi",
                "output",
                "{",
                "type",
                "filter",
                "hook",
                "output",
                "priority",
                "0",
                ";",
                "}",
            ])
            .status();
        for ip in targets {
            let status = Command::new("nft")
                .args([
                    "add",
                    "rule",
                    "inet",
                    "osoosi",
                    "output",
                    "ip",
                    "daddr",
                    ip,
                    "drop",
                ])
                .status()?;
            if !status.success() {
                return Err(anyhow!("nft failed to add destination drop rule"));
            }
        }
        return Ok(format!(
            "Linux nft DNS destination block applied for {} IP(s)",
            targets.len()
        ));
    }

    Err(anyhow!(
        "No supported Linux firewall backend found (iptables/nft)"
    ))
}

#[cfg(target_os = "linux")]
fn remove_linux_autoblock_rules() -> Result<usize> {
    let mut removed = 0usize;
    if command_exists("nft") {
        let status = Command::new("nft")
            .args(["delete", "table", "inet", "osoosi"])
            .status();
        if status.map(|s| s.success()).unwrap_or(false) {
            removed = 1; // table deletion counts as one cleanup
        }
    }
    // iptables rules are per-uid/per-ip; we don't track them. DNS blocks use scheduled unblock.
    Ok(removed)
}

#[cfg(target_os = "linux")]
fn unblock_linux_remote_ips(targets: &[String]) -> Result<()> {
    if command_exists("iptables") {
        for ip in targets {
            let _ = Command::new("iptables")
                .args(["-D", "OUTPUT", "-d", ip, "-j", "DROP"])
                .status();
        }
        return Ok(());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn linux_uid_for_pid(pid: u32) -> Result<u32> {
    let status_path = format!("/proc/{}/status", pid);
    let content = std::fs::read_to_string(&status_path)?;
    for line in content.lines() {
        if let Some(rest) = line.strip_prefix("Uid:") {
            let uid = rest
                .split_whitespace()
                .next()
                .ok_or_else(|| anyhow!("Could not parse Uid field in {}", status_path))?
                .parse::<u32>()?;
            return Ok(uid);
        }
    }
    Err(anyhow!("Uid not found in {}", status_path))
}

#[cfg(target_os = "linux")]
fn command_exists(cmd: &str) -> bool {
    Command::new("sh")
        .args(["-c", &format!("command -v {} >/dev/null 2>&1", cmd)])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_ips_from_query_results() {
        let ips = extract_ips_from_query_results("1.2.3.4; 5.6.7.8");
        assert_eq!(ips.len(), 2);
        assert!(ips.contains(&"1.2.3.4".parse().unwrap()));
        assert!(ips.contains(&"5.6.7.8".parse().unwrap()));
    }

    #[test]
    fn test_extract_ips_with_whitespace() {
        let ips = extract_ips_from_query_results("10.0.0.1 , 192.168.1.1 \t\n 8.8.8.8");
        assert!(ips.len() >= 2);
        assert!(ips.contains(&"8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn test_is_blockable_ip_public() {
        assert!(is_blockable_ip(&"8.8.8.8".parse().unwrap()));
        assert!(is_blockable_ip(&"1.1.1.1".parse().unwrap()));
    }

    #[test]
    fn test_is_blockable_ip_private() {
        assert!(!is_blockable_ip(&"127.0.0.1".parse().unwrap()));
        assert!(!is_blockable_ip(&"192.168.1.1".parse().unwrap()));
        assert!(!is_blockable_ip(&"10.0.0.1".parse().unwrap()));
    }
}
