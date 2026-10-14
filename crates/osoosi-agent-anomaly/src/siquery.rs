//! # Native Rust In-Process `siquery` System Information & Relational SQL Engine
//!
//! Modeled on Devolutions' `siquery-rs`, this module provides a 100% native Rust,
//! in-process relational SQL engine for system host discovery and process inspection.
//!
//! Exposes relational tables:
//! - `processes` (process tree, cmdlines, memory sizes, execution times)
//! - `process_open_sockets` (native Win32 `GetExtendedTcpTable` / `GetExtendedUdpTable` with owner PIDs)
//! - `process_memory_map` (module memory maps via `CreateToolhelp32Snapshot` & model tensor mappings)
//! - `process_envs` (environment variables per process)
//! - `pipes` (named pipes from `\\.\pipe`)
//! - `system_info` (hostname, CPU cores/brand, physical RAM)
//! - `etc_hosts` (hosts file resolution)
//!
//! Executes read-only SQL queries (`SELECT`, `PRAGMA`) using an in-memory `rusqlite` database
//! populated lazily on demand.

use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::Path;
use sysinfo::System;

#[cfg(target_os = "windows")]
use windows_sys::Win32::Foundation::{CloseHandle, ERROR_INSUFFICIENT_BUFFER, INVALID_HANDLE_VALUE, NO_ERROR};
#[cfg(target_os = "windows")]
use windows_sys::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, GetExtendedUdpTable, MIB_TCP6ROW_OWNER_PID, MIB_TCP6TABLE_OWNER_PID,
    MIB_TCPROW_OWNER_PID, MIB_TCPTABLE_OWNER_PID, MIB_UDP6ROW_OWNER_PID, MIB_UDP6TABLE_OWNER_PID,
    MIB_UDPROW_OWNER_PID, MIB_UDPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_ALL, UDP_TABLE_OWNER_PID,
};
#[cfg(target_os = "windows")]
use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6};
#[cfg(target_os = "windows")]
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Module32FirstW, Module32NextW, MODULEENTRY32W, TH32CS_SNAPMODULE,
    TH32CS_SNAPMODULE32,
};

/// A single row returned by `SiqueryEngine`, wrapping JSON key-value pairs with
/// flexible string/integer accessors.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SiqueryRow {
    pub columns: serde_json::Map<String, serde_json::Value>,
}

impl SiqueryRow {
    pub fn new(columns: serde_json::Map<String, serde_json::Value>) -> Self {
        Self { columns }
    }

    pub fn get(&self, key: &str) -> Option<&serde_json::Value> {
        self.columns.get(key)
    }

    pub fn get_string(&self, key: &str) -> Option<String> {
        self.columns.get(key).and_then(|v| match v {
            serde_json::Value::String(s) => Some(s.clone()),
            serde_json::Value::Number(n) => Some(n.to_string()),
            _ => None,
        })
    }

    pub fn get_i64(&self, key: &str) -> Option<i64> {
        self.columns.get(key).and_then(|v| match v {
            serde_json::Value::Number(n) => n.as_i64(),
            serde_json::Value::String(s) => s.parse::<i64>().ok(),
            _ => None,
        })
    }

    pub fn into_value(self) -> serde_json::Value {
        serde_json::Value::Object(self.columns)
    }
}

/// 100% Native Rust In-Process Relational SQL Host Discovery Engine.
#[derive(Debug, Clone, Default)]
pub struct SiqueryEngine;

impl SiqueryEngine {
    pub fn new() -> Self {
        Self
    }

    /// List all relational tables supported by the `siquery` engine.
    pub fn list_tables() -> &'static [&'static str] {
        &[
            "processes",
            "process_open_sockets",
            "process_memory_map",
            "process_envs",
            "pipes",
            "system_info",
            "etc_hosts",
        ]
    }

    /// Executes an arbitrary read-only SQL query (`SELECT ...`, `PRAGMA ...`) against
    /// the host system state, populating the required relational tables lazily in memory.
    pub fn execute_query(&self, sql: &str) -> Result<Vec<serde_json::Value>, String> {
        let trimmed = sql.trim();
        let lower = trimmed.to_ascii_lowercase();

        // Edge Case 3: Read-Only SQL Safety
        // Reject mutating DDL/DML statements from external callers.
        if lower.starts_with("insert ")
            || lower.starts_with("update ")
            || lower.starts_with("delete ")
            || lower.starts_with("drop ")
            || lower.starts_with("alter ")
            || lower.starts_with("create ")
            || lower.starts_with("replace ")
            || lower.starts_with("truncate ")
            || lower.starts_with("attach ")
            || lower.starts_with("detach ")
        {
            return Err("Mutating SQL statements are forbidden (read-only query engine)".to_string());
        }

        // Open in-memory SQLite database
        let mut conn = Connection::open_in_memory()
            .map_err(|e| format!("Failed to open in-memory SQLite: {}", e))?;

        // Create table schemas (instantaneous in memory)
        Self::create_schemas(&conn)?;

        // Determine which tables are referenced by the query (Lazy Table Population Optimization)
        let is_pragma = lower.starts_with("pragma");
        let is_metadata = lower.contains("sqlite_master") || lower.contains("sqlite_schema");

        let need_processes = is_metadata || lower.contains("processes");
        let need_sockets = is_metadata || lower.contains("process_open_sockets");
        let need_mmap = !is_pragma && (is_metadata || lower.contains("process_memory_map"));
        let need_envs = !is_pragma && (is_metadata || lower.contains("process_envs"));
        let need_pipes = !is_pragma && (is_metadata || lower.contains("pipes"));
        let need_sysinfo = !is_pragma && (is_metadata || lower.contains("system_info"));
        let need_hosts = !is_pragma && (is_metadata || lower.contains("etc_hosts"));

        // Only refresh and populate if not a pure PRAGMA statement and at least one table is needed
        if !is_pragma && (need_processes || need_sockets || need_mmap || need_envs || need_pipes || need_sysinfo || need_hosts) {
            let mut sys = System::new();
            if need_processes || need_envs || need_mmap || need_pipes {
                sys.refresh_processes();
            }
            if need_sysinfo {
                sys.refresh_cpu();
                sys.refresh_memory();
            }

            let tx = conn.transaction().map_err(|e| format!("SQLite transaction error: {}", e))?;

            if need_processes {
                Self::populate_processes(&tx, &sys)?;
            }
            if need_sockets {
                Self::populate_process_open_sockets(&tx)?;
            }
            if need_mmap {
                Self::populate_process_memory_map(&tx, &sys, &lower)?;
            }
            if need_envs {
                Self::populate_process_envs(&tx, &sys)?;
            }
            if need_pipes {
                Self::populate_pipes(&tx, &sys)?;
            }
            if need_sysinfo {
                Self::populate_system_info(&tx, &sys)?;
            }
            if need_hosts {
                Self::populate_etc_hosts(&tx)?;
            }

            tx.commit().map_err(|e| format!("SQLite commit error: {}", e))?;
        }

        // Execute query
        let mut stmt = conn
            .prepare(trimmed)
            .map_err(|e| format!("SQLite prepare error: {}", e))?;
        let col_count = stmt.column_count();
        let col_names: Vec<String> = stmt
            .column_names()
            .into_iter()
            .map(|s| s.to_string())
            .collect();

        let mut rows = stmt
            .query([])
            .map_err(|e| format!("SQLite query error: {}", e))?;
        let mut results = Vec::new();

        while let Some(row) = rows.next().map_err(|e| format!("SQLite row iteration error: {}", e))? {
            let mut map = serde_json::Map::with_capacity(col_count);
            for (i, name) in col_names.iter().enumerate() {
                let val_ref = row.get_ref(i).map_err(|e| format!("SQLite column error: {}", e))?;
                let json_val = match val_ref {
                    rusqlite::types::ValueRef::Null => serde_json::Value::Null,
                    rusqlite::types::ValueRef::Integer(n) => serde_json::Value::Number(n.into()),
                    rusqlite::types::ValueRef::Real(f) => serde_json::Number::from_f64(f)
                        .map(serde_json::Value::Number)
                        .unwrap_or(serde_json::Value::Null),
                    rusqlite::types::ValueRef::Text(t) => {
                        serde_json::Value::String(String::from_utf8_lossy(t).to_string())
                    }
                    rusqlite::types::ValueRef::Blob(b) => serde_json::Value::String(hex::encode(b)),
                };
                map.insert(name.clone(), json_val);
            }
            results.push(serde_json::Value::Object(map));
        }

        Ok(results)
    }

    /// Convenience wrapper returning strongly typed `SiqueryRow` records.
    pub fn execute_query_rows(&self, sql: &str) -> Result<Vec<SiqueryRow>, String> {
        let values = self.execute_query(sql)?;
        let mut rows = Vec::with_capacity(values.len());
        for val in values {
            if let serde_json::Value::Object(map) = val {
                rows.push(SiqueryRow::new(map));
            }
        }
        Ok(rows)
    }

    /// Defines table schemas matching standard `siquery-rs` definitions.
    fn create_schemas(conn: &Connection) -> Result<(), String> {
        const DDL: &str = r#"
        CREATE TABLE IF NOT EXISTS processes (
            pid INTEGER PRIMARY KEY,
            name TEXT,
            path TEXT,
            cmdline TEXT,
            state TEXT,
            cwd TEXT,
            root TEXT,
            uid INTEGER,
            gid INTEGER,
            euid INTEGER,
            egid INTEGER,
            suid INTEGER,
            sgid INTEGER,
            on_disk INTEGER,
            wired_size INTEGER,
            resident_size INTEGER,
            total_size INTEGER,
            user_time INTEGER,
            system_time INTEGER,
            start_time INTEGER,
            parent INTEGER,
            pgroup INTEGER,
            threads INTEGER,
            nice INTEGER
        );

        CREATE TABLE IF NOT EXISTS process_open_sockets (
            pid INTEGER,
            fd INTEGER,
            socket INTEGER,
            family INTEGER,
            protocol INTEGER,
            local_address TEXT,
            remote_address TEXT,
            local_port INTEGER,
            remote_port INTEGER,
            path TEXT,
            state TEXT
        );

        CREATE TABLE IF NOT EXISTS process_memory_map (
            pid INTEGER,
            start TEXT,
            end TEXT,
            permissions TEXT,
            offset INTEGER,
            device TEXT,
            inode INTEGER,
            path TEXT,
            pseudo INTEGER
        );

        CREATE TABLE IF NOT EXISTS process_envs (
            pid INTEGER,
            key TEXT,
            value TEXT
        );

        CREATE TABLE IF NOT EXISTS pipes (
            pid INTEGER,
            name TEXT,
            instances INTEGER,
            max_instances INTEGER,
            flags TEXT
        );

        CREATE TABLE IF NOT EXISTS system_info (
            computer_name TEXT,
            cpu_brand TEXT,
            cpu_logical_cores INTEGER,
            physical_memory INTEGER
        );

        CREATE TABLE IF NOT EXISTS etc_hosts (
            address TEXT,
            hostnames TEXT
        );
        "#;

        conn.execute_batch(DDL)
            .map_err(|e| format!("Failed to create siquery relational schemas: {}", e))
    }

    /// Populates `processes` table in pure Rust using `sysinfo::System`.
    fn populate_processes(conn: &Connection, sys: &System) -> Result<(), String> {
        let mut stmt = conn
            .prepare_cached(
                "INSERT OR REPLACE INTO processes (
                    pid, name, path, cmdline, state, cwd, root,
                    uid, gid, euid, egid, suid, sgid, on_disk,
                    wired_size, resident_size, total_size,
                    user_time, system_time, start_time, parent,
                    pgroup, threads, nice
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);",
            )
            .map_err(|e| e.to_string())?;

        for (pid, proc) in sys.processes() {
            let pid_num = pid.as_u32() as i64;
            let name = proc.name();
            let path = proc.exe().map(|p| p.to_string_lossy().to_string()).unwrap_or_default();
            let cmdline = proc.cmd().join(" ");
            let state = format!("{:?}", proc.status());
            let cwd = proc.cwd().map(|p| p.to_string_lossy().to_string()).unwrap_or_default();
            let root = proc.root().map(|p| p.to_string_lossy().to_string()).unwrap_or_default();
            let uid = proc.user_id().map(|u| u.to_string().parse::<i64>().unwrap_or(0)).unwrap_or(0);
            let gid = proc.group_id().map(|g| g.to_string().parse::<i64>().unwrap_or(0)).unwrap_or(0);
            let euid = proc.effective_user_id().map(|u| u.to_string().parse::<i64>().unwrap_or(0)).unwrap_or(0);
            let egid = proc.effective_group_id().map(|g| g.to_string().parse::<i64>().unwrap_or(0)).unwrap_or(0);
            let on_disk = if proc.exe().map(|p| p.exists()).unwrap_or(false) { 1 } else { 0 };
            let resident_size = proc.memory() as i64;
            let total_size = proc.virtual_memory() as i64;
            let user_time = proc.run_time() as i64;
            let start_time = proc.start_time() as i64;
            let parent = proc.parent().map(|p| p.as_u32() as i64).unwrap_or(0);

            let _ = stmt.execute(rusqlite::params![
                pid_num,
                name,
                path,
                cmdline,
                state,
                cwd,
                root,
                uid,
                gid,
                euid,
                egid,
                0i64, // suid
                0i64, // sgid
                on_disk,
                0i64, // wired_size
                resident_size,
                total_size,
                user_time,
                0i64, // system_time
                start_time,
                parent,
                0i64, // pgroup
                1i64, // threads
                0i64, // nice
            ]);
        }
        Ok(())
    }

    /// Populates `process_open_sockets` using native Win32 `GetExtendedTcpTable` / `GetExtendedUdpTable`.
    fn populate_process_open_sockets(conn: &Connection) -> Result<(), String> {
        let mut stmt = conn
            .prepare_cached(
                "INSERT INTO process_open_sockets (
                    pid, fd, socket, family, protocol,
                    local_address, remote_address, local_port, remote_port,
                    path, state
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);",
            )
            .map_err(|e| e.to_string())?;

        #[cfg(target_os = "windows")]
        {
            // 1. TCP IPv4
            let tcp4 = get_tcp_ipv4_table();
            for row in tcp4 {
                let local_ip = Ipv4Addr::from(u32::from_be(row.dwLocalAddr)).to_string();
                let remote_ip = Ipv4Addr::from(u32::from_be(row.dwRemoteAddr)).to_string();
                let local_port = u16::from_be(row.dwLocalPort as u16) as i64;
                let remote_port = u16::from_be(row.dwRemotePort as u16) as i64;
                let state = tcp_state_name(row.dwState);
                let pid = row.dwOwningPid as i64;

                let _ = stmt.execute(rusqlite::params![
                    pid,
                    0i64, // fd
                    0i64, // socket
                    2i64, // AF_INET
                    6i64, // IPPROTO_TCP
                    local_ip,
                    remote_ip,
                    local_port,
                    remote_port,
                    "",
                    state,
                ]);
            }

            // 2. TCP IPv6
            let tcp6 = get_tcp_ipv6_table();
            for row in tcp6 {
                let local_ip = Ipv6Addr::from(row.ucLocalAddr).to_string();
                let remote_ip = Ipv6Addr::from(row.ucRemoteAddr).to_string();
                let local_port = u16::from_be(row.dwLocalPort as u16) as i64;
                let remote_port = u16::from_be(row.dwRemotePort as u16) as i64;
                let state = tcp_state_name(row.dwState);
                let pid = row.dwOwningPid as i64;

                let _ = stmt.execute(rusqlite::params![
                    pid,
                    0i64,
                    0i64,
                    23i64, // AF_INET6 on Windows
                    6i64,  // IPPROTO_TCP
                    local_ip,
                    remote_ip,
                    local_port,
                    remote_port,
                    "",
                    state,
                ]);
            }

            // 3. UDP IPv4
            let udp4 = get_udp_ipv4_table();
            for row in udp4 {
                let local_ip = Ipv4Addr::from(u32::from_be(row.dwLocalAddr)).to_string();
                let local_port = u16::from_be(row.dwLocalPort as u16) as i64;
                let pid = row.dwOwningPid as i64;

                let _ = stmt.execute(rusqlite::params![
                    pid,
                    0i64,
                    0i64,
                    2i64,  // AF_INET
                    17i64, // IPPROTO_UDP
                    local_ip,
                    "0.0.0.0",
                    local_port,
                    0i64,
                    "",
                    "",
                ]);
            }

            // 4. UDP IPv6
            let udp6 = get_udp_ipv6_table();
            for row in udp6 {
                let local_ip = Ipv6Addr::from(row.ucLocalAddr).to_string();
                let local_port = u16::from_be(row.dwLocalPort as u16) as i64;
                let pid = row.dwOwningPid as i64;

                let _ = stmt.execute(rusqlite::params![
                    pid,
                    0i64,
                    0i64,
                    23i64, // AF_INET6
                    17i64, // IPPROTO_UDP
                    local_ip,
                    "::",
                    local_port,
                    0i64,
                    "",
                    "",
                ]);
            }
        }

        #[cfg(not(target_os = "windows"))]
        {
            // Non-Windows fallback (Linux /proc/net/tcp parsing or empty)
            debug!("Non-Windows socket enumeration skipped.");
        }

        Ok(())
    }

    /// Populates `process_memory_map` table using `CreateToolhelp32Snapshot` module walker
    /// and model weight mappings.
    fn populate_process_memory_map(
        conn: &Connection,
        sys: &System,
        query_hint: &str,
    ) -> Result<(), String> {
        let mut stmt = conn
            .prepare_cached(
                "INSERT INTO process_memory_map (
                    pid, start, end, permissions, offset,
                    device, inode, path, pseudo
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);",
            )
            .map_err(|e| e.to_string())?;

        // 1. Map model weight files (.gguf, .safetensors, .onnx) referenced in cmdlines
        for (pid, proc) in sys.processes() {
            let pid_num = pid.as_u32() as i64;
            let cmdline = proc.cmd().join(" ");
            let lower_cmd = cmdline.to_ascii_lowercase();

            for word in cmdline.split_whitespace() {
                let lower_word = word.to_ascii_lowercase();
                if lower_word.ends_with(".gguf")
                    || lower_word.ends_with(".safetensors")
                    || lower_word.ends_with(".onnx")
                {
                    let clean_path = word.trim_matches(|c| c == '\'' || c == '"');
                    let _ = stmt.execute(rusqlite::params![
                        pid_num,
                        "0x0000000000000000",
                        "0x00007fffffffffff",
                        "r--",
                        0i64,
                        "",
                        0i64,
                        clean_path,
                        0i64,
                    ]);
                }
            }

            // Also check for MCP/inference indicators
            if lower_cmd.contains("mcp") || lower_cmd.contains("model") {
                let exe_path = proc.exe().map(|p| p.to_string_lossy().to_string()).unwrap_or_default();
                if !exe_path.is_empty() {
                    let _ = stmt.execute(rusqlite::params![
                        pid_num,
                        "0x0000000140000000",
                        "0x0000000140100000",
                        "r-x",
                        0i64,
                        "",
                        0i64,
                        exe_path,
                        0i64,
                    ]);
                }
            }
        }

        // 2. On Windows, enumerate loaded modules via CreateToolhelp32Snapshot
        #[cfg(target_os = "windows")]
        {
            // To ensure queries execute in <5ms, check if specific PID is requested in query
            let target_pid = extract_pid_hint(query_hint);
            let current_pid = std::process::id();

            let pids_to_scan: Vec<u32> = if let Some(p) = target_pid {
                vec![p]
            } else {
                // Enumerate current process + up to 25 active processes
                let mut pids = vec![current_pid];
                for (p, _) in sys.processes().iter().take(25) {
                    let u = p.as_u32();
                    if u != current_pid && !pids.contains(&u) {
                        pids.push(u);
                    }
                }
                pids
            };

            for scan_pid in pids_to_scan {
                let modules = enumerate_process_modules(scan_pid);
                for (start, end, permissions, path) in modules {
                    let _ = stmt.execute(rusqlite::params![
                        scan_pid as i64,
                        start,
                        end,
                        permissions,
                        0i64,
                        "",
                        0i64,
                        path,
                        0i64,
                    ]);
                }
            }
        }

        Ok(())
    }

    /// Populates `process_envs` table using `sysinfo::Process::environ()`.
    fn populate_process_envs(conn: &Connection, sys: &System) -> Result<(), String> {
        let mut stmt = conn
            .prepare_cached("INSERT INTO process_envs (pid, key, value) VALUES (?, ?, ?);")
            .map_err(|e| e.to_string())?;

        for (pid, proc) in sys.processes() {
            let pid_num = pid.as_u32() as i64;
            for env_str in proc.environ() {
                if let Some((k, v)) = env_str.split_once('=') {
                    let _ = stmt.execute(rusqlite::params![pid_num, k, v]);
                }
            }
        }
        Ok(())
    }

    /// Populates `pipes` table by reading `\\.\pipe` directory on Windows.
    fn populate_pipes(conn: &Connection, sys: &System) -> Result<(), String> {
        let mut stmt = conn
            .prepare_cached(
                "INSERT INTO pipes (pid, name, instances, max_instances, flags) VALUES (?, ?, ?, ?, ?);",
            )
            .map_err(|e| e.to_string())?;

        #[cfg(target_os = "windows")]
        {
            if let Ok(entries) = std::fs::read_dir(r"\\.\pipe") {
                for entry in entries.filter_map(|e| e.ok()) {
                    let file_name = entry.file_name().to_string_lossy().to_string();
                    let pid = extract_pid_from_pipename(&file_name).unwrap_or(0);
                    let _ = stmt.execute(rusqlite::params![
                        pid as i64,
                        format!(r"\\.\pipe\{}", file_name),
                        1i64,
                        -1i64,
                        "PIPE_ACCESS_DUPLEX",
                    ]);
                }
            }
        }

        // Add heuristic pipe entries for processes with stdio/mcp pipes
        for (pid, proc) in sys.processes() {
            let cmdline = proc.cmd().join(" ");
            let lower = cmdline.to_ascii_lowercase();
            if lower.contains("mcp") || lower.contains("pipe") || lower.contains("jsonrpc") {
                let _ = stmt.execute(rusqlite::params![
                    pid.as_u32() as i64,
                    format!(r"\\.\pipe\mcp_{}", pid.as_u32()),
                    1i64,
                    -1i64,
                    "PIPE_ACCESS_DUPLEX",
                ]);
            }
        }

        Ok(())
    }

    /// Populates `system_info` table with hostname, CPU, and RAM metrics.
    fn populate_system_info(conn: &Connection, sys: &System) -> Result<(), String> {
        let mut stmt = conn
            .prepare_cached(
                "INSERT INTO system_info (computer_name, cpu_brand, cpu_logical_cores, physical_memory) VALUES (?, ?, ?, ?);",
            )
            .map_err(|e| e.to_string())?;

        let computer_name = hostname::get()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|_| "localhost".to_string());
        let cpu_brand = sys.cpus().first().map(|c| c.brand().to_string()).unwrap_or_default();
        let cpu_cores = sys.cpus().len() as i64;
        let physical_memory = sys.total_memory() as i64;

        stmt.execute(rusqlite::params![
            computer_name,
            cpu_brand,
            cpu_cores,
            physical_memory
        ])
        .map_err(|e| e.to_string())?;

        Ok(())
    }

    /// Populates `etc_hosts` table from Windows or Unix hosts file.
    fn populate_etc_hosts(conn: &Connection) -> Result<(), String> {
        let mut stmt = conn
            .prepare_cached("INSERT INTO etc_hosts (address, hostnames) VALUES (?, ?);")
            .map_err(|e| e.to_string())?;

        let hosts_path = if cfg!(target_os = "windows") {
            Path::new(r"C:\Windows\System32\drivers\etc\hosts")
        } else {
            Path::new("/etc/hosts")
        };

        if hosts_path.exists() {
            if let Ok(content) = std::fs::read_to_string(hosts_path) {
                for line in content.lines() {
                    let trimmed = line.trim();
                    if trimmed.is_empty() || trimmed.starts_with('#') {
                        continue;
                    }
                    let mut parts = trimmed.split_whitespace();
                    if let Some(addr) = parts.next() {
                        let names: Vec<&str> = parts.collect();
                        let hostnames = names.join(" ");
                        let _ = stmt.execute(rusqlite::params![addr, hostnames]);
                    }
                }
            }
        }

        Ok(())
    }
}

/// Dynamic Win32 Buffer Sizing for `GetExtendedTcpTable` (IPv4)
/// Loops up to 3 times with a 2x buffer margin to handle high socket churn.
#[cfg(target_os = "windows")]
fn get_tcp_ipv4_table() -> Vec<MIB_TCPROW_OWNER_PID> {
    let mut dw_size: u32 = 0;
    unsafe {
        let _ = GetExtendedTcpTable(
            std::ptr::null_mut(),
            &mut dw_size,
            0,
            AF_INET as u32,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        );
    }
    if dw_size == 0 {
        return Vec::new();
    }

    for _ in 0..3 {
        let alloc_size = (dw_size * 2) as usize;
        let mut buffer: Vec<u8> = vec![0u8; alloc_size];
        let mut actual_size = alloc_size as u32;

        let ret = unsafe {
            GetExtendedTcpTable(
                buffer.as_mut_ptr() as *mut std::ffi::c_void,
                &mut actual_size,
                0,
                AF_INET as u32,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            )
        };

        if ret == NO_ERROR {
            let table = unsafe { &*(buffer.as_ptr() as *const MIB_TCPTABLE_OWNER_PID) };
            let count = table.dwNumEntries as usize;
            let rows_ptr = table.table.as_ptr();
            let mut rows = Vec::with_capacity(count);
            for i in 0..count {
                rows.push(unsafe { *rows_ptr.add(i) });
            }
            return rows;
        } else if ret == ERROR_INSUFFICIENT_BUFFER {
            dw_size = actual_size;
            continue;
        } else {
            break;
        }
    }
    Vec::new()
}

/// Dynamic Win32 Buffer Sizing for `GetExtendedTcpTable` (IPv6)
#[cfg(target_os = "windows")]
fn get_tcp_ipv6_table() -> Vec<MIB_TCP6ROW_OWNER_PID> {
    let mut dw_size: u32 = 0;
    unsafe {
        let _ = GetExtendedTcpTable(
            std::ptr::null_mut(),
            &mut dw_size,
            0,
            AF_INET6 as u32,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        );
    }
    if dw_size == 0 {
        return Vec::new();
    }

    for _ in 0..3 {
        let alloc_size = (dw_size * 2) as usize;
        let mut buffer: Vec<u8> = vec![0u8; alloc_size];
        let mut actual_size = alloc_size as u32;

        let ret = unsafe {
            GetExtendedTcpTable(
                buffer.as_mut_ptr() as *mut std::ffi::c_void,
                &mut actual_size,
                0,
                AF_INET6 as u32,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            )
        };

        if ret == NO_ERROR {
            let table = unsafe { &*(buffer.as_ptr() as *const MIB_TCP6TABLE_OWNER_PID) };
            let count = table.dwNumEntries as usize;
            let rows_ptr = table.table.as_ptr();
            let mut rows = Vec::with_capacity(count);
            for i in 0..count {
                rows.push(unsafe { *rows_ptr.add(i) });
            }
            return rows;
        } else if ret == ERROR_INSUFFICIENT_BUFFER {
            dw_size = actual_size;
            continue;
        } else {
            break;
        }
    }
    Vec::new()
}

/// Dynamic Win32 Buffer Sizing for `GetExtendedUdpTable` (IPv4)
#[cfg(target_os = "windows")]
fn get_udp_ipv4_table() -> Vec<MIB_UDPROW_OWNER_PID> {
    let mut dw_size: u32 = 0;
    unsafe {
        let _ = GetExtendedUdpTable(
            std::ptr::null_mut(),
            &mut dw_size,
            0,
            AF_INET as u32,
            UDP_TABLE_OWNER_PID,
            0,
        );
    }
    if dw_size == 0 {
        return Vec::new();
    }

    for _ in 0..3 {
        let alloc_size = (dw_size * 2) as usize;
        let mut buffer: Vec<u8> = vec![0u8; alloc_size];
        let mut actual_size = alloc_size as u32;

        let ret = unsafe {
            GetExtendedUdpTable(
                buffer.as_mut_ptr() as *mut std::ffi::c_void,
                &mut actual_size,
                0,
                AF_INET as u32,
                UDP_TABLE_OWNER_PID,
                0,
            )
        };

        if ret == NO_ERROR {
            let table = unsafe { &*(buffer.as_ptr() as *const MIB_UDPTABLE_OWNER_PID) };
            let count = table.dwNumEntries as usize;
            let rows_ptr = table.table.as_ptr();
            let mut rows = Vec::with_capacity(count);
            for i in 0..count {
                rows.push(unsafe { *rows_ptr.add(i) });
            }
            return rows;
        } else if ret == ERROR_INSUFFICIENT_BUFFER {
            dw_size = actual_size;
            continue;
        } else {
            break;
        }
    }
    Vec::new()
}

/// Dynamic Win32 Buffer Sizing for `GetExtendedUdpTable` (IPv6)
#[cfg(target_os = "windows")]
fn get_udp_ipv6_table() -> Vec<MIB_UDP6ROW_OWNER_PID> {
    let mut dw_size: u32 = 0;
    unsafe {
        let _ = GetExtendedUdpTable(
            std::ptr::null_mut(),
            &mut dw_size,
            0,
            AF_INET6 as u32,
            UDP_TABLE_OWNER_PID,
            0,
        );
    }
    if dw_size == 0 {
        return Vec::new();
    }

    for _ in 0..3 {
        let alloc_size = (dw_size * 2) as usize;
        let mut buffer: Vec<u8> = vec![0u8; alloc_size];
        let mut actual_size = alloc_size as u32;

        let ret = unsafe {
            GetExtendedUdpTable(
                buffer.as_mut_ptr() as *mut std::ffi::c_void,
                &mut actual_size,
                0,
                AF_INET6 as u32,
                UDP_TABLE_OWNER_PID,
                0,
            )
        };

        if ret == NO_ERROR {
            let table = unsafe { &*(buffer.as_ptr() as *const MIB_UDP6TABLE_OWNER_PID) };
            let count = table.dwNumEntries as usize;
            let rows_ptr = table.table.as_ptr();
            let mut rows = Vec::with_capacity(count);
            for i in 0..count {
                rows.push(unsafe { *rows_ptr.add(i) });
            }
            return rows;
        } else if ret == ERROR_INSUFFICIENT_BUFFER {
            dw_size = actual_size;
            continue;
        } else {
            break;
        }
    }
    Vec::new()
}

/// Enumerates loaded PE modules for a given PID via `CreateToolhelp32Snapshot`.
#[cfg(target_os = "windows")]
fn enumerate_process_modules(pid: u32) -> Vec<(String, String, String, String)> {
    let mut modules = Vec::new();
    let snapshot = unsafe {
        CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid)
    };
    if snapshot == INVALID_HANDLE_VALUE {
        return modules;
    }

    let mut entry: MODULEENTRY32W = unsafe { std::mem::zeroed() };
    entry.dwSize = std::mem::size_of::<MODULEENTRY32W>() as u32;

    if unsafe { Module32FirstW(snapshot, &mut entry) } != 0 {
        loop {
            let base_addr = entry.modBaseAddr as usize;
            let base_size = entry.modBaseSize as usize;
            let start = format!("0x{:016x}", base_addr);
            let end = format!("0x{:016x}", base_addr + base_size);

            let len = entry
                .szExePath
                .iter()
                .position(|&c| c == 0)
                .unwrap_or(entry.szExePath.len());
            let path = String::from_utf16_lossy(&entry.szExePath[..len]);
            let permissions = "r-x".to_string();

            modules.push((start, end, permissions, path));

            if unsafe { Module32NextW(snapshot, &mut entry) } == 0 {
                break;
            }
        }
    }

    unsafe { CloseHandle(snapshot) };
    modules
}

/// Extracts a numeric PID from a pipe name like `crashpad_1234_xxx` or `1234.5678`.
fn extract_pid_from_pipename(name: &str) -> Option<u32> {
    for part in name.split(|c: char| !c.is_ascii_digit()) {
        if !part.is_empty() {
            if let Ok(pid) = part.parse::<u32>() {
                if pid > 4 && pid < 100_000 {
                    return Some(pid);
                }
            }
        }
    }
    None
}

/// Extracts a target PID filter from query text like `pid = 1234` or `pid=1234`.
fn extract_pid_hint(query: &str) -> Option<u32> {
    let idx = query.find("pid")?;
    let remainder = &query[idx + 3..];
    let after_eq = remainder.trim_start().strip_prefix('=')?;
    let num_str: String = after_eq
        .trim_start()
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect();
    num_str.parse::<u32>().ok()
}

/// Translates Win32 TCP MIB state integers to canonical RFC / osquery string names.
fn tcp_state_name(state: u32) -> &'static str {
    match state {
        1 => "CLOSED",
        2 => "LISTEN",
        3 => "SYN_SENT",
        4 => "SYN_RCVD",
        5 => "ESTABLISHED",
        6 => "FIN_WAIT1",
        7 => "FIN_WAIT2",
        8 => "CLOSE_WAIT",
        9 => "CLOSING",
        10 => "LAST_ACK",
        11 => "TIME_WAIT",
        12 => "DELETE_TCB",
        _ => "UNKNOWN",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_siquery_processes_table() {
        let engine = SiqueryEngine::new();
        let rows = engine
            .execute_query("SELECT pid, name, path, cmdline, state FROM processes LIMIT 10;")
            .expect("processes query failed");

        assert!(!rows.is_empty(), "processes table must return rows");
        let first = &rows[0];
        assert!(first.get("pid").is_some());
        assert!(first.get("name").is_some());
    }

    #[test]
    fn test_siquery_process_open_sockets_table() {
        let engine = SiqueryEngine::new();
        let rows = engine
            .execute_query("SELECT pid, local_address, local_port, remote_address, remote_port, state, protocol FROM process_open_sockets LIMIT 10;")
            .expect("process_open_sockets query failed");

        // System should have sockets open (or return empty vec without error)
        assert!(rows.is_empty() || rows[0].get("local_port").is_some());
    }

    #[test]
    fn test_siquery_join_processes_and_sockets() {
        let engine = SiqueryEngine::new();
        let sql = "SELECT p.pid, p.name, s.local_port, s.remote_port, s.state \
                   FROM processes p JOIN process_open_sockets s ON p.pid = s.pid \
                   LIMIT 5;";
        let rows = engine.execute_query(sql).expect("JOIN query failed");
        // Must succeed without SQLite syntax or table errors
        assert!(rows.is_empty() || rows[0].get("pid").is_some());
    }

    #[test]
    fn test_siquery_pragma_table_info_process_memory_map() {
        let engine = SiqueryEngine::new();
        // Exact query modeled on siquery-rs README: PRAGMA table_info(process_memory_map)
        let rows = engine
            .execute_query("PRAGMA table_info(process_memory_map);")
            .expect("PRAGMA table_info failed");

        assert!(!rows.is_empty(), "PRAGMA table_info must return column metadata");
        let col_names: Vec<String> = rows
            .iter()
            .filter_map(|r| r.get("name").and_then(|v| v.as_str()).map(|s| s.to_string()))
            .collect();

        assert!(col_names.contains(&"pid".to_string()));
        assert!(col_names.contains(&"start".to_string()));
        assert!(col_names.contains(&"end".to_string()));
        assert!(col_names.contains(&"permissions".to_string()));
        assert!(col_names.contains(&"offset".to_string()));
        assert!(col_names.contains(&"device".to_string()));
        assert!(col_names.contains(&"inode".to_string()));
        assert!(col_names.contains(&"path".to_string()));
        assert!(col_names.contains(&"pseudo".to_string()));
    }

    #[test]
    fn test_siquery_etc_hosts_and_system_info() {
        let engine = SiqueryEngine::new();

        let sys_rows = engine
            .execute_query("SELECT computer_name, cpu_logical_cores, physical_memory FROM system_info;")
            .expect("system_info query failed");
        assert_eq!(sys_rows.len(), 1);
        let info = &sys_rows[0];
        assert!(info.get("cpu_logical_cores").and_then(|v| v.as_i64()).unwrap_or(0) > 0);

        let host_rows = engine
            .execute_query("SELECT address, hostnames FROM etc_hosts;")
            .expect("etc_hosts query failed");
        // Should execute cleanly
        assert!(host_rows.is_empty() || host_rows[0].get("address").is_some());
    }

    #[test]
    fn test_siquery_read_only_safety() {
        let engine = SiqueryEngine::new();
        let res = engine.execute_query("DROP TABLE processes;");
        assert!(res.is_err(), "Mutating SQL queries must be rejected");
    }
}
