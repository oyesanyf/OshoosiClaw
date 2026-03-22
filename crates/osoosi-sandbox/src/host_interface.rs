//! Host Function Interface — The WASI "Syscall Boundary".
//!
//! Defines the interface between the WASM Brain (isolated logic) and the
//! Native Host (OS-touching code). Every interaction between the two worlds
//! passes through this boundary, and is metered, taint-checked, and audited.
//!
//! This module is the contract. The WASM side calls these as imported functions.
//! The native host provides the implementations.

use serde::{Deserialize, Serialize};

/// Every host function call is tagged with a request type.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HostCall {
    /// host_scan_file(bytes) -> MalwareScanResult
    ScanFile {
        bytes: Vec<u8>,
    },
    /// host_fetch_url(url) -> Response
    FetchUrl {
        url: String,
        method: String,
        headers: Vec<(String, String)>,
    },
    /// host_exec_command(cmd) -> Output
    ExecCommand {
        program: String,
        args: Vec<String>,
        requires_approval: bool,
    },
    /// host_read_db(query) -> Rows
    ReadDb {
        query: String,
        params: Vec<String>,
    },
    /// host_send_mesh(topic, data) -> ()
    SendMesh {
        topic: String,
        data: Vec<u8>,
    },
    /// host_write_audit(entry) -> Hash
    WriteAudit {
        entry: serde_json::Value,
    },
    /// Query threat intelligence (KEV/NVD/OTX).
    QueryThreatIntel {
        indicator: String,
        indicator_type: String,
    },
}

/// Every host function returns a typed response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HostResponse {
    /// MalwareScanResult
    ScanResult {
        is_malware: bool,
        malware_type: String,
        confidence: f64,
    },
    /// Response (HTTP)
    HttpResponse {
        status: u16,
        body: String,
    },
    /// Output (Command)
    CommandOutput {
        exit_code: i32,
        stdout: String,
        stderr: String,
    },
    /// Rows (Database)
    DbRows {
        rows: Vec<serde_json::Value>,
    },
    /// Hash (Audit/Mesh Ack)
    Hash(String),
    /// Acknowledgment (General)
    Ack {
        id: String,
    },
    /// Threat intel query result.
    ThreatIntelResult {
        found: bool,
        data: serde_json::Value,
    },
    /// Error response.
    Error {
        message: String,
    },
    /// Action queued for human approval.
    PendingApproval {
        approval_id: String,
    },
}

/// Metadata attached to every host call for auditing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostCallEnvelope {
    pub call_id: String,
    pub caller_module: String,
    pub call: HostCall,
    pub fuel_remaining: u64,
    pub taint_labels: Vec<String>,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

/// Metadata attached to every host response for auditing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostResponseEnvelope {
    pub call_id: String,
    pub response: HostResponse,
    pub duration_us: u64,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}
