//! Kill Switch — Process lifecycle management for WASM agents.
//!
//! Like Linux's process scheduler, this allows administrators to instantly
//! terminate a misbehaving WASM agent, reclaiming all resources.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use chrono::{DateTime, Utc};
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AgentStatus {
    Running,
    Paused,
    Killed,
    Completed,
    Error(String),
}

/// Tracks the lifecycle of a single WASM agent execution.
pub struct AgentProcess {
    pub id: String,
    pub name: String,
    pub started_at: DateTime<Utc>,
    pub status: AgentStatus,
    pub fuel_consumed: AtomicU64,
    pub memory_bytes: AtomicU64,
    pub syscall_count: AtomicU64,
    /// When set to true, the epoch will be incremented to kill the agent.
    kill_flag: Arc<AtomicBool>,
    /// The Wasmtime engine (used to trigger epoch interrupt).
    engine: wasmtime::Engine,
}

impl AgentProcess {
    pub fn new(id: String, name: String, engine: wasmtime::Engine) -> Self {
        Self {
            id,
            name,
            started_at: Utc::now(),
            status: AgentStatus::Running,
            fuel_consumed: AtomicU64::new(0),
            memory_bytes: AtomicU64::new(0),
            syscall_count: AtomicU64::new(0),
            kill_flag: Arc::new(AtomicBool::new(false)),
            engine,
        }
    }

    /// Kill the agent immediately by incrementing the Wasmtime epoch.
    pub fn kill(&mut self) {
        tracing::warn!("KILL SWITCH: Terminating agent '{}' (id={})", self.name, self.id);
        self.kill_flag.store(true, Ordering::SeqCst);
        self.engine.increment_epoch();
        self.status = AgentStatus::Killed;
    }

    /// Pause the agent (set flag; epoch-based scheduling will handle the rest).
    pub fn pause(&mut self) {
        tracing::info!("PAUSE: Agent '{}' paused", self.name);
        self.status = AgentStatus::Paused;
    }

    /// Check if the kill flag has been set.
    pub fn is_killed(&self) -> bool {
        self.kill_flag.load(Ordering::SeqCst)
    }

    /// Get a JSON snapshot of the agent's resource usage.
    pub fn snapshot(&self) -> serde_json::Value {
        serde_json::json!({
            "id": self.id,
            "name": self.name,
            "started_at": self.started_at,
            "status": format!("{:?}", self.status),
            "fuel_consumed": self.fuel_consumed.load(Ordering::Relaxed),
            "memory_bytes": self.memory_bytes.load(Ordering::Relaxed),
            "syscall_count": self.syscall_count.load(Ordering::Relaxed),
        })
    }
}

/// Process table: tracks all active WASM agents.
pub struct ProcessTable {
    agents: tokio::sync::Mutex<Vec<AgentProcess>>,
}

impl Default for ProcessTable {
    fn default() -> Self {
        Self::new()
    }
}

impl ProcessTable {
    pub fn new() -> Self {
        Self {
            agents: tokio::sync::Mutex::new(Vec::new()),
        }
    }

    pub async fn register(&self, agent: AgentProcess) {
        self.agents.lock().await.push(agent);
    }

    /// Kill an agent by ID.
    pub async fn kill(&self, id: &str) -> bool {
        let mut agents = self.agents.lock().await;
        if let Some(agent) = agents.iter_mut().find(|a| a.id == id) {
            agent.kill();
            true
        } else {
            false
        }
    }

    /// Kill all running agents.
    pub async fn kill_all(&self) {
        let mut agents = self.agents.lock().await;
        for agent in agents.iter_mut() {
            if matches!(agent.status, AgentStatus::Running) {
                agent.kill();
            }
        }
    }

    /// Get snapshots of all agents.
    pub async fn list(&self) -> Vec<serde_json::Value> {
        let agents = self.agents.lock().await;
        agents.iter().map(|a| a.snapshot()).collect()
    }
}
