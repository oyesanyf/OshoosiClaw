//! Process Hollowing Interception Detector.
//!
//! Intercepts process creation with CREATE_SUSPENDED (0x00000004),
//! remote memory modifications (WriteProcessMemory), and thread context redirection (SetThreadContext).

use std::sync::Arc;
use dashmap::DashMap;
use tracing::{info, warn};

pub const CREATE_SUSPENDED: u32 = 0x00000004;

#[derive(Debug, Clone)]
pub struct HollowingProcessState {
    pub pid: u32,
    pub image: String,
    pub created_suspended: bool,
    pub remote_write_count: usize,
    pub thread_redirected: bool,
    pub hollowing_confirmed: bool,
    pub caller_pids: Vec<u32>,
    pub created_at: std::time::Instant,
}

#[derive(Clone, Default)]
pub struct ProcessHollowingDetector {
    pub state_map: Arc<DashMap<u32, HollowingProcessState>>,
}

impl ProcessHollowingDetector {
    pub fn new() -> Self {
        Self {
            state_map: Arc::new(DashMap::new()),
        }
    }

    pub fn prune_stale(&self, max_age: std::time::Duration) {
        self.state_map.retain(|_, state| state.created_at.elapsed() < max_age);
    }

    /// Called when a new process is created.
    /// Returns true if the process was created in a suspended state (CREATE_SUSPENDED).
    pub fn on_process_create(&self, pid: u32, image: &str, create_flags: u32) -> bool {
        let is_suspended = (create_flags & CREATE_SUSPENDED) != 0;
        if is_suspended {
            if self.state_map.len() > 1024 {
                self.prune_stale(std::time::Duration::from_secs(3600));
            }

            info!(
                "ProcessHollowingDetector: Detected process created with CREATE_SUSPENDED: {} (PID {})",
                image, pid
            );
            self.state_map.insert(
                pid,
                HollowingProcessState {
                    pid,
                    image: image.to_string(),
                    created_suspended: true,
                    remote_write_count: 0,
                    thread_redirected: false,
                    hollowing_confirmed: false,
                    caller_pids: Vec::new(),
                    created_at: std::time::Instant::now(),
                },
            );
            true
        } else {
            false
        }
    }

    /// Called when remote memory writing (WriteProcessMemory / NtWriteVirtualMemory) is observed.
    /// If the target process was created suspended, this confirms process hollowing!
    pub fn on_remote_memory_write(&self, target_pid: u32, caller_pid: u32) -> bool {
        if let Some(mut state) = self.state_map.get_mut(&target_pid) {
            if state.created_suspended {
                state.remote_write_count += 1;
                state.caller_pids.push(caller_pid);
                state.hollowing_confirmed = true;
                warn!(
                    "ProcessHollowingDetector: CONFIRMED HOLLOWING! Remote memory write from caller PID {} to suspended process {} (PID {})",
                    caller_pid, state.image, target_pid
                );
                return true;
            }
        }
        false
    }

    /// Called when SetThreadContext / NtSetContextThread is observed on target PID.
    pub fn on_set_thread_context(&self, target_pid: u32) -> bool {
        if let Some(mut state) = self.state_map.get_mut(&target_pid) {
            state.thread_redirected = true;
            info!(
                "ProcessHollowingDetector: Thread context redirected for PID {}",
                target_pid
            );
            if state.created_suspended && state.remote_write_count > 0 {
                state.hollowing_confirmed = true;
                return true;
            }
        }
        false
    }

    /// Called when process terminates.
    pub fn on_process_terminate(&self, pid: u32) {
        if self.state_map.remove(&pid).is_some() {
            info!("ProcessHollowingDetector: Removed PID {} on termination", pid);
        }
    }

    pub fn is_hollowing_confirmed(&self, pid: u32) -> bool {
        self.state_map.get(&pid).map(|s| s.hollowing_confirmed).unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normal_process_lifecycle_not_flagged() {
        let detector = ProcessHollowingDetector::new();
        let pid = 1234;
        let created_suspended = detector.on_process_create(pid, "notepad.exe", 0);
        assert!(!created_suspended);
        assert!(!detector.is_hollowing_confirmed(pid));

        let write_confirmed = detector.on_remote_memory_write(pid, 5678);
        assert!(!write_confirmed);
        assert!(!detector.is_hollowing_confirmed(pid));

        detector.on_process_terminate(pid);
        assert_eq!(detector.state_map.len(), 0);
    }

    #[test]
    fn test_hollowing_detection_workflow() {
        let detector = ProcessHollowingDetector::new();
        let target_pid = 4321;
        let attacker_pid = 9999;

        // 1. Process created suspended
        let suspended = detector.on_process_create(target_pid, "svchost.exe", CREATE_SUSPENDED);
        assert!(suspended);
        assert!(detector.state_map.contains_key(&target_pid));
        assert!(!detector.is_hollowing_confirmed(target_pid));

        // 2. Caller writes to remote memory
        let confirmed = detector.on_remote_memory_write(target_pid, attacker_pid);
        assert!(confirmed);
        assert!(detector.is_hollowing_confirmed(target_pid));

        // 3. Thread context redirected
        let ctx = detector.on_set_thread_context(target_pid);
        assert!(ctx);

        {
            let state = detector.state_map.get(&target_pid).unwrap();
            assert!(state.thread_redirected);
            assert_eq!(state.remote_write_count, 1);
            assert_eq!(state.caller_pids, vec![attacker_pid]);
        }

        // 4. Terminate cleans up
        detector.on_process_terminate(target_pid);
        assert_eq!(detector.state_map.len(), 0);
        assert!(!detector.is_hollowing_confirmed(target_pid));
    }

    #[test]
    fn test_hollowing_state_pruning() {
        let detector = ProcessHollowingDetector::new();
        detector.on_process_create(1001, "proc1.exe", CREATE_SUSPENDED);
        detector.on_process_create(1002, "proc2.exe", CREATE_SUSPENDED);
        assert_eq!(detector.state_map.len(), 2);

        // Pruning with zero duration should prune all entries
        detector.prune_stale(std::time::Duration::from_millis(0));
        assert_eq!(detector.state_map.len(), 0);
    }
}

