//! Behavioral Detectors for Process, Console, and Execution Anomalies.
//!
//! Specifically implements detectors for:
//! - EDR-VEC-23: Interactive Elevated Console / Conhost QuickEdit Freeze,
//!   WriteConsoleInput Buffer Injection, and Parent cmd.exe Shell Drop.

use serde::{Deserialize, Serialize};

/// Context representation of a process and its console / window environment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsoleProcessContext {
    pub pid: u32,
    pub process_name: String,
    pub command_line: String,
    pub parent_name: String,
    pub parent_command_line: String,
    pub is_elevated: bool,
    pub is_signed: bool,
    pub has_attached_console: bool,
    pub console_mode: Option<u32>,
    pub console_window_title: Option<String>,
    pub attempted_buffer_injection: bool,
    pub running_duration_secs: u64,
}

/// Alert emitted by the console security detector when an interactive console exploit pattern is identified.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsoleSecurityAlert {
    pub rule_id: &'static str,
    pub mitre_technique: &'static str,
    pub severity: &'static str,
    pub description: String,
    pub recommended_action: &'static str,
}

// Windows Console Mode Constants
pub const ENABLE_MOUSE_INPUT: u32 = 0x0010;
pub const ENABLE_INSERT_MODE: u32 = 0x0020;
pub const ENABLE_QUICK_EDIT_MODE: u32 = 0x0040;
pub const ENABLE_EXTENDED_FLAGS: u32 = 0x0080;
pub const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// Detector for elevated console hijack, QuickEdit freeze DoS, and conhost buffer injection (EDR-VEC-23).
pub struct ElevatedConsoleHijackDetector;

impl ElevatedConsoleHijackDetector {
    /// Evaluates a process and its console context against EDR-VEC-23 attack patterns.
    pub fn evaluate(ctx: &ConsoleProcessContext) -> Option<ConsoleSecurityAlert> {
        let proc_lower = ctx.process_name.to_ascii_lowercase();
        let parent_lower = ctx.parent_name.to_ascii_lowercase();
        let cmd_lower = ctx.command_line.to_ascii_lowercase();
        let title_lower = ctx
            .console_window_title
            .as_deref()
            .unwrap_or("")
            .to_ascii_lowercase();

        // 1. EDR-VEC-23-BUFFER-INJECTION: Unauthorized attempt to inject console input events or attach/scrape buffer
        if ctx.attempted_buffer_injection
            || cmd_lower.contains("writeconsoleinput")
            || cmd_lower.contains("attachconsole")
            || cmd_lower.contains("readconsoleoutput")
        {
            return Some(ConsoleSecurityAlert {
                rule_id: "EDR-VEC-23-BUFFER-INJECTION",
                mitre_technique: "T1055.011",
                severity: "CRITICAL",
                description: format!(
                    "Process {} (PID {}) attempted unauthorized console input buffer injection or scraping (WriteConsoleInput/AttachConsole)",
                    ctx.process_name, ctx.pid
                ),
                recommended_action: "Flush console input buffer via FlushConsoleInputBuffer, terminate injecting process, and isolate host session",
            });
        }

        // 2. EDR-VEC-23-QUICKEDIT-FREEZE: QuickEdit / Select Mode freeze DoS on elevated console window
        let is_quickedit_active = title_lower.starts_with("select ")
            || ctx
                .console_mode
                .is_some_and(|m| (m & ENABLE_QUICK_EDIT_MODE) != 0);

        if is_quickedit_active && ctx.is_elevated && ctx.has_attached_console {
            return Some(ConsoleSecurityAlert {
                rule_id: "EDR-VEC-23-QUICKEDIT-FREEZE",
                mitre_technique: "T1562.001",
                severity: "HIGH",
                description: format!(
                    "Elevated process {} (PID {}) attached to interactive console with QuickEdit / Select Mode active; vulnerable to freeze DoS and output blocking",
                    ctx.process_name, ctx.pid
                ),
                recommended_action: "Apply harden_windows_console() to strip QuickEdit mode and enforce ENABLE_EXTENDED_FLAGS",
            });
        }

        // 3. EDR-VEC-23-UNSIGNED-ELEVATED-CONHOST: Unsigned daemon or long-running process attached to interactive elevated console without extended flags
        let lacks_extended_flags = ctx
            .console_mode
            .is_none_or(|m| (m & ENABLE_EXTENDED_FLAGS) == 0);
        if !ctx.is_signed
            && ctx.is_elevated
            && ctx.has_attached_console
            && (lacks_extended_flags || ctx.running_duration_secs > 30)
        {
            return Some(ConsoleSecurityAlert {
                rule_id: "EDR-VEC-23-UNSIGNED-ELEVATED-CONHOST",
                mitre_technique: "T1562",
                severity: "HIGH",
                description: format!(
                    "Unsigned process {} (PID {}) running elevated attached to interactive conhost without ENABLE_EXTENDED_FLAGS protection (uptime: {}s)",
                    ctx.process_name, ctx.pid, ctx.running_duration_secs
                ),
                recommended_action: "Verify Authenticode signature, invoke FreeConsole() in background mode, and enforce CREATE_NO_WINDOW",
            });
        }

        // 4. EDR-VEC-23-INTERACTIVE-CMD-PARENT: Long-running background daemon spawned from interactive elevated cmd.exe / start.exe without console detachment
        let is_shell_parent = parent_lower == "cmd.exe"
            || parent_lower == "powershell.exe"
            || parent_lower == "start.exe";
        let is_daemon_process = proc_lower.contains("osoosi")
            || proc_lower.contains("daemon")
            || proc_lower.contains("agent")
            || ctx.running_duration_secs > 60;
        if is_shell_parent && is_daemon_process && ctx.is_elevated && ctx.has_attached_console {
            return Some(ConsoleSecurityAlert {
                rule_id: "EDR-VEC-23-INTERACTIVE-CMD-PARENT",
                mitre_technique: "T1059.003",
                severity: "MEDIUM",
                description: format!(
                    "Long-running daemon {} (PID {}) running under interactive elevated parent shell {} without console detachment; risk of interactive shell drop on termination",
                    ctx.process_name, ctx.pid, ctx.parent_name
                ),
                recommended_action: "Invoke FreeConsole() or launch as a registered Windows Service under LocalSystem without desktop interactive window",
            });
        }

        None
    }
}
