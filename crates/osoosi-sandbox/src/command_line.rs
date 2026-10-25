//! Microsoft C/C++ runtime (`CommandLineToArgvW` / MSVCRT) argument quoting and command-line construction.
//!
//! Provides strict adherence to MSVCRT parsing semantics:
//! - An empty argument must be rendered as `""`.
//! - Arguments containing spaces, tabs, newlines, vertical tabs, or double quotes must be enclosed in double quotes.
//! - Sequences of backslashes immediately preceding a double quote must be doubled ($2n + 1$ backslashes followed by `"`).
//! - Sequences of backslashes immediately preceding the closing quote of an enclosed argument must be doubled ($2n$ backslashes followed by `"`).
//! - All other backslashes are preserved literally.

/// Quotes a single Windows command-line argument according to Microsoft C/C++ runtime
/// (`CommandLineToArgvW` / MSVCRT) parsing rules, preventing quote-escape and trailing-backslash
/// argument injection.
pub fn quote_windows_argv_arg(arg: &str) -> String {
    if !arg.is_empty()
        && !arg
            .chars()
            .any(|c| c == ' ' || c == '\t' || c == '\n' || c == '\x0b' || c == '"')
    {
        return arg.to_string();
    }
    let mut quoted = String::with_capacity(arg.len() + 4);
    quoted.push('"');
    let mut backslashes = 0usize;
    for ch in arg.chars() {
        if ch == '\\' {
            backslashes += 1;
        } else if ch == '"' {
            for _ in 0..(backslashes * 2 + 1) {
                quoted.push('\\');
            }
            quoted.push('"');
            backslashes = 0;
        } else {
            for _ in 0..backslashes {
                quoted.push('\\');
            }
            backslashes = 0;
            quoted.push(ch);
        }
    }
    for _ in 0..(backslashes * 2) {
        quoted.push('\\');
    }
    quoted.push('"');
    quoted
}

/// Builds a complete MSVCRT-quoted command line from an executable path and argument vector.
pub fn build_windows_command_line(program: &str, args: &[String]) -> String {
    let mut cmdline = format!("\"{}\"", program.replace('"', ""));
    for arg in args {
        cmdline.push(' ');
        cmdline.push_str(&quote_windows_argv_arg(arg));
    }
    cmdline
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_quote_windows_argv_arg_plain() {
        assert_eq!(quote_windows_argv_arg("simple"), "simple");
        assert_eq!(quote_windows_argv_arg("foo-bar_123.exe"), "foo-bar_123.exe");
    }

    #[test]
    fn test_quote_windows_argv_arg_empty() {
        assert_eq!(quote_windows_argv_arg(""), "\"\"");
    }

    #[test]
    fn test_quote_windows_argv_arg_spaces() {
        assert_eq!(quote_windows_argv_arg("hello world"), "\"hello world\"");
    }

    #[test]
    fn test_quote_windows_argv_arg_trailing_backslashes() {
        // Trailing backslash before closing quote must be doubled ($2n$)
        let tricky = r#"C:\path with spaces\trailing\"#;
        assert_eq!(
            quote_windows_argv_arg(tricky),
            r#""C:\path with spaces\trailing\\""#
        );
    }

    #[test]
    fn test_quote_windows_argv_arg_embedded_quotes() {
        // Backslash before embedded quote must be doubled ($2n + 1$)
        let arg = r#"foo\"bar"#;
        assert_eq!(quote_windows_argv_arg(arg), r#""foo\\\"bar""#);
    }

    #[test]
    fn test_build_windows_command_line_composition() {
        let full_cmd = build_windows_command_line(
            r"C:\Windows\System32\where.exe",
            &[
                r#"C:\path with spaces\trailing\"#.to_string(),
                "".to_string(),
                "normal".to_string(),
            ],
        );
        assert!(
            full_cmd.starts_with(r#""C:\Windows\System32\where.exe""#),
            "Command line must start with quoted program: {}",
            full_cmd
        );
        assert!(
            full_cmd.contains(r#""C:\path with spaces\trailing\\""#),
            "Command line must properly double trailing backslash: {}",
            full_cmd
        );
        assert!(
            full_cmd.ends_with(" \"\" normal"),
            "Command line must properly quote empty argument: {}",
            full_cmd
        );
    }
}
