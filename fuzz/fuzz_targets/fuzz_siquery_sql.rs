#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(query) = std::str::from_utf8(data) {
        let trimmed = query.trim();
        let is_select = trimmed.to_ascii_uppercase().starts_with("SELECT ");
        let has_semicolon = trimmed.trim_end_matches(';').contains(';');
        let _ = (is_select, has_semicolon);
    }
});
