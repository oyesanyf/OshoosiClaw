#!/usr/bin/env python3
"""Patch vendor/hayabusa/src/detections/configs.rs to add StoredStatic::dummy()"""
import sys

path = r"d:\harfile\OshoosiClaw\vendor\hayabusa\src\detections\configs.rs"

with open(path, "r", encoding="utf-8") as f:
    lines = f.readlines()

# Find insertion point: after "        ret\r\n    }\r\n" before the "    /// details" comment (line 881)
# The line 879 is "        ret\r\n", line 880 is "    }\r\n", line 881 is "    /// details..."
# We want to insert AFTER line 880 and BEFORE line 881

insert_after = None
for i, line in enumerate(lines):
    stripped = line.rstrip('\r\n')
    if stripped == '    }' and i > 870 and i < 885:
        # Check next line starts with the details comment
        if i + 1 < len(lines) and 'default' in lines[i+1] and 'details' in lines[i+1]:
            insert_after = i
            break

if insert_after is None:
    print("ERROR: Could not find insertion point!")
    sys.exit(1)

dummy_method = r'''
    /// Create a minimal `StoredStatic` that does **not** load any config files from disk.
    /// Used by OshoosiClaw when running Hayabusa as an embedded library where the
    /// standard `rules/config/` tree may not be relative to the CWD or the executable.
    pub fn dummy() -> StoredStatic {
        use aho_corasick::{AhoCorasickBuilder, MatchKind};
        StoredStatic {
            config: Config { action: None, debug: false },
            config_path: PathBuf::from("."),
            eventkey_alias: EventKeyAliasConfig::new(),
            ch_config: HashMap::new(),
            disp_abbr_generic: AhoCorasickBuilder::new()
                .ascii_case_insensitive(true)
                .match_kind(MatchKind::LeftmostLongest)
                .build::<&str>(&[])
                .unwrap(),
            disp_abbr_general_values: Vec::new(),
            provider_abbr_config: HashMap::new(),
            quiet_errors_flag: true,
            verbose_flag: false,
            metrics_flag: false,
            logon_summary_flag: false,
            search_flag: false,
            computer_metrics_flag: false,
            log_metrics_flag: false,
            extract_base64_flag: false,
            search_option: None,
            output_option: None,
            pivot_keyword_list_flag: false,
            default_details: HashMap::new(),
            html_report_flag: false,
            profiles: None,
            event_timeline_config: EventInfoConfig::default(),
            target_eventids: TargetIds::default(),
            target_ruleids: TargetIds::default(),
            thread_number: None,
            json_input_flag: false,
            output_path: None,
            common_options: CommonOptions {
                no_color: false,
                quiet: true,
                help: None,
            },
            multiline_flag: false,
            tab_separator_flag: false,
            include_computer: HashSet::default(),
            exclude_computer: HashSet::default(),
            include_eid: HashSet::default(),
            exclude_eid: HashSet::default(),
            include_status: HashSet::from_iter(vec![CompactString::from("*")]),
            field_data_map: None,
            no_pwsh_field_extraction: true,
            enable_recover_records: false,
            time_offset: None,
            is_low_memory: false,
            enable_all_rules: true,
            scan_all_evtx_files: false,
            metrics_remove_duplication: false,
            disable_abbreviation: true,
            validate_checksum: false,
        }
    }

'''

# Convert to CRLF lines
dummy_lines = [l + '\r\n' for l in dummy_method.split('\n')]

# Insert after line `insert_after` (0-indexed)
new_lines = lines[:insert_after + 1] + dummy_lines + lines[insert_after + 1:]

with open(path, "w", encoding="utf-8") as f:
    f.writelines(new_lines)

print(f"SUCCESS: Inserted dummy() method after line {insert_after + 1}")
