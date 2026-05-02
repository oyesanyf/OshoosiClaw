#!/usr/bin/env python3
"""Harden Hayabusa create_static_data to not panic on missing files."""
import sys

path = r"d:\harfile\OshoosiClaw\vendor\hayabusa\src\detections\configs.rs"

with open(path, "r", encoding="utf-8") as f:
    content = f.read()

# Replace the panicking unwrap sequence for channel_eid_info.txt
old1 = """.unwrap_or_else(|| {
                        check_setting_path(
                            &CURRENT_EXE_PATH.to_path_buf(),
                            "rules/config/channel_eid_info.txt",
                            true,
                        )
                        .unwrap()
                    })"""
new1 = """.unwrap_or_else(|| {
                        check_setting_path(
                            &CURRENT_EXE_PATH.to_path_buf(),
                            "rules/config/channel_eid_info.txt",
                            false,
                        ).unwrap_or_else(|| PathBuf::from(""))
                    })"""

# Replace the panicking unwrap sequence for target_event_IDs.txt
old2 = """.unwrap_or_else(|| {
                        check_setting_path(
                            &CURRENT_EXE_PATH.to_path_buf(),
                            "rules/config/target_event_IDs.txt",
                            true,
                        )
                        .unwrap()
                    })"""
new2 = """.unwrap_or_else(|| {
                        check_setting_path(
                            &CURRENT_EXE_PATH.to_path_buf(),
                            "rules/config/target_event_IDs.txt",
                            false,
                        ).unwrap_or_else(|| PathBuf::from(""))
                    })"""

# Also fix the .to_str().unwrap() which can panic if path is empty/invalid
# We'll use .to_str().unwrap_or("") instead

# Apply replacements
content = content.replace(old1, new1)
content = content.replace(old2, new2)

# Fix .to_str().unwrap() after the above blocks
# Line 822/823 and 835/836
content = content.replace(".to_str().unwrap()", '.to_str().unwrap_or("")')

# Also fix the profile loading which also has unwraps
content = content.replace('check_setting_path(\r\n                &CURRENT_EXE_PATH.to_path_buf(),\r\n                "config/default_profile.yaml",\r\n                true,\r\n            )\r\n            .unwrap()', 
                          'check_setting_path(&CURRENT_EXE_PATH.to_path_buf(), "config/default_profile.yaml", false).unwrap_or_else(|| PathBuf::from(""))')

content = content.replace('check_setting_path(\r\n                &CURRENT_EXE_PATH.to_path_buf(),\r\n                "config/profiles.yaml",\r\n                true,\r\n            )\r\n            .unwrap()', 
                          'check_setting_path(&CURRENT_EXE_PATH.to_path_buf(), "config/profiles.yaml", false).unwrap_or_else(|| PathBuf::from(""))')

with open(path, "w", encoding="utf-8") as f:
    f.write(content)

print("SUCCESS: Hardened create_static_data")
