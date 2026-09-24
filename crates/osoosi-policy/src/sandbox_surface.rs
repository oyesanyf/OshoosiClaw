#[cfg(target_os = "windows")]
use windows::Win32::Foundation::{CloseHandle, HANDLE};
#[cfg(target_os = "windows")]
use windows::Win32::Security::{
    GetSidSubAuthority, GetSidSubAuthorityCount, GetTokenInformation, IsValidSid,
    TokenElevation, TokenIntegrityLevel, TokenIsAppContainer, TokenPrivileges,
    LUID_AND_ATTRIBUTES, SE_PRIVILEGE_ENABLED, TOKEN_ELEVATION, TOKEN_MANDATORY_LABEL,
    TOKEN_PRIVILEGES, TOKEN_QUERY,
};
#[cfg(target_os = "windows")]
use windows::Win32::System::Threading::{
    OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxSurfaceInfo {
    pub integrity_level: String,
    pub is_app_container: bool,
    pub is_elevated: bool,
    pub privileges: Vec<String>,
}

#[cfg(target_os = "windows")]
pub fn parse_risk_privileges(privs: &[LUID_AND_ATTRIBUTES]) -> Vec<String> {
    let mut privileges = Vec::new();
    for luid_and_attrs in privs {
        if (luid_and_attrs.Attributes.0 & SE_PRIVILEGE_ENABLED.0) != 0 {
            let risk = match luid_and_attrs.Luid.LowPart {
                20 => "SeDebugPrivilege",
                29 => "SeImpersonatePrivilege",
                7 => "SeTcbPrivilege",
                30 => "SeCreateGlobalPrivilege",
                _ => "Other",
            };
            if risk != "Other" {
                privileges.push(risk.to_string());
            }
        }
    }
    privileges
}

#[cfg(target_os = "windows")]
pub fn analyze_process_sandbox(pid: u32) -> anyhow::Result<SandboxSurfaceInfo> {
    unsafe {
        let process_handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid)?;
        if process_handle.is_invalid() {
            return Err(anyhow::anyhow!("Failed to open process {}", pid));
        }

        let mut token_handle = HANDLE::default();
        if OpenProcessToken(process_handle, TOKEN_QUERY, &mut token_handle).is_err() {
            let _ = CloseHandle(process_handle);
            return Err(anyhow::anyhow!("Failed to open token for process {}", pid));
        }

        // 1. AppContainer Check
        let mut is_app_container: u32 = 0;
        let mut return_len: u32 = 0;
        let _ = GetTokenInformation(
            token_handle,
            TokenIsAppContainer,
            Some(&mut is_app_container as *mut _ as *mut _),
            std::mem::size_of::<u32>() as u32,
            &mut return_len,
        );

        // 2. Elevation Check
        let mut elevation: TOKEN_ELEVATION = std::mem::zeroed();
        let _ = GetTokenInformation(
            token_handle,
            TokenElevation,
            Some(&mut elevation as *mut _ as *mut _),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut return_len,
        );

        // 3. Integrity Level
        #[repr(C, align(8))]
        struct AlignedIntegrityBuf([u8; 128]);
        let mut integrity_info_buf = AlignedIntegrityBuf([0u8; 128]);
        let mut integrity_level = "Medium".to_string();
        if GetTokenInformation(
            token_handle,
            TokenIntegrityLevel,
            Some(integrity_info_buf.0.as_mut_ptr() as *mut _),
            128,
            &mut return_len,
        ).is_ok() && return_len as usize >= std::mem::size_of::<TOKEN_MANDATORY_LABEL>() {
            let label = &*(integrity_info_buf.0.as_ptr() as *const TOKEN_MANDATORY_LABEL);
            let sid = label.Label.Sid;
            if !sid.is_invalid() && IsValidSid(sid).as_bool() {
                let count_ptr = GetSidSubAuthorityCount(sid);
                if !count_ptr.is_null() {
                    let count = *count_ptr;
                    if count > 0 {
                        let subauth_ptr = GetSidSubAuthority(sid, (count - 1) as u32);
                        if !subauth_ptr.is_null() {
                            let rid = *subauth_ptr;
                            integrity_level = match rid {
                                0x0000..0x2000 => "Low".to_string(),
                                0x2000..0x3000 => "Medium".to_string(),
                                0x3000..0x4000 => "High".to_string(),
                                0x4000.. => "System".to_string(),
                            };
                        }
                    }
                }
            }
        }

        // 4. Privileges
        let mut privileges = Vec::new();
        let mut req_len: u32 = 0;
        let _ = GetTokenInformation(token_handle, TokenPrivileges, None, 0, &mut req_len);
        if req_len > 0 {
            // Ensure buffer is at least size_of::<TOKEN_PRIVILEGES>() to prevent UB when PrivilegeCount == 0
            let alloc_len = (req_len as usize).max(std::mem::size_of::<TOKEN_PRIVILEGES>());
            let mut priv_buf = vec![0u8; alloc_len];
            if GetTokenInformation(
                token_handle,
                TokenPrivileges,
                Some(priv_buf.as_mut_ptr() as *mut _),
                req_len,
                &mut return_len,
            ).is_ok() && return_len as usize >= std::mem::size_of::<u32>() {
                let token_privs = &*(priv_buf.as_ptr() as *const TOKEN_PRIVILEGES);
                let count = token_privs.PrivilegeCount as usize;
                let max_count = (return_len as usize).saturating_sub(std::mem::size_of::<u32>())
                    / std::mem::size_of::<LUID_AND_ATTRIBUTES>();
                let safe_count = count.min(max_count);
                if safe_count > 0 {
                    let privs_slice = std::slice::from_raw_parts(token_privs.Privileges.as_ptr(), safe_count);
                    privileges = parse_risk_privileges(privs_slice);
                }
            }
        }

        let _ = CloseHandle(token_handle);
        let _ = CloseHandle(process_handle);

        Ok(SandboxSurfaceInfo {
            integrity_level,
            is_app_container: is_app_container != 0,
            is_elevated: elevation.TokenIsElevated != 0,
            privileges,
        })
    }
}

#[cfg(not(target_os = "windows"))]
pub fn analyze_process_sandbox(_pid: u32) -> anyhow::Result<SandboxSurfaceInfo> {
    Ok(SandboxSurfaceInfo {
        integrity_level: "Medium".to_string(),
        is_app_container: false,
        is_elevated: false,
        privileges: Vec::new(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_analyze_process_sandbox_self() {
        let pid = std::process::id();
        let res = analyze_process_sandbox(pid);
        assert!(
            res.is_ok(),
            "analyze_process_sandbox failed for self pid {}: {:?}",
            pid,
            res.err()
        );
        let info = res.unwrap();

        #[cfg(target_os = "windows")]
        {
            assert!(
                ["Low", "Medium", "High", "System"].contains(&info.integrity_level.as_str()),
                "Unexpected integrity level: {}",
                info.integrity_level
            );
            println!(
                "Self sandbox surface: integrity={}, is_elevated={}, is_app_container={}, privileges={:?}",
                info.integrity_level, info.is_elevated, info.is_app_container, info.privileges
            );
        }

        #[cfg(not(target_os = "windows"))]
        {
            assert_eq!(info.integrity_level, "Medium");
        }
    }

    #[test]
    fn test_analyze_process_sandbox_invalid_pid() {
        // Querying non-existent PID should return Err and never panic
        let res = analyze_process_sandbox(u32::MAX);
        assert!(res.is_err(), "Expected error for invalid PID u32::MAX");

        let res_zero = analyze_process_sandbox(0);
        assert!(res_zero.is_err(), "Expected error for PID 0");
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_parse_risk_privileges_all_targets() {
        use windows::Win32::Foundation::LUID;

        let privs = vec![
            LUID_AND_ATTRIBUTES {
                Luid: LUID { LowPart: 20, HighPart: 0 },
                Attributes: SE_PRIVILEGE_ENABLED,
            },
            LUID_AND_ATTRIBUTES {
                Luid: LUID { LowPart: 29, HighPart: 0 },
                Attributes: SE_PRIVILEGE_ENABLED,
            },
            LUID_AND_ATTRIBUTES {
                Luid: LUID { LowPart: 7, HighPart: 0 },
                Attributes: SE_PRIVILEGE_ENABLED,
            },
            LUID_AND_ATTRIBUTES {
                Luid: LUID { LowPart: 30, HighPart: 0 },
                Attributes: SE_PRIVILEGE_ENABLED,
            },
            LUID_AND_ATTRIBUTES {
                Luid: LUID { LowPart: 99, HighPart: 0 },
                Attributes: SE_PRIVILEGE_ENABLED,
            },
        ];

        let identified = parse_risk_privileges(&privs);
        assert_eq!(
            identified,
            vec![
                "SeDebugPrivilege".to_string(),
                "SeImpersonatePrivilege".to_string(),
                "SeTcbPrivilege".to_string(),
                "SeCreateGlobalPrivilege".to_string(),
            ]
        );
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_parse_risk_privileges_disabled_filtered() {
        use windows::Win32::Foundation::LUID;
        use windows::Win32::Security::TOKEN_PRIVILEGES_ATTRIBUTES;

        let privs = vec![
            LUID_AND_ATTRIBUTES {
                Luid: LUID { LowPart: 20, HighPart: 0 },
                Attributes: TOKEN_PRIVILEGES_ATTRIBUTES(0), // Disabled
            },
            LUID_AND_ATTRIBUTES {
                Luid: LUID { LowPart: 29, HighPart: 0 },
                Attributes: TOKEN_PRIVILEGES_ATTRIBUTES(1), // SE_PRIVILEGE_ENABLED_BY_DEFAULT but not enabled
            },
            LUID_AND_ATTRIBUTES {
                Luid: LUID { LowPart: 7, HighPart: 0 },
                Attributes: SE_PRIVILEGE_ENABLED, // Enabled
            },
        ];

        let identified = parse_risk_privileges(&privs);
        assert_eq!(identified, vec!["SeTcbPrivilege".to_string()]);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_parse_risk_privileges_empty() {
        let identified = parse_risk_privileges(&[]);
        assert!(identified.is_empty());
    }
}
