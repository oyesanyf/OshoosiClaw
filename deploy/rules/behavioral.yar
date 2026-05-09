/*
    OshoosiClaw Behavioral Detection Rules (YARA-X)
    ----------------------------------------------
    These rules are matched against the serialized JSON representation of Sysmon events
    ingested via Native ETW. This replaces the legacy Hayabusa/Sigma engine.
*/

rule Suspicious_LSASS_Dump {
    meta:
        description = "Detects LSASS memory dumping via comsvcs.dll or rundll32"
        severity = "Critical"
    strings:
        $lsass = "lsass" nocase
        $comsvcs = "comsvcs.dll" nocase
        $minidump = "MiniDump" nocase
    condition:
        all of them
}

rule PowerShell_Download_Cradle {
    meta:
        description = "Detects PowerShell web-based download cradles"
        severity = "High"
    strings:
        $ps = "powershell" nocase
        $client = "Net.WebClient" nocase
        $download = "DownloadString" nocase
        $iwr = "Invoke-WebRequest" nocase
    condition:
        $ps and ($client and $download or $iwr)
}

rule Ransomware_Shadow_Copy_Deletion {
    meta:
        description = "Detects deletion of volume shadow copies via vssadmin or wmic"
        severity = "Critical"
    strings:
        $vss = "vssadmin" nocase
        $wmic = "wmic" nocase
        $shadow = "shadowcopy" nocase
        $delete = "delete" nocase
    condition:
        ($vss or $wmic) and $shadow and $delete
}

rule Lateral_Movement_WMI_Exec {
    meta:
        description = "Detects remote process execution via WMI"
        severity = "High"
    strings:
        $wmic = "wmic" nocase
        $node = "/node:" nocase
        $process = "process" nocase
        $call = "call" nocase
        $create = "create" nocase
    condition:
        $wmic and $node and $process and $call and $create
}

rule StickyKeys_Backdoor_Creation {
    meta:
        description = "Detects creation of the Sticky Keys debugger backdoor"
        severity = "Critical"
    strings:
        $sethc = "sethc.exe" nocase
        $utilman = "utilman.exe" nocase
        $imagefile = "Image File Execution Options" nocase
        $debugger = "debugger" nocase
    condition:
        ($sethc or $utilman) and $imagefile and $debugger
}
