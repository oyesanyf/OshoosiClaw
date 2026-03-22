rule osoosi_ransomware_keywords
{
    meta:
        author = "OpenỌ̀ṣọ́ọ̀sì"
        category = "ransomware"
        severity = "high"
    strings:
        $s1 = "encrypt" nocase
        $s2 = "decrypt" nocase
        $s3 = "ransom" nocase
        $s4 = "bitcoin" nocase
        $s5 = "DECRYPT_INSTRUCTION" nocase
        $s6 = ".encrypted" nocase
        $s7 = ".onion" nocase
    condition:
        3 of them
}

rule osoosi_trojan_injection_keywords
{
    meta:
        author = "OpenỌ̀ṣọ́ọ̀sì"
        category = "trojan"
        severity = "high"
    strings:
        $t1 = "backdoor" nocase
        $t2 = "keylog" nocase
        $t3 = "reverse_shell" nocase
        $t4 = "VirtualAllocEx" nocase
        $t5 = "WriteProcessMemory" nocase
        $t6 = "CreateRemoteThread" nocase
        $t7 = "NtCreateThreadEx" nocase
    condition:
        2 of ($t1,$t2,$t3) or 2 of ($t4,$t5,$t6,$t7)
}

rule osoosi_worm_propagation_keywords
{
    meta:
        author = "OpenỌ̀ṣọ́ọ̀sì"
        category = "worm"
        severity = "medium"
    strings:
        $w1 = "propagat" nocase
        $w2 = "self-replicat" nocase
        $w3 = "spread" nocase
        $w4 = "autorun.inf" nocase
        $w5 = "network_share" nocase
    condition:
        2 of them
}

rule osoosi_spyware_surveillance_keywords
{
    meta:
        author = "OpenỌ̀ṣọ́ọ̀sì"
        category = "spyware"
        severity = "medium"
    strings:
        $s1 = "surveillance" nocase
        $s2 = "keylog" nocase
        $s3 = "clipboard" nocase
        $s4 = "screenshot" nocase
        $s5 = "monitor" nocase
    condition:
        2 of them
}

rule osoosi_anti_vm_or_debug
{
    meta:
        author = "OpenỌ̀ṣọ́ọ̀sì"
        category = "evasion"
        severity = "medium"
    strings:
        $v1 = "vmware" nocase
        $v2 = "virtualbox" nocase
        $v3 = "qemu" nocase
        $d1 = "IsDebuggerPresent" ascii
        $d2 = "CheckRemoteDebuggerPresent" ascii
        $d3 = "NtQueryInformationProcess" ascii
    condition:
        any of them
}

rule osoosi_packer_or_shellcode_markers
{
    meta:
        author = "OpenỌ̀ṣọ́ọ̀sì"
        category = "packer_shellcode"
        severity = "high"
    strings:
        $p1 = "UPX" ascii
        $p2 = "Themida" ascii
        $p3 = "VMProtect" ascii
        $sc1 = { FC E8 ?? ?? ?? ?? }
        $sc2 = { 90 90 90 90 }
    condition:
        any of them
}
