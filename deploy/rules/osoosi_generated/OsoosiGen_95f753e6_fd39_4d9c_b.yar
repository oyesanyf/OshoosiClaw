rule OsoosiGen_95f753e6_fd39_4d9c_b
{
    meta:
        description = "Auto-generated from OpenỌ̀ṣọ́ọ̀sì detection"
        confidence = 1 source_node = "DESKTOP-4MJ7SCN"
    strings:
        $proc = "netsh.exe" ascii wide

    condition:
        $proc
}