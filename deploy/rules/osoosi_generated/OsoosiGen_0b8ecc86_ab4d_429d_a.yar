rule OsoosiGen_0b8ecc86_ab4d_429d_a
{
    meta:
        description = "Auto-generated from OpenỌ̀ṣọ́ọ̀sì detection"
        confidence = 1 source_node = "DESKTOP-4MJ7SCN"
    strings:
        $proc = "Sysmon64.exe" ascii wide

    condition:
        $proc
}