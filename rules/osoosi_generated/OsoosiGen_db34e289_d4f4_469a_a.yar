rule OsoosiGen_db34e289_d4f4_469a_a
{
    meta:
        description = "Auto-generated from OpenỌ̀ṣọ́ọ̀sì detection"
        confidence = 1 source_node = "DESKTOP-4MJ7SCN"
    strings:
        $proc = "WMIC.exe" ascii wide

    condition:
        $proc
}