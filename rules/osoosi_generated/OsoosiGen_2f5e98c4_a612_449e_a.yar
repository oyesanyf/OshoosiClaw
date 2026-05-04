rule OsoosiGen_2f5e98c4_a612_449e_a
{
    meta:
        description = "Auto-generated from OpenỌ̀ṣọ́ọ̀sì detection"
        confidence = 1 source_node = "DESKTOP-4MJ7SCN"
    strings:
        $proc = "where.exe" ascii wide

    condition:
        $proc
}