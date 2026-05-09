rule OsoosiGen_7d7606f3_6480_44c2_b
{
    meta:
        description = "Auto-generated from OpenỌ̀ṣọ́ọ̀sì detection"
        confidence = 1 source_node = "DESKTOP-4MJ7SCN"
    strings:
        $proc = "where.exe" ascii wide

    condition:
        $proc
}