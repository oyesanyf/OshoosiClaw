rule OsoosiGen_d5c791bd_1981_4910_b
{
    meta:
        description = "Auto-generated from OpenỌ̀ṣọ́ọ̀sì detection"
        confidence = 1 source_node = "DESKTOP-4MJ7SCN"
    strings:
        $proc = "conhost.exe" ascii wide

    condition:
        $proc
}