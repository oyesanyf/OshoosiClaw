rule OsoosiGen_ff0eb35d_3832_4616_b
{
    meta:
        description = "Auto-generated from OpenỌ̀ṣọ́ọ̀sì detection"
        confidence = 1 source_node = "DESKTOP-4MJ7SCN"
    strings:
        $proc = "svchost.exe" ascii wide

    condition:
        $proc
}