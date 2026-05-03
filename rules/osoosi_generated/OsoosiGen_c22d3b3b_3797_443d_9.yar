rule OsoosiGen_c22d3b3b_3797_443d_9
{
    meta:
        description = "Auto-generated from OpenỌ̀ṣọ́ọ̀sì detection"
        confidence = 0.89960515 source_node = "DESKTOP-4MJ7SCN"
    strings:
        $proc = "cargo.exe" ascii wide

    condition:
        $proc
}