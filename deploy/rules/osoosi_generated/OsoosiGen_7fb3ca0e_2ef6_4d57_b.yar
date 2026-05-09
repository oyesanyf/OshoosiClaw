rule OsoosiGen_7fb3ca0e_2ef6_4d57_b
{
    meta:
        description = "Auto-generated from OpenỌ̀ṣọ́ọ̀sì detection"
        confidence = 0.93999994 source_node = "DESKTOP-4MJ7SCN"
    strings:
        $proc = "vctip.exe" ascii wide

    condition:
        $proc
}