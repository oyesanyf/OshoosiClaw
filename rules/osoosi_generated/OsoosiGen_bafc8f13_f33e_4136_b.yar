rule OsoosiGen_bafc8f13_f33e_4136_b
{
    meta:
        description = "Auto-generated from OpenỌ̀ṣọ́ọ̀sì detection"
        confidence = 0.94982636 source_node = "DESKTOP-4MJ7SCN"
    strings:
        $proc = "rustc.exe" ascii wide

    condition:
        $proc
}