rule OsoosiGen_3af69808_6d1d_49f9_a
{
    meta:
        description = "Auto-generated from OpenỌ̀ṣọ́ọ̀sì detection"
        confidence = 0.89924073 source_node = "DESKTOP-4MJ7SCN"
    strings:
        $proc = "cargo.exe" ascii wide

    condition:
        $proc
}
