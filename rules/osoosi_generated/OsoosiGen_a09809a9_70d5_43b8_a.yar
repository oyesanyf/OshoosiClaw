rule OsoosiGen_a09809a9_70d5_43b8_a
{
    meta:
        description = "Auto-generated from OpenỌ̀ṣọ́ọ̀sì detection"
        confidence = 0.8996234 source_node = "DESKTOP-4MJ7SCN"
    strings:
        $proc = "cargo.exe" ascii wide

    condition:
        $proc
}
