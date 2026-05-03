rule OsoosiGen_4ec3eedc_1898_4a87_8
{
    meta:
        description = "Auto-generated from OpenỌ̀ṣọ́ọ̀sì detection"
        confidence = 0.8993603 source_node = "DESKTOP-4MJ7SCN"
    strings:
        $proc = "cargo.exe" ascii wide

    condition:
        $proc
}
