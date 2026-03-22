rule OsoosiGen_e262cc30_3f26_4f96_b
{
    meta:
        description = "Auto-generated from OpenỌ̀ṣọ́ọ̀sì detection"
        confidence = 0.9645272 source_node = "ecomplabs002"
    strings:
        $proc = "cargo.exe" ascii wide

    condition:
        $proc
}