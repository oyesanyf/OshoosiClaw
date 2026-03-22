rule OsoosiGen_681363bc_3943_442b_b
{
    meta:
        description = "Auto-generated from OpenỌ̀ṣọ́ọ̀sì detection"
        confidence = 0.9645272 source_node = "ecomplabs002"
    strings:
        $proc = "cargo.exe" ascii wide

    condition:
        $proc
}