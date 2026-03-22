rule OsoosiGen_ba1a6e8f_0360_443e_b
{
    meta:
        description = "Auto-generated from OpenỌ̀ṣọ́ọ̀sì detection"
        confidence = 1 source_node = "ecomplabs002"
    strings:
        $proc = "cargo.exe" ascii wide

    condition:
        $proc
}