rule OsoosiGen_23a29b21_9303_4c11_b
{
    meta:
        description = "Auto-generated from OpenỌ̀ṣọ́ọ̀sì detection"
        confidence = 0.8631357 source_node = "ecomplabs002"
    strings:
        $proc = "cargo.exe" ascii wide

    condition:
        $proc
}