rule OsoosiGen_1404b3cb_88bf_45f4_8
{
    meta:
        description = "Auto-generated from OpenỌ̀ṣọ́ọ̀sì detection"
        confidence = 0.8631357 source_node = "ecomplabs002"
    strings:
        $proc = "cargo.exe" ascii wide

    condition:
        $proc
}