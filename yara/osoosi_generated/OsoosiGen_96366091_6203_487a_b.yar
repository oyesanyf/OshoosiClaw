rule OsoosiGen_96366091_6203_487a_b
{
    meta:
        description = "Auto-generated from OpenỌ̀ṣọ́ọ̀sì detection"
        confidence = 0.8733267 source_node = "ecomplabs002"
    strings:
        $proc = "Antigravity.exe" ascii wide

    condition:
        $proc
}