rule OsoosiGen_6af71904_d379_4387_a
{
    meta:
        description = "Auto-generated from OpenỌ̀ṣọ́ọ̀sì detection"
        confidence = 0.9666889 source_node = "ecomplabs002"
    strings:
        $proc = "Antigravity.exe" ascii wide

    condition:
        $proc
}