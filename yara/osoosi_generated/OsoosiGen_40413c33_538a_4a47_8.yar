rule OsoosiGen_40413c33_538a_4a47_8
{
    meta:
        description = "Auto-generated from OpenỌ̀ṣọ́ọ̀sì detection"
        confidence = 1 source_node = "ecomplabs002"
    strings:
        $proc = "Antigravity.exe" ascii wide

    condition:
        $proc
}