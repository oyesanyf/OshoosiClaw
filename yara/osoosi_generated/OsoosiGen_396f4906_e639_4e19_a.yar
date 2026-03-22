rule OsoosiGen_396f4906_e639_4e19_a
{
    meta:
        description = "Auto-generated from OpenỌ̀ṣọ́ọ̀sì detection"
        confidence = 1 source_node = "ecomplabs002"
    strings:
        $proc = "Antigravity.exe" ascii wide

    condition:
        $proc
}