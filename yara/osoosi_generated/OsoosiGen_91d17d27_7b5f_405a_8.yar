rule OsoosiGen_91d17d27_7b5f_405a_8
{
    meta:
        description = "Auto-generated from OpenỌ̀ṣọ́ọ̀sì detection"
        confidence = 0.92354214 source_node = "ecomplabs002"
    strings:
        $proc = "Antigravity.exe" ascii wide

    condition:
        $proc
}