rule OsoosiGen_8504bf38_1d0a_4927_a
{
    meta:
        description = "Auto-generated from OpenỌ̀ṣọ́ọ̀sì detection"
        confidence = 1 source_node = "ecomplabs002"
    strings:
        $proc = "FileCoAuth.exe" ascii wide

    condition:
        $proc
}