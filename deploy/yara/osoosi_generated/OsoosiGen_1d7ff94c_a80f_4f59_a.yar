rule OsoosiGen_1d7ff94c_a80f_4f59_a
{
    meta:
        description = "Auto-generated from OpenỌ̀ṣọ́ọ̀sì detection"
        confidence = 1 source_node = "ecomplabs002"
    strings:
        $proc = "osoosi.exe" ascii wide

    condition:
        $proc
}