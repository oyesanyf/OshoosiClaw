rule OsoosiGen_24a7f880_b99d_4df0_8
{
    meta:
        description = "Auto-generated from OpenỌ̀ṣọ́ọ̀sì detection"
        confidence = 0.9902344 source_node = "DESKTOP-4MJ7SCN"
    strings:
        $proc = "python.exe" ascii wide

    condition:
        $proc
}