rule OsoosiGen_e75d59f4_2650_4267_a
{
    meta:
        description = "Auto-generated from OpenỌ̀ṣọ́ọ̀sì detection"
        confidence = 0.9902344 source_node = "DESKTOP-4MJ7SCN"
    strings:
        $proc = "python.exe" ascii wide

    condition:
        $proc
}