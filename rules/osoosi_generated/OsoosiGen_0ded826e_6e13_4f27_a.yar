rule OsoosiGen_0ded826e_6e13_4f27_a
{
    meta:
        description = "Auto-generated from OpenỌ̀ṣọ́ọ̀sì detection"
        confidence = 0.9 source_node = "DESKTOP-4MJ7SCN"
    strings:
        $proc = "python.exe" ascii wide

    condition:
        $proc
}