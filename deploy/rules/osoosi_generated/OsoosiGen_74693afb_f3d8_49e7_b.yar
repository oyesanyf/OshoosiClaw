rule OsoosiGen_74693afb_f3d8_49e7_b
{
    meta:
        description = "Auto-generated from OpenỌ̀ṣọ́ọ̀sì detection"
        confidence = 1 source_node = "DESKTOP-4MJ7SCN"
    strings:
        $proc = "FileCoAuth.exe" ascii wide

    condition:
        $proc
}