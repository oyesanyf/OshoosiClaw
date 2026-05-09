rule OsoosiGen_2eebc0d7_ea1e_48b4_8
{
    meta:
        description = "Auto-generated from OpenỌ̀ṣọ́ọ̀sì detection"
        confidence = 1 source_node = "DESKTOP-4MJ7SCN"
    strings:
        $proc = "HxTsr.exe" ascii wide

    condition:
        $proc
}