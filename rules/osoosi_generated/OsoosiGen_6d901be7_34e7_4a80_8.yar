rule OsoosiGen_6d901be7_34e7_4a80_8
{
    meta:
        description = "Auto-generated from OpenỌ̀ṣọ́ọ̀sì detection"
        confidence = 1 source_node = "DESKTOP-4MJ7SCN"
    strings:
        $proc = "HxTsr.exe" ascii wide

    condition:
        $proc
}