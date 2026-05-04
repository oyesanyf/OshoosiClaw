rule OsoosiGen_8f8068e0_e0c7_42b0_9
{
    meta:
        description = "Auto-generated from OpenỌ̀ṣọ́ọ̀sì detection"
        confidence = 1 source_node = "DESKTOP-4MJ7SCN"
    strings:
        $proc = "conhost.exe" ascii wide

    condition:
        $proc
}