rule OsoosiGen_88cdaa22_2f16_4efb_9
{
    meta:
        description = "Auto-generated from OpenỌ̀ṣọ́ọ̀sì detection"
        confidence = 1 source_node = "DESKTOP-4MJ7SCN"
    strings:
        $proc = "WMIC.exe" ascii wide

    condition:
        $proc
}