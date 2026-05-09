rule OsoosiGen_8a40829a_5447_4703_9
{
    meta:
        description = "Auto-generated from OpenỌ̀ṣọ́ọ̀sì detection"
        confidence = 1 source_node = "DESKTOP-4MJ7SCN"
    strings:
        $proc = "where.exe" ascii wide

    condition:
        $proc
}