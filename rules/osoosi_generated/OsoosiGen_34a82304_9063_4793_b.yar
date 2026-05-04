rule OsoosiGen_34a82304_9063_4793_b
{
    meta:
        description = "Auto-generated from OpenỌ̀ṣọ́ọ̀sì detection"
        confidence = 1 source_node = "DESKTOP-4MJ7SCN"
    strings:
        $proc = "TiWorker.exe" ascii wide

    condition:
        $proc
}