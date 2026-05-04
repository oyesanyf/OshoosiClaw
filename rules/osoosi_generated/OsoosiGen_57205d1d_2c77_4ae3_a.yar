rule OsoosiGen_57205d1d_2c77_4ae3_a
{
    meta:
        description = "Auto-generated from OpenỌ̀ṣọ́ọ̀sì detection"
        confidence = 1 source_node = "DESKTOP-4MJ7SCN"
    strings:
        $proc = "updater.exe" ascii wide

    condition:
        $proc
}