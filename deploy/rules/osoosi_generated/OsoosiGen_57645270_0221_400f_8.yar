rule OsoosiGen_57645270_0221_400f_8
{
    meta:
        description = "Auto-generated from OpenỌ̀ṣọ́ọ̀sì detection"
        confidence = 1 source_node = "DESKTOP-4MJ7SCN"
    strings:
        $proc = "updater.exe" ascii wide

    condition:
        $proc
}