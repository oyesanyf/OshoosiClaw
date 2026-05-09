rule OsoosiGen_371cd1f8_2d70_468a_8
{
    meta:
        description = "Auto-generated from OpenỌ̀ṣọ́ọ̀sì detection"
        confidence = 1 source_node = "DESKTOP-4MJ7SCN"
    strings:
        $proc = "updater.exe" ascii wide

    condition:
        $proc
}