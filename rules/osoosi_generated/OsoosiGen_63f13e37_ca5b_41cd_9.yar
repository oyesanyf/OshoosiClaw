rule OsoosiGen_63f13e37_ca5b_41cd_9
{
    meta:
        description = "Auto-generated from OpenỌ̀ṣọ́ọ̀sì detection"
        confidence = 1 source_node = "DESKTOP-4MJ7SCN"
    strings:
        $proc = "updater.exe" ascii wide

    condition:
        $proc
}