rule OsoosiGen_69acc61f_9e08_4c75_9
{
    meta:
        description = "Auto-generated from OpenỌ̀ṣọ́ọ̀sì detection"
        confidence = 0.94982636 source_node = "DESKTOP-4MJ7SCN"
    strings:
        $proc = "rustc.exe" ascii wide

    condition:
        $proc
}