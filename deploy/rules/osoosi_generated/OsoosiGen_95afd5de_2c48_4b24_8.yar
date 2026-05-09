rule OsoosiGen_95afd5de_2c48_4b24_8
{
    meta:
        description = "Auto-generated from OpenỌ̀ṣọ́ọ̀sì detection"
        confidence = 0.97930634 source_node = "DESKTOP-4MJ7SCN"
    strings:
        $proc = "git.exe" ascii wide

    condition:
        $proc
}