rule OsoosiGen_7e0ae211_f398_4a7e_8
{
    meta:
        description = "Auto-generated from OpenỌ̀ṣọ́ọ̀sì detection"
        confidence = 1 source_node = "DESKTOP-4MJ7SCN"
    strings:
        $proc = "conhost.exe" ascii wide

    condition:
        $proc
}