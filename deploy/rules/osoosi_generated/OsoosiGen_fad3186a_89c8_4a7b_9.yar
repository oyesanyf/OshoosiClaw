rule OsoosiGen_fad3186a_89c8_4a7b_9
{
    meta:
        description = "Auto-generated from OpenỌ̀ṣọ́ọ̀sì detection"
        confidence = 1 source_node = "DESKTOP-4MJ7SCN"
    strings:
        $proc = "FileCoAuth.exe" ascii wide

    condition:
        $proc
}