rule OsoosiGen_11b71c49_34cd_4736_a
{
    meta:
        description = "Auto-generated from OpenỌ̀ṣọ́ọ̀sì detection"
        confidence = 1 source_node = "DESKTOP-4MJ7SCN"
    strings:
        $proc = "FileCoAuth.exe" ascii wide

    condition:
        $proc
}