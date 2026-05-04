rule OsoosiGen_4bc0a872_45cd_413b_b
{
    meta:
        description = "Auto-generated from OpenỌ̀ṣọ́ọ̀sì detection"
        confidence = 1 source_node = "DESKTOP-4MJ7SCN"
    strings:
        $proc = "TiWorker.exe" ascii wide

    condition:
        $proc
}