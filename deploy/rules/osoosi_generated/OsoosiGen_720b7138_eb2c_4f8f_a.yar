rule OsoosiGen_720b7138_eb2c_4f8f_a
{
    meta:
        description = "Auto-generated from OpenỌ̀ṣọ́ọ̀sì detection"
        confidence = 1 source_node = "DESKTOP-4MJ7SCN"
    strings:
        $proc = "TiWorker.exe" ascii wide

    condition:
        $proc
}