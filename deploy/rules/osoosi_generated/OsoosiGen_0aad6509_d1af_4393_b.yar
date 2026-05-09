rule OsoosiGen_0aad6509_d1af_4393_b
{
    meta:
        description = "Auto-generated from OpenỌ̀ṣọ́ọ̀sì detection"
        confidence = 1 source_node = "DESKTOP-4MJ7SCN"
    strings:
        $proc = "TiWorker.exe" ascii wide

    condition:
        $proc
}