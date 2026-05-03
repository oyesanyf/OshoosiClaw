rule OsoosiGen_b5f0db69_c955_44fd_b
{
    meta:
        description = "Auto-generated from OpenỌ̀ṣọ́ọ̀sì detection"
        confidence = 0.94968975 source_node = "DESKTOP-4MJ7SCN"
    strings:
        $proc = "rustc.exe" ascii wide

    condition:
        $proc
}