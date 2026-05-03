rule OsoosiGen_6c8da7bc_7343_4f23_8
{
    meta:
        description = "Auto-generated from OpenỌ̀ṣọ́ọ̀sì detection"
        confidence = 0.98404574 source_node = "DESKTOP-4MJ7SCN"
    strings:
        $proc = "ollama.exe" ascii wide

    condition:
        $proc
}
