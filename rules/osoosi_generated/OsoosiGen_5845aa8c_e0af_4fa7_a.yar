rule OsoosiGen_5845aa8c_e0af_4fa7_a
{
    meta:
        description = "Auto-generated from OpenỌ̀ṣọ́ọ̀sì detection"
        confidence = 0.98571384 source_node = "DESKTOP-4MJ7SCN"
    strings:
        $proc = "rg.exe" ascii wide

    condition:
        $proc
}
