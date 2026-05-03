rule OsoosiGen_3dfa187b_263f_4240_8
{
    meta:
        description = "Auto-generated from OpenỌ̀ṣọ́ọ̀sì detection"
        confidence = 0.9 source_node = "DESKTOP-4MJ7SCN"
    strings:
        $proc = "python.exe" ascii wide

    condition:
        $proc
}