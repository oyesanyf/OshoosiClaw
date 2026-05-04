rule OsoosiGen_a5ae5df1_805c_4909_b
{
    meta:
        description = "Auto-generated from OpenỌ̀ṣọ́ọ̀sì detection"
        confidence = 1 source_node = "DESKTOP-4MJ7SCN"
    strings:
        $proc = "HxTsr.exe" ascii wide

    condition:
        $proc
}