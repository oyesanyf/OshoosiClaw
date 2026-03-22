rule OsoosiGen_18adf128_0069_44e3_a
{
    meta:
        description = "Auto-generated from OpenỌ̀ṣọ́ọ̀sì detection"
        confidence = 0.8758514 source_node = "ecomplabs002"
    strings:
        $proc = "powershell.exe" ascii wide

    condition:
        $proc
}