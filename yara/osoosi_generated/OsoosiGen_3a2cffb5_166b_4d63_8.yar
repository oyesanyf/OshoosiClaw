rule OsoosiGen_3a2cffb5_166b_4d63_8
{
    meta:
        description = "Auto-generated from OpenỌ̀ṣọ́ọ̀sì detection"
        confidence = 0.83619344 source_node = "ecomplabs002"
    strings:
        $proc = "powershell.exe" ascii wide

    condition:
        $proc
}