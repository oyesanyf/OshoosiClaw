rule OsoosiGen_f4a53114_874a_4ed7_a
{
    meta:
        description = "Auto-generated from OpenỌ̀ṣọ́ọ̀sì detection"
        confidence = 0.8151452 source_node = "ecomplabs002"
    strings:
        $proc = "powershell.exe" ascii wide

    condition:
        $proc
}