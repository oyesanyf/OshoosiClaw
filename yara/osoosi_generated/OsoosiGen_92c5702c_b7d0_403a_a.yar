rule OsoosiGen_92c5702c_b7d0_403a_a
{
    meta:
        description = "Auto-generated from OpenỌ̀ṣọ́ọ̀sì detection"
        confidence = 0.8352164 source_node = "ecomplabs002"
    strings:
        $proc = "powershell.exe" ascii wide

    condition:
        $proc
}