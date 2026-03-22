rule OsoosiGen_97926498_1e7b_481b_9
{
    meta:
        description = "Auto-generated from OpenỌ̀ṣọ́ọ̀sì detection"
        confidence = 0.85709965 source_node = "ecomplabs002"
    strings:
        $proc = "powershell.exe" ascii wide

    condition:
        $proc
}