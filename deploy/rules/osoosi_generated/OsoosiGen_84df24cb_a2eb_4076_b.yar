rule OsoosiGen_84df24cb_a2eb_4076_b
{
    meta:
        description = "Auto-generated from OpenỌ̀ṣọ́ọ̀sì detection"
        confidence = 0.97930634 source_node = "DESKTOP-4MJ7SCN"
    strings:
        $proc = "git.exe" ascii wide

    condition:
        $proc
}