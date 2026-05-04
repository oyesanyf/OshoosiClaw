rule OsoosiGen_462b6a5e_aae0_4ff0_a
{
    meta:
        description = "Auto-generated from OpenỌ̀ṣọ́ọ̀sì detection"
        confidence = 0.97930634 source_node = "DESKTOP-4MJ7SCN"
    strings:
        $proc = "git.exe" ascii wide

    condition:
        $proc
}