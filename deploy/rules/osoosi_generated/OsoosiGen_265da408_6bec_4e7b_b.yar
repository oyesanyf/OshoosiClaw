rule OsoosiGen_265da408_6bec_4e7b_b
{
    meta:
        description = "Auto-generated from OpenỌ̀ṣọ́ọ̀sì detection"
        confidence = 1 source_node = "DESKTOP-4MJ7SCN"
    strings:
        $proc = "TrustedInstaller.exe" ascii wide

    condition:
        $proc
}