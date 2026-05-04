rule OsoosiGen_4187c438_7eab_4e8b_a
{
    meta:
        description = "Auto-generated from OpenỌ̀ṣọ́ọ̀sì detection"
        confidence = 1 source_node = "DESKTOP-4MJ7SCN"
    strings:
        $proc = "TrustedInstaller.exe" ascii wide

    condition:
        $proc
}