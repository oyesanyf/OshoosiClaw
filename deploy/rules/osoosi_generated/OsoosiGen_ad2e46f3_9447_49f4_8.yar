rule OsoosiGen_ad2e46f3_9447_49f4_8
{
    meta:
        description = "Auto-generated from OpenỌ̀ṣọ́ọ̀sì detection"
        confidence = 1 source_node = "DESKTOP-4MJ7SCN"
    strings:
        $proc = "TrustedInstaller.exe" ascii wide

    condition:
        $proc
}