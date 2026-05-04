rule OsoosiGen_16275864_2613_467c_9
{
    meta:
        description = "Auto-generated from OpenỌ̀ṣọ́ọ̀sì detection"
        confidence = 1 source_node = "DESKTOP-4MJ7SCN"
    strings:
        $proc = "TrustedInstaller.exe" ascii wide

    condition:
        $proc
}