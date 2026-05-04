rule OsoosiGen_e7fb3351_a083_45af_9
{
    meta:
        description = "Auto-generated from OpenỌ̀ṣọ́ọ̀sì detection"
        confidence = 1 source_node = "DESKTOP-4MJ7SCN"
    strings:
        $proc = "FileCoAuth.exe" ascii wide

    condition:
        $proc
}