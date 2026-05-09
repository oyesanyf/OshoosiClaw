rule OsoosiGen_e466f69d_8eff_4bce_8
{
    meta:
        description = "Auto-generated from OpenỌ̀ṣọ́ọ̀sì detection"
        confidence = 0.875 source_node = "DESKTOP-4MJ7SCN"
    strings:
        $proc = "wermgr.exe" ascii wide

    condition:
        $proc
}