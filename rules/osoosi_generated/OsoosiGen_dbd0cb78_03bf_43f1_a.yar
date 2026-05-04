rule OsoosiGen_dbd0cb78_03bf_43f1_a
{
    meta:
        description = "Auto-generated from OpenỌ̀ṣọ́ọ̀sì detection"
        confidence = 0.875 source_node = "DESKTOP-4MJ7SCN"
    strings:
        $proc = "wermgr.exe" ascii wide

    condition:
        $proc
}