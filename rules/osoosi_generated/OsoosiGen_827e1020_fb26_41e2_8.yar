rule OsoosiGen_827e1020_fb26_41e2_8
{
    meta:
        description = "Auto-generated from OpenỌ̀ṣọ́ọ̀sì detection"
        confidence = 0.94982636 source_node = "DESKTOP-4MJ7SCN"
    strings:
        $proc = "rustc.exe" ascii wide

    condition:
        $proc
}