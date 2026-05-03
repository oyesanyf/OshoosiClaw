rule OsoosiGen_2c025611_b4ac_4f1c_b
{
    meta:
        description = "Auto-generated from OpenỌ̀ṣọ́ọ̀sì detection"
        confidence = 0.94968975 source_node = "DESKTOP-4MJ7SCN"
    strings:
        $proc = "rustc.exe" ascii wide

    condition:
        $proc
}