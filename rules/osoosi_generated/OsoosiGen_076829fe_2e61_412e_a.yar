rule OsoosiGen_076829fe_2e61_412e_a
{
    meta:
        description = "Auto-generated from OpenỌ̀ṣọ́ọ̀sì detection"
        confidence = 0.89912117 source_node = "DESKTOP-4MJ7SCN"
    strings:
        $proc = "cargo.exe" ascii wide

    condition:
        $proc
}
