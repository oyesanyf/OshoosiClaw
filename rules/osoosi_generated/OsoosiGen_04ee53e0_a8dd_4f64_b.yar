rule OsoosiGen_04ee53e0_a8dd_4f64_b
{
    meta:
        description = "Auto-generated from OpenỌ̀ṣọ́ọ̀sì detection"
        confidence = 1 source_node = "DESKTOP-4MJ7SCN"
    strings:
        $proc = "WmiPrvSE.exe" ascii wide

    condition:
        $proc
}