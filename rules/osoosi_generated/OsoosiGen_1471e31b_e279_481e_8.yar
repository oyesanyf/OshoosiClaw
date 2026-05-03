rule OsoosiGen_1471e31b_e279_481e_8
{
    meta:
        description = "Auto-generated from OpenỌ̀ṣọ́ọ̀sì detection"
        confidence = 0.98571384 source_node = "DESKTOP-4MJ7SCN"
    strings:
        $proc = "rg.exe" ascii wide

    condition:
        $proc
}
