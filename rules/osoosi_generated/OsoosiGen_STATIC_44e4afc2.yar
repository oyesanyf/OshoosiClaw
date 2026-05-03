rule OsoosiGen_STATIC_44e4afc2
{
    meta:
        description = "Auto-generated from OpenỌ̀ṣọ́ọ̀sì detection"
        confidence = 0.90000004 source_node = "local"
    strings:
        $proc = "rg.exe" ascii wide
        $h = { 44 E4 AF C2 2F F2 29 24 38 D4 C5 81 23 66 F6 44 48 03 DB 45 3F 80 CD 07 34 E3 E8 37 F1 51 9B BA }

    condition:
        any of them
}