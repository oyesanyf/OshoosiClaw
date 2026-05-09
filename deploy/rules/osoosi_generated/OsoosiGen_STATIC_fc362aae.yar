rule OsoosiGen_STATIC_fc362aae
{
    meta:
        description = "Auto-generated from OpenỌ̀ṣọ́ọ̀sì detection"
        confidence = 0.90000004 source_node = "local"
    strings:
        $proc = "sh.exe" ascii wide
        $h = { FC 36 2A AE 1F 21 7D 34 D0 22 37 D9 95 27 83 9D D6 CF 85 B3 7C 7A 02 77 10 94 00 BF A0 FA A5 94 }

    condition:
        any of them
}