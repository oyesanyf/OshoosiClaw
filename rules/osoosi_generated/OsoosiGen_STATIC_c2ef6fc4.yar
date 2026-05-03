rule OsoosiGen_STATIC_c2ef6fc4
{
    meta:
        description = "Auto-generated from OpenỌ̀ṣọ́ọ̀sì detection"
        confidence = 0.90000004 source_node = "local"
    strings:
        $proc = "grep.exe" ascii wide
        $h = { C2 EF 6F C4 19 63 0D 56 61 54 F8 37 2E 94 85 9D F8 14 1D 02 80 5B C7 BC E3 9C 72 6A 1F FE F7 C1 }

    condition:
        any of them
}