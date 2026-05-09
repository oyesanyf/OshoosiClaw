rule OsoosiGen_STATIC_c115a66a
{
    meta:
        description = "Auto-generated from OpenỌ̀ṣọ́ọ̀sì detection"
        confidence = 0.90000004 source_node = "local"
    strings:
        $proc = "git.exe" ascii wide
        $h = { C1 15 A6 6A 1B ED E6 69 4B 51 3A F4 20 CC 90 F8 77 5B E0 36 66 A5 4D 1E CB 82 D6 19 6B 92 9F E9 }

    condition:
        any of them
}