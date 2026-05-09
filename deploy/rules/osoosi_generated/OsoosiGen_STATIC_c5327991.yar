rule OsoosiGen_STATIC_c5327991
{
    meta:
        description = "Auto-generated from OpenỌ̀ṣọ́ọ̀sì detection"
        confidence = 0.90000004 source_node = "local"
    strings:
        $proc = "git.exe" ascii wide
        $h = { C5 32 79 91 9F DE A0 34 74 BB 23 B4 65 B3 A8 22 87 15 74 91 F1 BD 69 A5 EB 82 DD 98 31 58 23 33 }

    condition:
        any of them
}