rule OsoosiGen_STATIC_e3ebbd54
{
    meta:
        description = "Auto-generated from OpenỌ̀ṣọ́ọ̀sì detection"
        confidence = 0.95 source_node = "local"
    strings:
        $proc = "rustc.exe" ascii wide
        $h = { E3 EB BD 54 7E A7 B7 3C 03 4D 58 8B A5 69 60 2B 37 9F 3B 05 AD 1A 3B 5F 8D CF AB 9D 44 78 D7 4A }

    condition:
        any of them
}