rule OsoosiGen_STATIC_c99bbd69
{
    meta:
        description = "Auto-generated from OpenỌ̀ṣọ́ọ̀sì detection"
        confidence = 0.90000004 source_node = "local"
    strings:
        $proc = "FileCoAuth.exe" ascii wide
        $h = { C9 9B BD 69 05 8F 91 5C 93 AB 06 C7 22 8E 39 C8 1A 36 BA 97 1D 4F CD 66 46 9A 99 92 8A D8 9F F8 }

    condition:
        any of them
}
