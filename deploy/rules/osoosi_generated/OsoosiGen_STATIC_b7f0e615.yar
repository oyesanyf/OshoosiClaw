rule OsoosiGen_STATIC_b7f0e615
{
    meta:
        description = "Auto-generated from OpenỌ̀ṣọ́ọ̀sì detection"
        confidence = 0.90000004 source_node = "local"
    strings:
        $proc = "git-credential-manager.exe" ascii wide
        $h = { B7 F0 E6 15 35 B7 BA B8 1E A1 11 26 EC F1 E7 AD 44 86 42 6D F6 99 21 A7 8A 68 0D C4 0B AE 2C 12 }

    condition:
        any of them
}