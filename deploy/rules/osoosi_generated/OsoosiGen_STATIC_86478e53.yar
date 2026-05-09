rule OsoosiGen_STATIC_86478e53
{
    meta:
        description = "Auto-generated from OpenỌ̀ṣọ́ọ̀sì detection"
        confidence = 0.90000004 source_node = "local"
    strings:
        $proc = "cargo.exe" ascii wide
        $h = { 86 47 8E 53 F7 69 37 9D 7F 0E BF A7 C9 AA 97 CB 76 CA 92 23 3F 79 AA 2C C0 DB EE 2E FA AC 73 C7 }

    condition:
        any of them
}