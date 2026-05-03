rule OsoosiGen_STATIC_7ca24f26
{
    meta:
        description = "Auto-generated from OpenỌ̀ṣọ́ọ̀sì detection"
        confidence = 0.90000004 source_node = "local"
    strings:
        $proc = "python.exe" ascii wide
        $h = { 7C A2 4F 26 D6 E3 F4 63 41 9E E4 F5 37 DD D3 AC D3 12 C3 8F E4 5E 67 8C CE 08 57 2F 26 A8 BD 1A }

    condition:
        any of them
}