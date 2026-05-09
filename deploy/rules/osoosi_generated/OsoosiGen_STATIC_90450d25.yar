rule OsoosiGen_STATIC_90450d25
{
    meta:
        description = "Auto-generated from OpenỌ̀ṣọ́ọ̀sì detection"
        confidence = 0.90000004 source_node = "local"
    strings:
        $proc = "git-remote-https.exe" ascii wide
        $h = { 90 45 0D 25 F9 40 C1 58 65 B5 B3 3D 76 34 63 02 27 CE 93 69 3E 67 D9 32 7B E6 D6 67 D4 18 17 F2 }

    condition:
        any of them
}