rule OsoosiGen_9184160f_86a9_4bf6_9
{
    meta:
        description = "Auto-generated from OpenỌ̀ṣọ́ọ̀sì detection"
        confidence = 0.98263824 source_node = "DESKTOP-4MJ7SCN"
    strings:
        $proc = "ollama.exe" ascii wide

    condition:
        $proc
}