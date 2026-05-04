rule OsoosiGen_dacebc51_8d04_416a_8
{
    meta:
        description = "Auto-generated from OpenỌ̀ṣọ́ọ̀sì detection"
        confidence = 0.98263824 source_node = "DESKTOP-4MJ7SCN"
    strings:
        $proc = "ollama.exe" ascii wide

    condition:
        $proc
}