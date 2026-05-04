rule OsoosiGen_98bc4d82_4523_4ffd_9
{
    meta:
        description = "Auto-generated from OpenỌ̀ṣọ́ọ̀sì detection"
        confidence = 0.98265815 source_node = "DESKTOP-4MJ7SCN"
    strings:
        $proc = "ollama.exe" ascii wide

    condition:
        $proc
}