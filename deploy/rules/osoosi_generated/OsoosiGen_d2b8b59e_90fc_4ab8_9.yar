rule OsoosiGen_d2b8b59e_90fc_4ab8_9
{
    meta:
        description = "Auto-generated from OpenỌ̀ṣọ́ọ̀sì detection"
        confidence = 0.9797163 source_node = "DESKTOP-4MJ7SCN"
    strings:
        $proc = "chrome.exe" ascii wide

    condition:
        $proc
}