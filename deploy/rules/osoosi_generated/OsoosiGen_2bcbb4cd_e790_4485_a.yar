rule OsoosiGen_2bcbb4cd_e790_4485_a
{
    meta:
        description = "Auto-generated from OpenỌ̀ṣọ́ọ̀sì detection"
        confidence = 0.9797163 source_node = "DESKTOP-4MJ7SCN"
    strings:
        $proc = "chrome.exe" ascii wide

    condition:
        $proc
}