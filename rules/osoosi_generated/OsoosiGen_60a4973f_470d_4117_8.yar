rule OsoosiGen_60a4973f_470d_4117_8
{
    meta:
        description = "Auto-generated from OpenỌ̀ṣọ́ọ̀sì detection"
        confidence = 0.9797163 source_node = "DESKTOP-4MJ7SCN"
    strings:
        $proc = "chrome.exe" ascii wide

    condition:
        $proc
}