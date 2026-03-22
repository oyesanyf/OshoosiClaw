rule OsoosiGen_9812245d_7adb_4326_9
{
    meta:
        description = "Auto-generated from OpenỌ̀ṣọ́ọ̀sì detection"
        confidence = 1 source_node = "ecomplabs002"
    strings:
        $proc = "language_server_windows_x64.exe" ascii wide

    condition:
        $proc
}