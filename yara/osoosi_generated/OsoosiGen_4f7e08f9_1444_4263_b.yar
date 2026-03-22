rule OsoosiGen_4f7e08f9_1444_4263_b
{
    meta:
        description = "Auto-generated from OpenỌ̀ṣọ́ọ̀sì detection"
        confidence = 1 source_node = "ecomplabs002"
    strings:
        $proc = "language_server_windows_x64.exe" ascii wide

    condition:
        $proc
}