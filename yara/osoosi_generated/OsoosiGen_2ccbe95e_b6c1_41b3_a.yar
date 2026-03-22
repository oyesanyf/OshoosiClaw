rule OsoosiGen_2ccbe95e_b6c1_41b3_a
{
    meta:
        description = "Auto-generated from OpenỌ̀ṣọ́ọ̀sì detection"
        confidence = 1 source_node = "ecomplabs002"
    strings:
        $proc = "language_server_windows_x64.exe" ascii wide

    condition:
        $proc
}