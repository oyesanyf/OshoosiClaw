rule OsoosiGen_096e4c0c_9fa7_4831_9
{
    meta:
        description = "Auto-generated from OpenỌ̀ṣọ́ọ̀sì detection"
        confidence = 1 source_node = "ecomplabs002"
    strings:
        $proc = "FileCoAuth.exe" ascii wide

    condition:
        $proc
}