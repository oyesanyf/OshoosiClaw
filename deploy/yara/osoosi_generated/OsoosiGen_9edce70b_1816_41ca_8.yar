rule OsoosiGen_9edce70b_1816_41ca_8
{
    meta:
        description = "Auto-generated from OpenỌ̀ṣọ́ọ̀sì detection"
        confidence = 1 source_node = "ecomplabs002"
    strings:
        $proc = "GoogleDriveFS.exe" ascii wide

    condition:
        $proc
}