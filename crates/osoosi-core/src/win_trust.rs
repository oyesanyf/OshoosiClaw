pub fn verify_file_signature(path: &str) -> bool {
    osoosi_types::verify_file_signature(path)
}

pub fn is_trusted_signed_binary(path: &std::path::Path) -> bool {
    osoosi_types::is_trusted_signed_binary(path)
}

pub fn is_trusted_vendor(name: &str) -> bool {
    osoosi_types::is_trusted_vendor(name)
}
