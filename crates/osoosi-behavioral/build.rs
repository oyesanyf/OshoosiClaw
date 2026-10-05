fn main() {
    // Submodules are optional and managed out-of-band; avoid blocking offline/air-gapped builds
    println!("cargo:rerun-if-changed=../../.gitmodules");
}
