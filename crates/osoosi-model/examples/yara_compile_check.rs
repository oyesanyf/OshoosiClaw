//! cargo run -p osoosi-model --example yara_compile_check -- <file.yar>
fn main() {
    let path = std::env::args().nth(1).expect("usage: yara_compile_check <file.yar>");
    let src = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {}", path, e));
    let mut c = yara_x::Compiler::new();
    if let Err(e) = c.add_source(src.as_str()) {
        eprintln!("{}: {}", path, e);
        std::process::exit(1);
    }
    let _ = c.build();
    println!("OK {}", path);
}
