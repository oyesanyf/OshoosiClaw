fn main() {
    let channel = "Microsoft-Windows-Sysmon/Operational";
    let query = "*[System[TimeCreated[timediff(@SystemTime) <= 600000]]]";
    let output = std::process::Command::new("wevtutil")
        .args([
            "qe",
            channel,
            "/rd:false",
            "/e:root",
            "/c:1",
            "/f:xml",
            &format!("/q:\"{}\"", query),
        ])
        .output()
        .expect("Failed to execute wevtutil");

    println!("Status: {}", output.status);
    println!("Stdout len: {}", output.stdout.len());
    println!("Stderr: {}", String::from_utf8_lossy(&output.stderr));
}
