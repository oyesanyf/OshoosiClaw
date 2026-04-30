use std::process::Command;

fn main() {
    // Only run this if we are in a git repository
    if std::path::Path::new("../../.git").exists() || std::path::Path::new(".git").exists() {
        println!("cargo:warning=Updating git submodules...");
        let status = Command::new("git")
            .args(&["submodule", "update", "--init", "--recursive"])
            .current_dir("../../") // Root of the workspace
            .status();

        match status {
            Ok(s) if s.success() => {
                println!("cargo:warning=Git submodules updated successfully.");
            }
            Ok(s) => {
                println!("cargo:warning=Git submodule update failed with status: {}", s);
            }
            Err(e) => {
                println!("cargo:warning=Failed to execute git command: {}. If you are not in a git repo, you can ignore this.", e);
            }
        }
    }
    
    // Tell Cargo to rerun this script if .gitmodules changes
    println!("cargo:rerun-if-changed=../../.gitmodules");
}
