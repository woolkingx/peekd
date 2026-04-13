use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    // Look for BPF object in multiple locations:
    // 1. BPF_OBJ env var (explicit override)
    // 2. target/peekd-ebpf.o (built by cargo xtask build-ebpf)
    // 3. Fallback: empty placeholder (will fail at runtime)

    let workspace_root = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap())
        .parent()
        .unwrap()
        .to_path_buf();

    let bpf_path = if let Ok(path) = env::var("BPF_OBJ") {
        PathBuf::from(path)
    } else {
        let xtask_path = workspace_root.join("target").join("peekd-ebpf.o");
        if xtask_path.exists() {
            xtask_path
        } else {
            // Create placeholder — will fail at Ebpf::load() runtime
            let out_dir = env::var("OUT_DIR").unwrap();
            let placeholder = PathBuf::from(&out_dir).join("peekd-ebpf");
            if !placeholder.exists() {
                eprintln!("cargo:warning=BPF object not found. Run `cargo xtask build-ebpf` first.");
                let _ = fs::write(&placeholder, b"");
            }
            placeholder
        }
    };

    println!("cargo:rustc-env=BPF_PATH={}", bpf_path.display());
    println!("cargo:rerun-if-env-changed=BPF_OBJ");
    println!("cargo:rerun-if-changed={}", bpf_path.display());
}
