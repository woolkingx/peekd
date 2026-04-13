//! xtask: Build tooling for peekd workspace.
//!
//! Builds peekd-ebpf for bpfel-unknown-none target using cargo.
//! Usage: cargo xtask build-ebpf [--release]

use std::path::PathBuf;
use std::process::Command;

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();

    match args.first().map(|s| s.as_str()) {
        Some("build-ebpf") => build_ebpf(args.contains(&"--release".to_string()))?,
        Some(cmd) => anyhow::bail!("unknown command: {}", cmd),
        None => {
            eprintln!("Usage: cargo xtask build-ebpf [--release]");
            std::process::exit(1);
        }
    }

    Ok(())
}

fn build_ebpf(release: bool) -> anyhow::Result<()> {
    let workspace_root = workspace_root()?;
    let ebpf_dir = workspace_root.join("peekd-ebpf");

    // peekd-ebpf must be built with nightly + bpfel-unknown-none target
    let mut cmd = Command::new("cargo");
    cmd.current_dir(&ebpf_dir);

    // .cargo/config.toml in peekd-ebpf sets target, rustflags (--btf), and build-std
    cmd.arg("+nightly");
    cmd.arg("build");

    if release {
        cmd.arg("--release");
    }

    eprintln!("[xtask] building peekd-ebpf for bpfel-unknown-none");
    let status = cmd.status()?;

    if !status.success() {
        anyhow::bail!("peekd-ebpf build failed");
    }

    // Copy built object to where build.rs expects it
    let profile = if release { "release" } else { "debug" };
    let bpf_obj = ebpf_dir
        .join("target")
        .join("bpfel-unknown-none")
        .join(profile)
        .join("peekd-ebpf");

    let dest = workspace_root.join("target").join("peekd-ebpf.o");
    std::fs::create_dir_all(dest.parent().unwrap())?;
    std::fs::copy(&bpf_obj, &dest)?;

    // Strip .debug_* and .rel.debug_* sections that aya-obj cannot parse.
    // Keep .BTF and .BTF.ext (required for BTF-defined maps).
    let strip_status = Command::new("llvm-strip")
        .args([
            "--strip-debug",
            "--keep-section=.BTF",
            "--keep-section=.BTF.ext",
        ])
        .arg(&dest)
        .status();
    match strip_status {
        Ok(s) if s.success() => eprintln!("[xtask] stripped debug sections (kept .BTF)"),
        Ok(_) => eprintln!("[xtask] warn: llvm-strip failed, using unstripped object"),
        Err(_) => eprintln!("[xtask] warn: llvm-strip not found, using unstripped object"),
    }

    eprintln!("[xtask] BPF object: {} ({}B)", dest.display(), std::fs::metadata(&dest)?.len());
    Ok(())
}

fn workspace_root() -> anyhow::Result<PathBuf> {
    let output = Command::new("cargo")
        .args(["locate-project", "--workspace", "--message-format=plain"])
        .output()?;
    let path = String::from_utf8(output.stdout)?;
    Ok(PathBuf::from(path.trim()).parent().unwrap().to_path_buf())
}
