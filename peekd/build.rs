use std::env;
use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use libbpf_cargo::SkeletonBuilder;

const BPF_SRC: &str = "src/bpf/peekd.bpf.c";
const BPF_HEADER: &str = "src/bpf/peekd.h";

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let workspace_root = manifest_dir.parent().unwrap().to_path_buf();
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let skel_path = out_dir.join("peekd.skel.rs");
    let obj_path = workspace_root
        .join("target")
        .join("bpf")
        .join("peekd.bpf.o");
    let release = env::var("PROFILE").is_ok_and(|profile| profile == "release");

    fs::create_dir_all(obj_path.parent().unwrap()).unwrap();

    let arch = env::var("CARGO_CFG_TARGET_ARCH")
        .expect("CARGO_CFG_TARGET_ARCH must be set in build script");

    let mut builder = SkeletonBuilder::new();
    builder
        .source(BPF_SRC)
        .obj(&obj_path)
        .reference_obj(true)
        .clang_args([
            OsStr::new("-I"),
            vmlinux::include_path_root().join(arch).as_os_str(),
            OsStr::new("-I"),
            manifest_dir.join("src").join("bpf").as_os_str(),
        ]);

    if let Ok(clang) = env::var("CLANG") {
        builder.clang(clang);
    }

    builder
        .build_and_generate(&skel_path)
        .unwrap_or_else(|err| panic!("failed to build libbpf skeleton from {BPF_SRC}: {err}"));

    if release {
        validate_release_bpf_object(&workspace_root, &obj_path);
    }

    println!("cargo:rustc-env=PEEKD_BPF_SKEL={}", skel_path.display());
    println!("cargo:rustc-env=PEEKD_BPF_OBJ={}", obj_path.display());
    println!("cargo:rerun-if-env-changed=CLANG");
    println!("cargo:rerun-if-changed={BPF_SRC}");
    println!("cargo:rerun-if-changed={BPF_HEADER}");
    println!("cargo:rerun-if-changed=../peekd-common/src");
    println!("cargo:rerun-if-changed=../peekd-common/Cargo.toml");
}

fn validate_release_bpf_object(workspace_root: &Path, bpf_path: &Path) {
    let metadata = fs::metadata(bpf_path).unwrap_or_else(|_| {
        panic!(
            "release build requires libbpf eBPF object at {}; run `cargo build --release -p peekd`",
            bpf_path.display()
        )
    });
    if metadata.len() == 0 {
        panic!(
            "release build refuses empty libbpf eBPF object at {}; rebuild with `cargo build --release -p peekd`",
            bpf_path.display()
        );
    }
    let object_mtime = metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH);
    if is_stale(workspace_root, object_mtime) {
        panic!(
            "release build refuses stale libbpf eBPF object at {}; rebuild with `cargo build --release -p peekd`",
            bpf_path.display()
        );
    }
}

fn is_stale(workspace_root: &Path, object_mtime: SystemTime) -> bool {
    let paths = [
        "peekd/src/bpf/peekd.bpf.c",
        "peekd/src/bpf/peekd.h",
        "peekd-common/src",
        "peekd-common/Cargo.toml",
    ];
    paths
        .iter()
        .map(|path| workspace_root.join(path))
        .any(|path| path_newer_than(&path, object_mtime))
}

fn path_newer_than(path: &Path, mtime: SystemTime) -> bool {
    let Ok(metadata) = fs::metadata(path) else {
        return false;
    };
    if metadata.is_dir() {
        return fs::read_dir(path)
            .ok()
            .into_iter()
            .flatten()
            .filter_map(Result::ok)
            .any(|entry| path_newer_than(&entry.path(), mtime));
    }
    metadata.modified().is_ok_and(|modified| modified > mtime)
}
