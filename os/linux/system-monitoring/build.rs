use libbpf_cargo::SkeletonBuilder;
use std::env;
use std::path::PathBuf;

fn main() {
    let mut out =
        PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR must be set in build script"));
    out.push("sentinel.skel.rs");

    SkeletonBuilder::new()
        .source("src/bpf/sentinel.bpf.c")
        .build_and_generate(&out)
        .expect("bpf compilation failed");

    println!("cargo:rerun-if-changed=src/bpf/sentinel.bpf.c");
}