use std::{env, path::PathBuf, process::Command};


fn main() {
    println!("cargo:rerun-if-changed=common/data.h");
    // use bindgen to generate bindings
    let bindings = bindgen::Builder::default()
        .header("src/common/data.h")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .generate()
        .expect("Unable to generate bindings");

    bindings
        .write_to_file(PathBuf::from("src/common").join("data.rs"))
        .expect("Couldn't write bindings!");

    // create a common/mod.rs file to re-export the generated bindings
    std::fs::write("src/common/mod.rs", "pub mod data;").expect("Couldn't write mod.rs");






    println!("cargo:rerun-if-changed=bpf/hello_world_bpf.c");
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let out_path = out_dir.join("hello_world_bpf.o");

    let kernel_release = Command::new("uname")
        .arg("-r")
        .output()
        .expect("Failed to execute uname")
        .stdout;
    let kernel_release_str = String::from_utf8(kernel_release).expect("Invalid UTF-8 from uname");
    let include_path = format!(
        "-I/usr/src/linux-headers-{}/include",
        kernel_release_str.trim()
    );

    let bpf_source_file = "bpf/hello_world_bpf.c";

    let mut command = Command::new("clang-13");

    let command = command
        .args(&[
            "-g",
            "-O2",
            "-D __TARGET_ARCH_x86",
            "-target",
            "bpf",
            &include_path,
            "-c",
            bpf_source_file,
            "-o",
        ])
        .arg(out_path.clone());
    
    if !command.status().expect("Failed to compile BPF source file").success() {
        panic!("Failed to compile BPF source file");
    }

    println!(
        "cargo:rustc-env=CONFIG_DAT_PATH={}",
        out_path.display()
    );
}
