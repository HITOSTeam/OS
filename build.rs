#![allow(unused)]
use std::fs::{File, read_dir};
use std::io::{Result, Write};
use std::{env, path::PathBuf};

fn main() {
    emit_linker_script_arg();

    // 告诉 Cargo 编译时需要重新运行 build.rs 的条件
    println!("cargo:rerun-if-changed=../user/src/bin");

    // 可以打印环境变量给编译器
    println!("cargo:rustc-env=MY_ENV_VAR=hello");

    // 可以生成文件到 OUT_DIR
    let target_file = "./src/link_app.asm";
    let user_app_dir = "./results";
    let mut file = std::fs::File::create(target_file).unwrap();
    let _ = std::fs::create_dir_all(user_app_dir);

    let entries = match read_dir(user_app_dir) {
        Ok(entries) => Some(entries),
        Err(err) => {
            println!(
                "cargo:warning=missing results dir '{}': {}",
                user_app_dir, err
            );
            None
        }
    };
    let mut num_app = 0;
    if let Some(entries) = entries {
        for entry in entries {
            let entry = entry.unwrap();
            let path = entry.path();
            if path.is_file() {
                let file_name = path.file_name().unwrap().to_str().unwrap();
                if file_name.ends_with(".bin") {
                    let app_name = &file_name[0..file_name.len() - 4]; // 去掉 "app_" 前缀和 ".bin" 后缀
                    writeln!(file, ".section .rodata").unwrap();
                    writeln!(file, ".align 3");

                    writeln!(file, "app_{}_name:", num_app).unwrap();
                    writeln!(file, "    .asciz \"{}\"", app_name).unwrap();
                    // writeln!(file, ".align 3");

                    // writeln!(file, ".section .data").unwrap();
                    // writeln!(file, "app_{}_start:", num).unwrap();
                    // writeln!(file, "    .incbin \"{}/{}\"", user_app_dir, file_name).unwrap();
                    // writeln!(file, ".align 3");
                    // writeln!(file, "app_{}_end:", num).unwrap();
                    num_app += 1;
                }
            }
        }
    }
    writeln!(file, ".section .rodata").unwrap();
    writeln!(file, ".align 3");
    writeln!(file, "    .global num_user_apps").unwrap();
    writeln!(file, "num_user_apps:").unwrap();
    writeln!(file, "    .quad {}", num_app).unwrap();
    for i in 0..num_app {
        // writeln!(file, "    .quad app_{}_start", i).unwrap();
        // writeln!(file, "    .quad app_{}_end", i).unwrap();
        writeln!(file, "    .quad app_{}_name", i).unwrap();
    }
    // list dir
}

fn emit_linker_script_arg() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    let linker_script = match arch.as_str() {
        "riscv64" => "src/linker.ld",
        "loongarch64" => "src/linker_loongarch.ld",
        _ => return,
    };
    let linker_script = manifest_dir.join(linker_script);

    println!("cargo:rerun-if-changed={}", linker_script.display());
    println!("cargo:rustc-link-arg=-T{}", linker_script.display());
}
