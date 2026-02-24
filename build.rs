#![allow(unused)]
use std::fs::{File, read_dir};
use std::io::{Result, Write};
fn main() {
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
        for (num, entry) in entries.enumerate() {
            let entry = entry.unwrap();
            let path = entry.path();
            if path.is_file() {
                let file_name = path.file_name().unwrap().to_str().unwrap();
                if file_name.ends_with(".bin") {
                    let app_name = &file_name[0..file_name.len() - 4]; // 去掉 "app_" 前缀和 ".bin" 后缀
                    writeln!(file, ".section .rodata").unwrap();
                    writeln!(file, ".align 3");

                    writeln!(file, "app_{}_name:", num).unwrap();
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
