use std::env;
use std::path::PathBuf;

fn main() {
    // Look for the shared library in common locations
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let root = manifest_dir
        .parent()    // rust/
        .and_then(|p| p.parent())  // bindings/
        .and_then(|p| p.parent()); // UltrafastSecp256k1/

    if let Some(root) = root {
        // Try common build directories
        let search_dirs = vec![
            root.join("bindings").join("c_api").join("build"),
            root.join("bindings").join("c_api").join("build").join("Release"),
            root.join("build_rel"),
            root.join("build-linux"),
        ];

        for dir in &search_dirs {
            if dir.exists() {
                println!("cargo:rustc-link-search=native={}", dir.display());
            }
        }
    }

    // Also check environment variable
    if let Ok(lib_dir) = env::var("ULTRAFAST_SECP256K1_LIB_DIR") {
        println!("cargo:rustc-link-search=native={}", lib_dir);
    }

    println!("cargo:rustc-link-lib=dylib=ultrafast_secp256k1");
}
