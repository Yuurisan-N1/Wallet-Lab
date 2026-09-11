fn main() {
    // Link against the ufsecp shared library.
    // The library must be in the system library path or specified via:
    //   UFSECP_LIB_DIR env var, or cargo:rustc-link-search path.
    if let Ok(dir) = std::env::var("UFSECP_LIB_DIR") {
        println!("cargo:rustc-link-search=native={}", dir);
    } else if std::path::Path::new("/usr/local/lib/libufsecp.so").exists() {
        println!("cargo:rustc-link-search=native=/usr/local/lib");
    }
    println!("cargo:rustc-link-lib=dylib=ufsecp");
}
