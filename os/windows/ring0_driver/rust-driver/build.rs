fn main() -> Result<(), wdk_build::ConfigError> {
    // CRT must be statically linked — kernel mode has no CRT DLL.
    std::env::set_var("CARGO_CFG_TARGET_FEATURE", "crt-static");

    // ── Linker flags ──────────────────────────────────────────────────────────

    // Mark the image as a kernel driver.
    println!("cargo:rustc-link-arg=/DRIVER");

    // Enforce code-integrity checks; required for PatchGuard / KMCI compliance.
    println!("cargo:rustc-link-arg=/INTEGRITYCHECK");

    println!("cargo:rustc-link-arg=/OPT:REF");
    println!("cargo:rustc-link-arg=/OPT:ICF");

    // Control Flow Guard — mandatory for HVCI / VBS compatibility.
    // Without this the driver will be blocked by Hypervisor-Protected Code
    // Integrity on machines with VBS enabled (modern Windows 11 defaults).
    println!("cargo:rustc-link-arg=/GUARD:CF");

    // Shadow-Stack (CET) compatibility — required for Kernel CET on Win11 22H2+.
    // Marks the image as compatible with the hardware shadow stack so the
    // kernel doesn't have to disable CET enforcement for this binary.
    println!("cargo:rustc-link-arg=/CETCOMPAT");

    // Reproducible builds: strip the absolute path from the PDB reference.
    // Prevents accidental leakage of build-machine paths in the binary.
    println!("cargo:rustc-link-arg=/PDBALTPATH:%_PDB%");

    wdk_build::configure_wdk_binary_build()?;
    Ok(())
}