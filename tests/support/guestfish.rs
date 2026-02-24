use anyhow::{Result, bail};
use std::process::Command;

fn has_cmd(cmd: &str) -> bool {
    match Command::new(cmd).arg("--version").output() {
        Ok(_) => true,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
        Err(_) => false,
    }
}

/// Require libguestfs extraction tools for images that need kernel/initrd extraction.
pub fn ensure_guestfish_tools() -> Result<()> {
    if !has_cmd("guestfish") {
        bail!("Missing required command: guestfish (package: libguestfs-tools).");
    }
    if !has_cmd("virt-copy-out") {
        bail!("Missing required command: virt-copy-out (package: libguestfs-tools).");
    }
    Ok(())
}
