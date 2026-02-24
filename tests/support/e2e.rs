use std::{path::Path, process::Command};

use anyhow::{Context, Result, bail};

/// Require explicit opt-in for slow integration tests.
pub fn ensure_e2e_enabled() -> Result<()> {
    let enabled = matches!(
        std::env::var("QLEAN_RUN_E2E").as_deref(),
        Ok("1") | Ok("true") | Ok("yes")
    );

    if !enabled {
        bail!("E2E VM tests are disabled. Set QLEAN_RUN_E2E=1 to run them.");
    }

    Ok(())
}

/// Return `true` if a command exists on PATH.
fn has_cmd(cmd: &str) -> bool {
    match Command::new(cmd).arg("--version").output() {
        Ok(_) => true,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
        Err(_) => false,
    }
}

/// Qlean can use TCP SSH fallback when vsock is unavailable.
pub fn log_vsock_status() {
    let has_vsock =
        Path::new("/dev/vhost-vsock").exists() || Path::new("/sys/module/vhost_vsock").exists();
    if !has_vsock {
        eprintln!("INFO: vhost-vsock is not available; Qlean will use TCP SSH fallback if needed.");
    }
}

/// Validate mandatory host commands for E2E execution.
pub fn ensure_vm_test_commands() -> Result<()> {
    if !has_cmd("virsh") {
        bail!("Missing required command: virsh (libvirt-clients).");
    }
    if !has_cmd("qemu-system-x86_64") && !has_cmd("qemu-kvm") {
        bail!("Missing required command: qemu-system-x86_64 (or qemu-kvm).");
    }
    Ok(())
}

/// Validate the libvirt system URI before running slow tests.
pub fn ensure_libvirt_system() -> Result<()> {
    let output = Command::new("virsh")
        .args(["-c", "qemu:///system", "list", "--all"])
        .output()
        .context("failed to execute `virsh -c qemu:///system list --all`")?;

    if !output.status.success() {
        bail!(
            "libvirt system URI is not usable: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    Ok(())
}

/// Fail early on host setup issues. Do not skip after opt-in.
pub fn ensure_vm_test_env() -> Result<()> {
    ensure_e2e_enabled()?;
    ensure_vm_test_commands()?;
    ensure_libvirt_system()?;
    log_vsock_status();
    Ok(())
}
