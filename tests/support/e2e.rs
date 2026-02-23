use std::{path::Path, process::Command};

/// Gate slow / privileged integration tests.
/// Enable by running: `QLEAN_RUN_E2E=1 cargo test --test ubuntu_image -- --nocapture`
pub fn e2e_enabled() -> bool {
    matches!(
        std::env::var("QLEAN_RUN_E2E").as_deref(),
        Ok("1") | Ok("true") | Ok("yes")
    )
}

/// Best-effort check for WSL.
pub fn is_wsl() -> bool {
    if std::env::var_os("WSL_INTEROP").is_some() || std::env::var_os("WSL_DISTRO_NAME").is_some() {
        return true;
    }
    std::fs::read_to_string("/proc/version")
        .map(|s| s.to_lowercase().contains("microsoft"))
        .unwrap_or(false)
}

/// Return `true` if a command exists on PATH.
pub fn has_cmd(cmd: &str) -> bool {
    match Command::new(cmd).arg("--version").output() {
        Ok(_) => true,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
        Err(_) => false,
    }
}

/// Best-effort connectivity check for the libvirt system URI.
fn can_connect_libvirt_system() -> bool {
    Command::new("virsh")
        .args(["-c", "qemu:///system", "list", "--all"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Qlean's SSH transport currently relies on vhost-vsock (AF_VSOCK).
fn has_vhost_vsock() -> bool {
    Path::new("/dev/vhost-vsock").exists() || Path::new("/sys/module/vhost_vsock").exists()
}

/// Skip E2E tests early if the environment can't support them.
/// Returns `true` if the test should proceed.
pub fn should_run_vm_tests() -> bool {
    if !e2e_enabled() {
        eprintln!("SKIP: E2E VM tests disabled. Set QLEAN_RUN_E2E=1 to enable.");
        return false;
    }
    if !Path::new("/dev/kvm").exists() {
        eprintln!(
            "SKIP: /dev/kvm not found. Install/enable KVM or run on a host with virtualization."
        );
        return false;
    }
    if !has_cmd("virsh") {
        eprintln!("SKIP: could not find `virsh` on PATH (libvirt-clients).");
        return false;
    }
    if !has_cmd("qemu-system-x86_64") && !has_cmd("qemu-kvm") {
        eprintln!("SKIP: could not find `qemu-system-x86_64` (or `qemu-kvm`) on PATH.");
        return false;
    }
    if !has_vhost_vsock() {
        eprintln!(
            "INFO: vhost-vsock not available on this kernel; E2E can still run using TCP SSH fallback."
        );
    }

    if is_wsl() {
        if !can_connect_libvirt_system() {
            eprintln!(
                "SKIP: WSL detected and `virsh -c qemu:///system` is not usable (permission or libvirtd not running).\n\
Hint: ensure systemd is enabled in WSL, start libvirtd, and add your user to libvirt/kvm groups, then `wsl --shutdown`."
            );
            return false;
        }
        eprintln!(
            "INFO: WSL detected, but KVM/libvirt appear usable; proceeding with E2E VM tests."
        );
    }
    true
}
