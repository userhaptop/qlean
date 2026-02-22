use std::{path::Path, process::Command, sync::Once};
use tracing_subscriber::{EnvFilter, fmt::time::LocalTime};

pub fn tracing_subscriber_init() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        tracing_subscriber::fmt()
            .with_env_filter(EnvFilter::from_default_env())
            .with_timer(LocalTime::rfc_3339())
            // Multiple test modules may try to install a global subscriber.
            // Use try_init to avoid panics when one is already set.
            .try_init()
            .ok();
    });
}

/// Gate slow / privileged integration tests.
/// Enable by running: `QLEAN_RUN_E2E=1 cargo test --test ubuntu_image -- --nocapture`
pub fn e2e_enabled() -> bool {
    matches!(
        std::env::var("QLEAN_RUN_E2E").as_deref(),
        Ok("1") | Ok("true") | Ok("yes")
    )
}

/// Best-effort check for WSL. Many QEMU/KVM setups won't work in WSL.
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
///
/// In WSL (and some constrained environments), `virsh` may exist but the user
/// may not have permission to access the system socket, or libvirtd may not be
/// running. In those cases we prefer to skip rather than hang.
fn can_connect_libvirt_system() -> bool {
    Command::new("virsh")
        .args(["-c", "qemu:///system", "list", "--all"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Qlean's SSH transport currently relies on vhost-vsock (AF_VSOCK).
/// If the host kernel doesn't expose vhost-vsock, VM startup tests will fail
/// with "network unreachable" when attempting to connect via vsock.
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
    // Qlean's current VM backend uses libvirt/virsh.
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
            "SKIP: vhost-vsock not available on this kernel (/dev/vhost-vsock or /sys/module/vhost_vsock missing).\n\
Qlean currently uses vsock for SSH; enable the vhost_vsock kernel module or run on a host that provides it."
        );
        return false;
    }

    // WSL can support /dev/kvm on newer builds, but libvirt permissions/config
    // are frequently missing. If we're on WSL, require a quick connectivity
    // check to avoid false negatives or long hangs.
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
