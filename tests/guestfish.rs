use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::OnceLock;

/// Return `true` if a command exists on PATH.
fn has_cmd(cmd: &str) -> bool {
    match Command::new(cmd).arg("--version").output() {
        Ok(_) => true,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
        Err(_) => false,
    }
}

/// Some distros require libguestfs (guestfish/virt-copy-out) to extract kernel/initrd from qcow2.
///
/// Note: On WSL and other minimal environments, libguestfs can *exist* but fail at runtime because
/// `supermin` cannot find a host kernel image under /boot. In that case we skip and print remediation.
pub fn has_guestfish_tools() -> bool {
    static CACHED: OnceLock<bool> = OnceLock::new();
    *CACHED.get_or_init(|| has_guestfish_tools_inner())
}

fn has_guestfish_tools_inner() -> bool {
    if !(has_cmd("guestfish") && has_cmd("virt-copy-out")) {
        eprintln!(
            "SKIP: Fedora/Arch extraction requires `guestfish` and `virt-copy-out` (package: libguestfs-tools).\n\
Install with: sudo apt install -y libguestfs-tools"
        );
        return false;
    }

    // libguestfs can use a prebuilt appliance. If one is present, we're usually good.
    let appliance_kernel_candidates = [
        "/usr/lib/guestfs/appliance/kernel",
        "/usr/lib64/guestfs/appliance/kernel",
        "/usr/share/guestfs/appliance/kernel",
    ];
    if appliance_kernel_candidates
        .iter()
        .any(|p| Path::new(p).exists())
    {
        // On WSL, even with tools installed, runtime can still fail. Probe in that case.
        return if is_wsl() {
            probe_libguestfs_runtime()
        } else {
            true
        };
    }

    // Otherwise it will try to build an appliance via supermin, which requires a host kernel image.
    let has_host_kernel = Path::new("/boot/vmlinuz").exists()
        || std::fs::read_dir("/boot")
            .map(|it| {
                it.filter_map(|e| e.ok())
                    .any(|e| e.file_name().to_string_lossy().starts_with("vmlinuz"))
            })
            .unwrap_or(false);

    if has_host_kernel {
        return if is_wsl() {
            probe_libguestfs_runtime()
        } else {
            true
        };
    }

    eprintln!(
        "SKIP: `guestfish` is installed but libguestfs appliance/kernel is missing.\n\
On WSL this commonly breaks `supermin`. Install a *kernel image package* so /boot contains vmlinuz*, e.g.:\n\
  sudo apt install -y linux-image-generic\n\
  # or (smaller)\n\
  sudo apt install -y linux-image-virtual\n\
Then retry.\n\
(If /boot is not usable in your environment, you can build a fixed appliance once and point libguestfs to it:)\n\
  mkdir -p ~/.local/share/qlean/guestfs-appliance\n\
  libguestfs-make-fixed-appliance ~/.local/share/qlean/guestfs-appliance\n\
  export LIBGUESTFS_PATH=~/.local/share/qlean/guestfs-appliance"
    );
    false
}

fn is_wsl() -> bool {
    std::fs::read_to_string("/proc/version")
        .map(|s| s.to_lowercase().contains("microsoft"))
        .unwrap_or(false)
}

fn probe_libguestfs_runtime() -> bool {
    // If the test tool isn't present, we can't reliably probe; fall back to the heuristic checks.
    if !has_cmd("libguestfs-test-tool") {
        return true;
    }

    // Use the system `timeout` if available to avoid hanging CI/WSL runs.
    let use_timeout = has_cmd("timeout");
    let mut cmd = if use_timeout {
        let mut c = Command::new("timeout");
        c.arg("30s").arg("libguestfs-test-tool");
        c
    } else {
        Command::new("libguestfs-test-tool")
    };

    cmd.env("LIBGUESTFS_BACKEND", "direct")
        .stdout(Stdio::null())
        .stderr(Stdio::piped());

    match cmd.output() {
        Ok(out) if out.status.success() => true,
        Ok(out) => {
            let stderr = String::from_utf8_lossy(&out.stderr);
            let first_lines = stderr.lines().take(8).collect::<Vec<_>>().join("\n");
            eprintln!(
                "SKIP: libguestfs runtime probe failed (guestfish/virt-copy-out will likely fail).\n\
Hint: run `LIBGUESTFS_BACKEND=direct libguestfs-test-tool` to see full diagnostics.\n\
stderr (first lines):\n{}",
                first_lines
            );
            false
        }
        Err(e) => {
            eprintln!(
                "SKIP: failed to run libguestfs runtime probe: {}\n\
Hint: ensure `libguestfs-tools` is installed.",
                e
            );
            false
        }
    }
}
