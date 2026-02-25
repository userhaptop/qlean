use std::{
    process::Stdio,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use console::strip_ansi_codes;
use tokio::{
    io::{AsyncBufReadExt, BufReader},
    time::{Duration, timeout},
};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, trace, warn};

use crate::{
    KVM_AVAILABLE, MachineConfig,
    machine::MachineImage,
    utils::{CommandExt, QleanDirs},
};

const QEMU_TIMEOUT: Duration = Duration::from_secs(360 * 60); // 6 hours

pub struct QemuLaunchParams {
    pub expected_to_exit: Arc<AtomicBool>,
    pub cid: u32,
    pub image: MachineImage,
    pub config: MachineConfig,
    pub vmid: String,
    pub is_init: bool,
    pub cancel_token: CancellationToken,
    pub mac_address: String,
    /// Optional host-forwarded TCP port for SSH (used as a fallback when vsock is unavailable).
    pub ssh_tcp_port: Option<u16>,
}

pub async fn launch_qemu(params: QemuLaunchParams) -> anyhow::Result<()> {
    // Prepare QEMU command
    let mut qemu_cmd = tokio::process::Command::new("qemu-system-x86_64");

    qemu_cmd
        // Decrease idle CPU usage
        .args(["-machine", "hpet=off"])
        // Vsock device (preferred transport)
        .args([
            "-device",
            &format!(
                "vhost-vsock-pci,id=vhost-vsock-pci0,guest-cid={}",
                params.cid
            ),
        ]);

    let use_direct_kernel_boot = params.image.prefer_direct_kernel_boot
        && params.image.kernel.exists()
        && params.image.initrd.exists()
        && std::fs::metadata(&params.image.kernel)
            .map(|m| m.len() > 0)
            .unwrap_or(false)
        && std::fs::metadata(&params.image.initrd)
            .map(|m| m.len() > 0)
            .unwrap_or(false);

    if use_direct_kernel_boot {
        qemu_cmd
            .args(["-kernel", params.image.kernel.to_str().unwrap()])
            .args([
                "-append",
                &format!("rw {} console=ttyS0", params.image.root_arg),
            ])
            .args(["-initrd", params.image.initrd.to_str().unwrap()]);
    } else {
        warn!("Kernel/initrd extraction is unavailable. Booting from qcow2 disk image directly.");
    }

    qemu_cmd
        // Disk
        .args([
            "-drive",
            &format!(
                "file={},if=virtio,cache=writeback",
                params.image.overlay.to_str().unwrap()
            ),
        ])
        // No GUI
        .arg("-nographic");

    // ---------------------------------------------------------------------
    // Network
    // Prefer bridged networking for parity with "real" hosts, but fall back to
    // user-mode networking (slirp) when bridging is unavailable (common on WSL2
    // or hosts without qemu bridge ACL configured).
    //
    // When using user-mode networking, we rely on hostfwd for SSH TCP fallback.
    // ---------------------------------------------------------------------
    let bridge_name = "qlbr0";
    let ssh_port = params.ssh_tcp_port;
    let want_bridge = has_iface(bridge_name) && bridge_conf_allows(bridge_name);

    if want_bridge {
        qemu_cmd
            .args(["-netdev", &format!("bridge,id=net0,br={bridge_name}")])
            .args([
                "-device",
                &format!("virtio-net-pci,netdev=net0,mac={}", params.mac_address),
            ]);

        // Optional user-mode networking with host port forwarding for SSH fallback.
        // This provides a TCP escape hatch even when vsock is unreliable.
        if let Some(port) = ssh_port {
            qemu_cmd
                .args([
                    "-netdev",
                    &format!("user,id=net1,hostfwd=tcp:127.0.0.1:{}-:22", port),
                ])
                .args(["-device", "virtio-net-pci,netdev=net1"]);
        }
    } else {
        warn!("Bridged networking is unavailable. Falling back to user-mode networking + hostfwd.");

        let port = ssh_port.ok_or_else(|| {
            anyhow::anyhow!("user-mode networking fallback requires ssh_tcp_port to be set")
        })?;

        qemu_cmd
            .args([
                "-netdev",
                &format!("user,id=net0,hostfwd=tcp:127.0.0.1:{}-:22", port),
            ])
            .args([
                "-device",
                &format!("virtio-net-pci,netdev=net0,mac={}", params.mac_address),
            ]);
    }

    // Memory and CPUs
    qemu_cmd
        .args(["-m", &params.config.mem.to_string()])
        .args(["-smp", &params.config.core.to_string()])
        // Output redirection
        .args(["-serial", "mon:stdio"]);
    if params.is_init {
        // Seed ISO
        qemu_cmd.args([
            "-drive",
            &format!(
                "file={},if=virtio,media=cdrom",
                params.image.seed.to_str().unwrap()
            ),
        ]);
    }

    let kvm_available = KVM_AVAILABLE.get().copied().unwrap_or(false);
    if kvm_available {
        // KVM acceleration
        qemu_cmd.args(["-accel", "kvm"]).args(["-cpu", "host"]);
    } else {
        warn!(
            "KVM is not available on this host. QEMU will run without hardware acceleration, which may result in significantly reduced performance."
        );
    }

    // Spawn QEMU process
    info!("Starting QEMU");
    debug!("QEMU command: {:?}", qemu_cmd.to_string());
    let mut qemu_child = qemu_cmd
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()?;

    // Store QEMU PID
    let pid = qemu_child.id().expect("failed to get QEMU PID");
    let dirs = QleanDirs::new()?;
    let pid_file_path = dirs.runs.join(&params.vmid).join("qemu.pid");
    tokio::fs::write(pid_file_path, pid.to_string()).await?;

    // Capture and log stdout
    let stdout = qemu_child.stdout.take().expect("Failed to capture stdout");
    let stdout_task = tokio::spawn(async move {
        let reader = BufReader::new(stdout);
        let mut lines = reader.lines();
        while let Ok(Some(line)) = lines.next_line().await {
            trace!("[qemu] {}", strip_ansi_codes(&line));
        }
    });

    // Capture and log stderr
    let stderr = qemu_child.stderr.take().expect("Failed to capture stderr");
    let stderr_task = tokio::spawn(async move {
        let reader = BufReader::new(stderr);
        let mut lines = reader.lines();
        while let Ok(Some(line)) = lines.next_line().await {
            error!("[qemu] {}", strip_ansi_codes(&line));
        }
    });

    let result = match timeout(QEMU_TIMEOUT, qemu_child.wait()).await {
        Err(_) => {
            error!("QEMU process timed out after 6 hours");
            Err(anyhow::anyhow!("QEMU process timed out"))
        }
        Ok(Err(e)) => {
            error!("Failed to wait for QEMU: {}", e);
            Err(e.into())
        }
        Ok(Ok(status)) => {
            if status.success() {
                if params.expected_to_exit.load(Ordering::SeqCst) {
                    info!("⏏️  Process {} exited as expected", pid);
                    Ok(())
                } else {
                    error!("Process {} exited unexpectedly", pid);
                    Err(anyhow::anyhow!("QEMU exited unexpectedly"))
                }
            } else {
                Err(anyhow::anyhow!(
                    "QEMU exited with error code: {:?}",
                    status.code()
                ))
            }
        }
    };

    // Cancel any ongoing operations due to QEMU exit
    params.cancel_token.cancel();

    // Wait for logging tasks to complete
    let _ = tokio::join!(stdout_task, stderr_task);

    result
}

fn bridge_conf_allows(bridge: &str) -> bool {
    // qemu-bridge-helper enforces an ACL file (commonly /etc/qemu/bridge.conf).
    // If the file is missing or doesn't allow the bridge, QEMU will fail with:
    // "failed to parse default acl file `/etc/qemu/bridge.conf`" or "bridge helper failed".
    let conf = match std::fs::read_to_string("/etc/qemu/bridge.conf") {
        Ok(c) => c,
        Err(_) => return false,
    };
    for line in conf.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // Supported entries: "allow <bridge>".
        if let Some(rest) = line.strip_prefix("allow ") {
            let b = rest.trim();
            if b == "all" || b == bridge {
                return true;
            }
        }
    }
    false
}

fn has_iface(name: &str) -> bool {
    std::path::Path::new(&format!("/sys/class/net/{name}")).exists()
}
