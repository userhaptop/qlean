use anyhow::Result;
use qlean::{Distro, MachineConfig, create_image, with_machine};
use serial_test::serial;
use std::{str, time::Duration};

#[path = "support/e2e.rs"]
mod e2e;
#[path = "support/logging.rs"]
mod logging;

use e2e::ensure_vm_test_env;
use logging::tracing_subscriber_init;

#[tokio::test]
#[serial]
async fn test_ubuntu_image_creation() -> Result<()> {
    tracing_subscriber_init();

    ensure_vm_test_env()?;
    eprintln!("INFO: host checks passed");

    // Ubuntu  uses pre-extracted kernel/initrd.
    eprintln!("INFO: creating image");
    let image = tokio::time::timeout(
        Duration::from_secs(15 * 60),
        create_image(Distro::Ubuntu, "ubuntu-noble-cloudimg"),
    )
    .await??;

    assert!(image.path().exists(), "qcow2 image must exist");
    assert!(image.kernel().exists(), "kernel must exist");
    assert!(image.initrd().exists(), "initrd must exist");
    eprintln!("INFO: image ready: {}", image.path().display());

    eprintln!("INFO: starting VM and waiting for SSH");
    // Full startup flow validation
    let config = MachineConfig::default();
    tokio::time::timeout(Duration::from_secs(5 * 60), async {
        with_machine(&image, &config, |vm| {
            Box::pin(async {
                let result = vm.exec(". /etc/os-release && echo $ID").await?;
                assert!(result.status.success());
                let distro_id = str::from_utf8(&result.stdout)?.trim();
                assert!(
                    distro_id.contains("ubuntu"),
                    "unexpected distro id: {distro_id}"
                );
                Ok(())
            })
        })
        .await
    })
    .await??;

    Ok(())
}
