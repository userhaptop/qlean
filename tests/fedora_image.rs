use anyhow::Result;
use qlean::{Distro, MachineConfig, create_image, with_machine};
use serial_test::serial;
use std::{str, time::Duration};

#[path = "support/e2e.rs"]
mod e2e;
#[path = "support/guestfish.rs"]
mod guestfish;
#[path = "support/logging.rs"]
mod logging;

use e2e::should_run_vm_tests;
use guestfish::has_guestfish_tools;
use logging::tracing_subscriber_init;

#[tokio::test]
#[serial]
async fn test_fedora_image_startup_flow() -> Result<()> {
    tracing_subscriber_init();

    if !should_run_vm_tests() {
        return Ok(());
    }

    // `has_guestfish_tools` prints an actionable SKIP reason on failure.
    if !has_guestfish_tools() {
        return Ok(());
    }

    let image = tokio::time::timeout(
        Duration::from_secs(25 * 60),
        create_image(Distro::Fedora, "fedora-cloud"),
    )
    .await??;

    assert!(image.path().exists(), "qcow2 image must exist");
    assert!(image.kernel().exists(), "kernel must exist");
    assert!(image.initrd().exists(), "initrd must exist");

    // Full startup flow validation (mirrors single_machine.rs::hello)
    let config = MachineConfig::default();
    tokio::time::timeout(Duration::from_secs(8 * 60), async {
        with_machine(&image, &config, |vm| {
            Box::pin(async {
                let result = vm.exec("whoami").await?;
                assert!(result.status.success());
                assert_eq!(str::from_utf8(&result.stdout)?.trim(), "root");
                Ok(())
            })
        })
        .await
    })
    .await??;

    Ok(())
}
