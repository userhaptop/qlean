use std::future::Future;
use std::pin::Pin;
use std::sync::OnceLock;

use anyhow::Result;
use kvm_ioctls::Kvm;

use crate::utils::ensure_prerequisites;

mod image;
mod machine;
mod pool;
mod qemu;
mod ssh;
mod utils;

// Re-export public types and functions
pub use image::CustomImageConfig;
pub use image::Distro;
pub use image::Image;
pub use image::ImageSource;
pub use image::ShaType;
pub use image::compute_sha256_streaming;
pub use image::compute_sha512_streaming;
pub use image::create_custom_image;
pub use image::create_image;
pub use image::get_sha256;
pub use image::get_sha512;
pub use machine::{Machine, MachineConfig};
pub use pool::MachinePool;

static KVM_AVAILABLE: OnceLock<bool> = OnceLock::new();

pub async fn with_machine<'a, F, R>(image: &'a Image, config: &'a MachineConfig, f: F) -> Result<R>
where
    F: for<'b> FnOnce(&'b mut Machine) -> Pin<Box<dyn Future<Output = Result<R>> + 'b>>,
{
    #[cfg(not(target_os = "linux"))]
    {
        anyhow::bail!("Qlean currently only supports Linux hosts.");
    }

    ensure_prerequisites().await?;

    KVM_AVAILABLE.get_or_init(|| Kvm::new().is_ok());

    let mut machine = Machine::new(image, config).await?;
    machine.init().await?;
    let result = f(&mut machine).await;
    machine.shutdown().await?;

    result
}

pub async fn with_pool<F, R>(f: F) -> Result<R>
where
    F: for<'a> FnOnce(&'a mut MachinePool) -> Pin<Box<dyn Future<Output = Result<R>> + 'a>>,
{
    #[cfg(not(target_os = "linux"))]
    {
        anyhow::bail!("Qlean currently only supports Linux hosts.");
    }

    ensure_prerequisites().await?;

    KVM_AVAILABLE.get_or_init(|| Kvm::new().is_ok());

    let mut pool = MachinePool::new();
    let result = f(&mut pool).await;
    pool.shutdown_all().await?;

    result
}
