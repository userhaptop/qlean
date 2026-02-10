use anyhow::Result;
use qlean::{CustomImageConfig, ImageSource, ShaType, create_custom_image};
use serial_test::serial;
use std::path::PathBuf;

mod common;
use common::tracing_subscriber_init;

// ---------------------------------------------------------------------------
// Unit tests for CustomImageConfig
// ---------------------------------------------------------------------------

#[test]
fn test_custom_image_config_with_preextracted_serde() {
    let config = CustomImageConfig {
        image_source: ImageSource::Url("https://example.com/image.qcow2".to_string()),
        image_hash: "abcdef123456".to_string(),
        image_hash_type: ShaType::Sha256,
        kernel_source: Some(ImageSource::Url("https://example.com/vmlinuz".to_string())),
        kernel_hash: Some("kernel789".to_string()),
        initrd_source: Some(ImageSource::Url("https://example.com/initrd".to_string())),
        initrd_hash: Some("initrd012".to_string()),
    };

    let json = serde_json::to_string(&config).unwrap();
    let decoded: CustomImageConfig = serde_json::from_str(&json).unwrap();

    assert_eq!(decoded.image_hash, "abcdef123456");
    assert_eq!(decoded.kernel_hash, Some("kernel789".to_string()));
    assert_eq!(decoded.initrd_hash, Some("initrd012".to_string()));
}

#[test]
fn test_custom_image_config_url_serde() {
    let config = CustomImageConfig {
        image_source: ImageSource::Url("https://example.com/image.qcow2".to_string()),
        image_hash: "abc123".to_string(),
        image_hash_type: ShaType::Sha256,
        kernel_source: None,
        kernel_hash: None,
        initrd_source: None,
        initrd_hash: None,
    };

    let json = serde_json::to_string(&config).unwrap();
    let decoded: CustomImageConfig = serde_json::from_str(&json).unwrap();

    assert_eq!(decoded.image_hash, "abc123");
    // Test that None values are properly serialized/deserialized
    assert!(decoded.kernel_source.is_none());
}

#[test]
fn test_custom_image_config_local_path_serde() {
    let config = CustomImageConfig {
        image_source: ImageSource::LocalPath(PathBuf::from("/path/to/image.qcow2")),
        image_hash: "def456".to_string(),
        image_hash_type: ShaType::Sha512,
        kernel_source: Some(ImageSource::LocalPath(PathBuf::from("/path/to/vmlinuz"))),
        kernel_hash: Some("kernelhash".to_string()),
        initrd_source: Some(ImageSource::LocalPath(PathBuf::from("/path/to/initrd"))),
        initrd_hash: Some("initrdhash".to_string()),
    };

    let json = serde_json::to_string(&config).unwrap();
    let decoded: CustomImageConfig = serde_json::from_str(&json).unwrap();

    assert_eq!(decoded.image_hash, "def456");
    match decoded.kernel_source.unwrap() {
        ImageSource::LocalPath(p) => assert_eq!(p, PathBuf::from("/path/to/vmlinuz")),
        _ => panic!("Expected LocalPath"),
    }
}

// ---------------------------------------------------------------------------
// Error handling tests
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn test_custom_image_nonexistent_local_path() -> Result<()> {
    tracing_subscriber_init();

    let config = CustomImageConfig {
        image_source: ImageSource::LocalPath(PathBuf::from("/nonexistent/image.qcow2")),
        image_hash: "fakehash".to_string(),
        image_hash_type: ShaType::Sha256,
        kernel_source: None,
        kernel_hash: None,
        initrd_source: None,
        initrd_hash: None,
    };

    let result = create_custom_image("test-nonexistent", config).await;
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("does not exist"));

    Ok(())
}

#[tokio::test]
#[serial]
async fn test_custom_image_hash_mismatch() -> Result<()> {
    tracing_subscriber_init();

    let tmp = tempfile::NamedTempFile::new()?;
    let path = tmp.path().to_path_buf();

    {
        use std::io::Write;
        let mut f = std::fs::File::create(&path)?;
        f.write_all(b"test content")?;
    }

    let config = CustomImageConfig {
        image_source: ImageSource::LocalPath(path),
        image_hash: "wronghash123".to_string(),
        image_hash_type: ShaType::Sha256,
        kernel_source: None,
        kernel_hash: None,
        initrd_source: None,
        initrd_hash: None,
    };

    let result = create_custom_image("test-hash-mismatch", config).await;
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("hash mismatch"));

    Ok(())
}
