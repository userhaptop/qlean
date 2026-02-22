use anyhow::Result;
use qlean::{compute_sha256_streaming, compute_sha512_streaming, get_sha256, get_sha512};
use serial_test::serial;

mod common;
use common::tracing_subscriber_init;

// ---------------------------------------------------------------------------
// Correctness tests: streaming hash must match shell commands
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn test_streaming_sha256_matches_shell() -> Result<()> {
    tracing_subscriber_init();

    let tmp = tempfile::NamedTempFile::new()?;
    let path = tmp.path().to_path_buf();

    {
        use std::io::Write;
        let mut f = std::fs::File::create(&path)?;
        f.write_all(b"streaming sha256 correctness check")?;
    }

    let shell_result = get_sha256(&path).await?;
    let stream_result = compute_sha256_streaming(&path).await?;

    assert_eq!(
        shell_result, stream_result,
        "streaming SHA-256 must match shell command output"
    );

    Ok(())
}

#[tokio::test]
#[serial]
async fn test_streaming_sha512_matches_shell() -> Result<()> {
    tracing_subscriber_init();

    let tmp = tempfile::NamedTempFile::new()?;
    let path = tmp.path().to_path_buf();

    {
        use std::io::Write;
        let mut f = std::fs::File::create(&path)?;
        f.write_all(b"streaming sha512 correctness check")?;
    }

    let shell_result = get_sha512(&path).await?;
    let stream_result = compute_sha512_streaming(&path).await?;

    assert_eq!(
        shell_result, stream_result,
        "streaming SHA-512 must match shell command output"
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// Edge case tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_streaming_sha256_empty_file() -> Result<()> {
    let tmp = tempfile::NamedTempFile::new()?;
    let path = tmp.path().to_path_buf();

    let hash = compute_sha256_streaming(&path).await?;

    // SHA-256 of empty file (well-known constant)
    assert_eq!(
        hash,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );

    Ok(())
}

#[tokio::test]
async fn test_streaming_sha256_small_file() -> Result<()> {
    let tmp = tempfile::NamedTempFile::new()?;
    let path = tmp.path().to_path_buf();

    {
        use std::io::Write;
        let mut f = std::fs::File::create(&path)?;
        f.write_all(b"hello world")?;
    }

    let hash = compute_sha256_streaming(&path).await?;

    // SHA-256 of "hello world"
    assert_eq!(
        hash,
        "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
    );

    Ok(())
}

#[tokio::test]
async fn test_streaming_sha512_known_value() -> Result<()> {
    let tmp = tempfile::NamedTempFile::new()?;
    let path = tmp.path().to_path_buf();

    {
        use std::io::Write;
        let mut f = std::fs::File::create(&path)?;
        f.write_all(b"The quick brown fox jumps over the lazy dog")?;
    }

    let hash = compute_sha512_streaming(&path).await?;

    // SHA-512 of "The quick brown fox jumps over the lazy dog"
    assert_eq!(
        hash,
        "07e547d9586f6a73f73fbac0435ed76951218fb7d0c8d788a309d785436bbb642e93a252a954f23912547d1e8a3b5ed6e1bfd7097821233fa0538f3db854fee6"
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// Large file tests
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn test_streaming_sha256_10mb_file() -> Result<()> {
    tracing_subscriber_init();

    let tmp = tempfile::NamedTempFile::new()?;
    let path = tmp.path().to_path_buf();

    {
        use std::io::Write;
        let mut f = std::fs::File::create(&path)?;
        let chunk = vec![0xABu8; 1024 * 1024]; // 1 MB of 0xAB
        for _ in 0..10 {
            f.write_all(&chunk)?;
        }
    }

    let shell = get_sha256(&path).await?;
    let stream = compute_sha256_streaming(&path).await?;

    assert_eq!(shell, stream, "10MB file: streaming must match shell");

    Ok(())
}
