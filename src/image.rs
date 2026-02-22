use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use futures::StreamExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};
use tokio::{fs::File, io::AsyncWriteExt};
use tracing::{debug, warn};

use crate::utils::QleanDirs;

pub trait ImageAction {
    /// Download the image from remote source
    fn download(&self, name: &str) -> impl std::future::Future<Output = Result<()>> + Send;
    /// Extract kernel and initrd from the image
    fn extract(
        &self,
        name: &str,
    ) -> impl std::future::Future<Output = Result<(PathBuf, PathBuf)>> + Send;
    /// Get the distro type
    fn distro(&self) -> Distro;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageMeta<A: ImageAction> {
    pub name: String,
    pub path: PathBuf,
    pub kernel: PathBuf,
    pub initrd: PathBuf,
    #[serde(skip)]
    pub vendor: A,
    pub checksum: ShaSum,
}

#[derive(Debug, PartialEq, Serialize, Deserialize, Clone)]
pub enum Distro {
    Debian,
    Ubuntu,
    Fedora,
    Arch,
    Custom,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize, Clone)]
pub enum ShaType {
    Sha256,
    Sha512,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShaSum {
    pub path: PathBuf,
    pub sha_type: ShaType,
}

/// Source of a file: URL or local file path
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ImageSource {
    Url(String),
    LocalPath(PathBuf),
}

/// Configuration for custom images - supports two modes:
/// 1. Image only (requires guestfish for extraction)
/// 2. Image + pre-extracted kernel/initrd (WSL-friendly)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CustomImageConfig {
    // Image file (required)
    pub image_source: ImageSource,
    pub image_hash: String,
    pub image_hash_type: ShaType,

    // Optional: pre-extracted kernel and initrd (for WSL compatibility)
    pub kernel_source: Option<ImageSource>,
    pub kernel_hash: Option<String>,
    pub initrd_source: Option<ImageSource>,
    pub initrd_hash: Option<String>,
}

/// Parses SHA512SUMS format and returns the hash for an exact filename match.
///
/// # Arguments
/// * `checksums_text` - The content of a SHA512SUMS file
/// * `filename` - The exact filename to search for (e.g., "debian-13-generic-amd64.qcow2")
///
/// # Returns
/// The SHA512 hash if found, or None if no exact match exists
pub fn find_sha512_for_file(checksums_text: &str, filename: &str) -> Option<String> {
    checksums_text.lines().find_map(|line| {
        let mut parts = line.split_whitespace();
        let hash = parts.next()?;
        let fname = parts.next()?;

        (fname == filename).then(|| hash.to_string())
    })
}

/// Parse a checksum file and return the hash for a given filename.
///
/// Supports common formats:
/// 1) "<hex>  <filename>"
/// 2) "SHA256 (<filename>) = <hex>" / "SHA512 (<filename>) = <hex>"
pub fn find_hash_for_file(checksums_text: &str, filename: &str) -> Option<String> {
    // Format 1: "<hex>  <filename>"
    if let Some(h) = checksums_text.lines().find_map(|line| {
        let mut parts = line.split_whitespace();
        let hash = parts.next()?;
        let fname = parts.next()?;
        (fname == filename).then(|| hash.to_string())
    }) {
        return Some(h);
    }

    // Format 2: "SHA256 (<filename>) = <hex>" / "SHA512 (<filename>) = <hex>"
    for line in checksums_text.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("SHA256 (")
            && let Some(rest) = rest.strip_prefix(filename)
            && let Some(rest) = rest.strip_prefix(") = ")
        {
            return Some(rest.trim().to_string());
        }

        if let Some(rest) = line.strip_prefix("SHA512 (")
            && let Some(rest) = rest.strip_prefix(filename)
            && let Some(rest) = rest.strip_prefix(") = ")
        {
            return Some(rest.trim().to_string());
        }
    }

    None
}

async fn fetch_text(url: &str) -> Result<String> {
    // Keep metadata fetches snappy: if a mirror is slow/hung, we fall back.
    let client = reqwest::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(15))
        .timeout(std::time::Duration::from_secs(30))
        .user_agent("qlean/0.2 (image-fetch)")
        .build()
        .with_context(|| "failed to build HTTP client")?;

    let resp = client
        .get(url)
        .send()
        .await
        .with_context(|| format!("failed to GET {}", url))?;
    let status = resp.status();
    anyhow::ensure!(status.is_success(), "GET {} failed: {}", url, status);

    resp.text()
        .await
        .with_context(|| format!("failed reading body from {}", url))
}

// ---------------------------------------------------------------------------
// Fedora/Arch "latest stable" resolvers
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct ResolvedRemote {
    /// Candidate URLs to try in order. Mirrors can hang; we retry/fallback.
    urls: Vec<String>,
    sha256: String,
}

/// Query endoflife.date for the latest maintained Fedora release number.
///
/// This endpoint is stable and returns structured JSON. We select the first
/// release entry where `isMaintained=true` and `isEol=false`.
async fn resolve_latest_fedora_release() -> Result<String> {
    #[derive(Deserialize)]
    struct EolResp {
        result: EolResult,
    }
    #[derive(Deserialize)]
    struct EolResult {
        releases: Vec<EolRelease>,
    }
    #[derive(Deserialize)]
    struct EolRelease {
        name: String,
        #[serde(default, rename = "isEol")]
        is_eol: bool,
        #[serde(default, rename = "isMaintained")]
        is_maintained: bool,
    }

    // Public JSON API documented on https://endoflife.date/fedora
    let url = "https://endoflife.date/api/v1/products/fedora/";
    let body = fetch_text(url).await?;
    let parsed: EolResp =
        serde_json::from_str(&body).with_context(|| "failed to parse Fedora release JSON")?;

    let latest = parsed
        .result
        .releases
        .into_iter()
        .find(|r| r.is_maintained && !r.is_eol)
        .map(|r| r.name)
        .with_context(|| "could not determine latest maintained Fedora release")?;

    Ok(latest)
}

/// Resolve the latest Fedora Cloud Base Generic qcow2 URL and its SHA256.
///
/// Implementation strategy:
/// 1) Determine the latest maintained Fedora version.
/// 2) Fetch an HTML directory listing from one of several known mirrors.
/// 3) Parse the directory listing to locate the *exact* qcow2 filename and
///    the corresponding CHECKSUM file name.
/// 4) Download the CHECKSUM file and extract the SHA256 for the qcow2.
async fn resolve_latest_fedora_cloud_qcow2() -> Result<ResolvedRemote> {
    let ver = resolve_latest_fedora_release().await?;

    // Mirror directory patterns differ. We try a small set of mirrors known to
    // provide HTML listings. We keep this list short to reduce fragility.
    // Order matters: prefer official redirector first, then a couple of mirrors
    // that typically provide directory listings.
    let candidates = [
        format!(
            "https://download.fedoraproject.org/pub/fedora/linux/releases/{}/Cloud/x86_64/images/",
            ver
        ),
        format!(
            "https://ftp2.osuosl.org/pub/fedora/linux/releases/{}/Cloud/x86_64/images/",
            ver
        ),
        format!(
            "https://mirrors.oit.uci.edu/fedora/linux/releases/{}/Cloud/x86_64/images/",
            ver
        ),
        format!(
            "https://mirrors.telepoint.bg/fedora/releases/{}/Cloud/x86_64/images/",
            ver
        ),
        format!(
            "https://mirrors.kernel.org/fedora/releases/{}/Cloud/x86_64/images/",
            ver
        ),
    ];

    // Collect all mirrors where we can fetch a usable listing. We'll parse once
    // and then try downloads across all mirrors.
    let mut good_bases: Vec<String> = Vec::new();
    let mut listing_html: Option<String> = None;
    for u in &candidates {
        match fetch_text(u).await {
            Ok(text) => {
                if text.contains("Fedora-Cloud-Base-Generic") && text.contains("CHECKSUM") {
                    good_bases.push(u.clone());
                    if listing_html.is_none() {
                        listing_html = Some(text);
                    }
                }
            }
            Err(e) => {
                debug!("Fedora listing fetch failed for {}: {:#}", u, e);
            }
        }
    }

    anyhow::ensure!(
        !good_bases.is_empty(),
        "failed to fetch Fedora Cloud images listing from mirrors"
    );
    let listing_html = listing_html.unwrap();

    let (qcow2_name, checksum_name) = parse_fedora_cloud_listing(&listing_html, &ver)?;

    // Use the first good base to fetch CHECKSUM (hash should match across mirrors).
    let checksum_url = format!("{}{}", good_bases[0], checksum_name);
    let checksum_text = fetch_text(&checksum_url).await?;
    let sha256 = find_hash_for_file(&checksum_text, &qcow2_name).with_context(|| {
        format!(
            "could not find hash for {} in {}",
            qcow2_name, checksum_name
        )
    })?;

    // Build download URLs. Prefer bases where listing worked, but also try the
    // full candidate set as a fallback (a mirror may block directory listing
    // but still serve the file).
    let mut bases = good_bases;
    for c in &candidates {
        if !bases.iter().any(|b| b == c) {
            bases.push(c.clone());
        }
    }
    let urls = bases
        .into_iter()
        .map(|base| format!("{}{}", base, qcow2_name))
        .collect::<Vec<_>>();

    Ok(ResolvedRemote { urls, sha256 })
}

fn parse_fedora_cloud_listing(listing_html: &str, ver: &str) -> Result<(String, String)> {
    // Parse filename candidates.
    // Listings generally contain only one compose, so the first match is fine.
    let qcow2_prefix = format!("Fedora-Cloud-Base-Generic-{}-", ver);
    let qcow2_suffix = ".x86_64.qcow2";
    let mut qcow2_name: Option<String> = None;
    let mut checksum_name: Option<String> = None;

    for token in listing_html
        .split(|c: char| !(c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_'))
    {
        if qcow2_name.is_none() && token.starts_with(&qcow2_prefix) && token.ends_with(qcow2_suffix)
        {
            qcow2_name = Some(token.to_string());
        }
        if checksum_name.is_none()
            && token.starts_with(&format!("Fedora-Cloud-{}-", ver))
            && token.ends_with("-x86_64-CHECKSUM")
        {
            checksum_name = Some(token.to_string());
        }
        if qcow2_name.is_some() && checksum_name.is_some() {
            break;
        }
    }

    let qcow2_name = qcow2_name
        .with_context(|| "could not locate Fedora Cloud Base Generic qcow2 filename in listing")?;
    let checksum_name = checksum_name
        .with_context(|| "could not locate Fedora Cloud CHECKSUM filename in listing")?;

    Ok((qcow2_name, checksum_name))
}

/// Resolve the latest Arch cloud image URL and SHA256.
///
/// Arch publishes stable "latest" URLs plus a sidecar .SHA256 file.
async fn resolve_latest_arch_cloudimg() -> Result<ResolvedRemote> {
    // Multiple mirrors; any could stall. We fetch SHA256 from the first
    // available mirror (sidecar is identical across mirrors).
    let bases = [
        "https://geo.mirror.pkgbuild.com/images/latest",
        "https://mirrors.kernel.org/archlinux/images/latest",
        "https://mirror.rackspace.com/archlinux/images/latest",
    ];
    let filename = "Arch-Linux-x86_64-cloudimg.qcow2";

    let mut sha_text: Option<String> = None;
    let mut good_bases: Vec<String> = Vec::new();
    for base in &bases {
        let sha_url = format!("{}/{}.SHA256", base, filename);
        match fetch_text(&sha_url).await {
            Ok(t) => {
                good_bases.push(base.to_string());
                if sha_text.is_none() {
                    sha_text = Some(t);
                }
            }
            Err(e) => debug!("Arch SHA256 fetch failed for {}: {:#}", sha_url, e),
        }
    }

    anyhow::ensure!(
        !good_bases.is_empty(),
        "failed to fetch Arch cloud image SHA256 from mirrors"
    );

    let sha_text = sha_text.unwrap();
    let sha256 = find_hash_for_file(&sha_text, filename)
        .with_context(|| "could not parse Arch .SHA256 file")?;

    let urls = good_bases
        .into_iter()
        .map(|base| format!("{}/{}", base, filename))
        .collect::<Vec<_>>();
    Ok(ResolvedRemote { urls, sha256 })
}

// ---------------------------------------------------------------------------
// Streaming hash functions - optimized for release mode performance
// ---------------------------------------------------------------------------

/// Compute SHA-256 hash using streaming approach with sync I/O
/// This provides 7-27% better performance than shell commands in release mode
pub async fn compute_sha256_streaming(path: &Path) -> Result<String> {
    let path = path.to_path_buf();

    tokio::task::spawn_blocking(move || {
        use std::io::Read;

        let mut file = std::fs::File::open(&path)
            .with_context(|| format!("failed to open file for hashing: {}", path.display()))?;

        let mut hasher = Sha256::new();
        let mut buf = vec![0u8; 64 * 1024]; // 64 KB buffer

        loop {
            let n = file
                .read(&mut buf)
                .with_context(|| "failed to read file during hashing")?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
        }

        Ok(format!("{:x}", hasher.finalize()))
    })
    .await
    .with_context(|| "hash computation task failed")?
}

/// Compute SHA-512 hash using streaming approach with sync I/O
pub async fn compute_sha512_streaming(path: &Path) -> Result<String> {
    let path = path.to_path_buf();

    tokio::task::spawn_blocking(move || {
        use std::io::Read;

        let mut file = std::fs::File::open(&path)
            .with_context(|| format!("failed to open file for hashing: {}", path.display()))?;

        let mut hasher = Sha512::new();
        let mut buf = vec![0u8; 64 * 1024];

        loop {
            let n = file
                .read(&mut buf)
                .with_context(|| "failed to read file during hashing")?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
        }

        Ok(format!("{:x}", hasher.finalize()))
    })
    .await
    .with_context(|| "hash computation task failed")?
}

/// Download file and compute hash in single pass to avoid reading file twice
pub async fn download_with_hash(
    url: &str,
    dest_path: &PathBuf,
    hash_type: ShaType,
) -> Result<String> {
    // Keep a temp file to avoid leaving a partially-downloaded blob behind.
    let tmp_path = dest_path.with_extension("part");

    debug!("Downloading {} to {}", url, dest_path.display());

    let client = reqwest::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(20))
        // Do NOT set a short global timeout for large images; we handle stalls
        // with an idle timeout on the stream.
        .user_agent("qlean/0.2 (image-download)")
        .build()
        .with_context(|| "failed to build HTTP client")?;

    let response = client
        .get(url)
        .send()
        .await
        .with_context(|| format!("failed to download from {}", url))?;

    let status = response.status();
    anyhow::ensure!(status.is_success(), "GET {} failed: {}", url, status);

    // Ensure destination directory exists.
    if let Some(parent) = tmp_path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .with_context(|| format!("failed to create dir {}", parent.display()))?;
    }

    // Start fresh on each attempt.
    let _ = tokio::fs::remove_file(&tmp_path).await;

    let mut file = File::create(&tmp_path)
        .await
        .with_context(|| format!("failed to create file at {}", tmp_path.display()))?;

    let mut stream = response.bytes_stream();
    let idle = std::time::Duration::from_secs(30);
    let mut downloaded: u64 = 0;
    let mut last_report: u64 = 0;
    // Report download progress in reasonably small increments. On slower links (or in CI/WSL),
    // 64MiB can take long enough that the test runner prints a scary "running over 60 seconds"
    // warning with no other output.
    let report_step: u64 = 16 * 1024 * 1024; // 16 MiB

    let hash = match hash_type {
        ShaType::Sha256 => {
            let mut h = Sha256::new();
            loop {
                let next = tokio::time::timeout(idle, stream.next())
                    .await
                    .with_context(|| {
                        format!("download stalled for {} (>{:?} without data)", url, idle)
                    })?;
                let Some(chunk) = next else { break };
                let chunk = chunk.with_context(|| "failed to read chunk")?;
                downloaded += chunk.len() as u64;
                if downloaded - last_report >= report_step {
                    last_report = downloaded;
                    debug!("Downloading {}: {} MiB", url, downloaded / (1024 * 1024));
                }
                h.update(&chunk);
                file.write_all(&chunk)
                    .await
                    .with_context(|| "failed to write chunk")?;
            }
            format!("{:x}", h.finalize())
        }
        ShaType::Sha512 => {
            let mut h = Sha512::new();
            loop {
                let next = tokio::time::timeout(idle, stream.next())
                    .await
                    .with_context(|| {
                        format!("download stalled for {} (>{:?} without data)", url, idle)
                    })?;
                let Some(chunk) = next else { break };
                let chunk = chunk.with_context(|| "failed to read chunk")?;
                downloaded += chunk.len() as u64;
                if downloaded - last_report >= report_step {
                    last_report = downloaded;
                    debug!("Downloading {}: {} MiB", url, downloaded / (1024 * 1024));
                }
                h.update(&chunk);
                file.write_all(&chunk)
                    .await
                    .with_context(|| "failed to write chunk")?;
            }
            format!("{:x}", h.finalize())
        }
    };

    file.flush().await.with_context(|| "failed to flush file")?;

    // Atomically move into place.
    tokio::fs::rename(&tmp_path, dest_path)
        .await
        .with_context(|| {
            format!(
                "failed to move {} -> {}",
                tmp_path.display(),
                dest_path.display()
            )
        })?;

    Ok(hash)
}

/// Try downloading a remote file from multiple candidate URLs.
///
/// Mirrors can hang mid-transfer; we apply an idle timeout and move on.
pub async fn download_with_hash_multi(
    urls: &[String],
    dest_path: &PathBuf,
    hash_type: ShaType,
    expected_hex: Option<&str>,
) -> Result<(String, String)> {
    let mut last_err: Option<anyhow::Error> = None;

    for (idx, url) in urls.iter().enumerate() {
        // If a cached file exists and matches expected, short-circuit.
        if let Some(expected) = expected_hex
            && dest_path.exists()
        {
            // Avoid moving `hash_type` (non-Copy) so it can be reused for mirror retries.
            let computed = match &hash_type {
                ShaType::Sha256 => compute_sha256_streaming(dest_path).await,
                ShaType::Sha512 => compute_sha512_streaming(dest_path).await,
            };

            if let Ok(h) = computed
                && h.eq_ignore_ascii_case(expected)
            {
                debug!("Using cached file at {}", dest_path.display());
                return Ok((h, "(cached)".to_string()));
            }
        }

        debug!("Download attempt {}/{}: {}", idx + 1, urls.len(), url);
        match download_with_hash(url, dest_path, hash_type.clone()).await {
            Ok(h) => {
                if let Some(expected) = expected_hex
                    && !h.eq_ignore_ascii_case(expected)
                {
                    warn!(
                        "hash mismatch from {}: expected {}, got {}",
                        url, expected, h
                    );
                    last_err = Some(anyhow::anyhow!(
                        "hash mismatch from {}: expected {}, got {}",
                        url,
                        expected,
                        h
                    ));
                    // continue to next mirror
                    continue;
                }
                return Ok((h, url.clone()));
            }
            Err(e) => {
                warn!("download failed for {}: {:#}", url, e);
                last_err = Some(e);
                // next mirror
            }
        }
    }

    Err(last_err.unwrap_or_else(|| anyhow::anyhow!("all download mirrors failed")))
}

/// Download or copy file from ImageSource with hash verification
async fn download_or_copy_with_hash(
    source: &ImageSource,
    dest: &PathBuf,
    expected_hash: &str,
    hash_type: ShaType,
) -> Result<()> {
    match source {
        ImageSource::Url(url) => {
            // Reuse cached download if it matches, otherwise overwrite.
            if dest.exists() {
                let existing = match hash_type {
                    ShaType::Sha256 => compute_sha256_streaming(dest).await,
                    ShaType::Sha512 => compute_sha512_streaming(dest).await,
                };
                if let Ok(h) = existing
                    && h.eq_ignore_ascii_case(expected_hash)
                {
                    return Ok(());
                }
            }

            let computed = download_with_hash(url, dest, hash_type).await?;
            anyhow::ensure!(
                computed.to_lowercase() == expected_hash.to_lowercase(),
                "hash mismatch: expected {}, got {}",
                expected_hash,
                computed
            );
        }
        ImageSource::LocalPath(src) => {
            anyhow::ensure!(src.exists(), "file does not exist: {}", src.display());
            tokio::fs::copy(src, dest).await?;

            let computed = match hash_type {
                ShaType::Sha256 => compute_sha256_streaming(dest).await?,
                ShaType::Sha512 => compute_sha512_streaming(dest).await?,
            };

            anyhow::ensure!(
                computed.to_lowercase() == expected_hash.to_lowercase(),
                "hash mismatch: expected {}, got {}",
                expected_hash,
                computed
            );
        }
    }
    Ok(())
}

impl<A: ImageAction + std::default::Default> ImageMeta<A> {
    /// Create a new image by downloading and extracting
    pub async fn create(name: &str) -> Result<Self> {
        debug!("Fetching image {} ...", name);

        let dirs = QleanDirs::new()?;

        if let Ok(image) = Self::load(name).await {
            debug!("Using cached image.");
            return Ok(image);
        }

        let image_dir = dirs.images.join(name);
        if image_dir.exists() {
            tokio::fs::remove_dir_all(&image_dir).await?;
        }
        tokio::fs::create_dir_all(&image_dir).await?;

        let distro_action = A::default();

        distro_action.download(name).await?;

        let (kernel, initrd) = distro_action.extract(name).await?;
        let image_path = image_dir.join(format!("{}.qcow2", name));
        let checksum_path = image_dir.join("checksums");
        let checksum = ShaSum {
            path: checksum_path,
            sha_type: ShaType::Sha512,
        };
        let image = ImageMeta {
            path: image_path,
            kernel,
            initrd,
            checksum,
            name: name.to_string(),
            vendor: distro_action,
        };

        image.save(name).await?;

        Ok(image)
    }

    /// Load image metadata from disk and validate checksums
    async fn load(name: &str) -> Result<Self> {
        let dirs = QleanDirs::new()?;
        let json_path = dirs.images.join(format!("{}.json", name));

        let json_content = tokio::fs::read_to_string(&json_path)
            .await
            .with_context(|| format!("failed to read config file at {}", json_path.display()))?;

        let image: ImageMeta<A> = serde_json::from_str(&json_content)
            .with_context(|| format!("failed to parse JSON from {}", json_path.display()))?;

        let checksum_dir = dirs.images.join(name);
        let checksum_command = match image.checksum.sha_type {
            ShaType::Sha256 => "sha256sum",
            ShaType::Sha512 => "sha512sum",
        };

        let output = tokio::process::Command::new(checksum_command)
            .arg("-c")
            .arg(&image.checksum.path)
            .arg("--quiet")
            .current_dir(&checksum_dir)
            .output()
            .await
            .with_context(|| format!("failed to execute {} -c", checksum_command))?;

        if !output.status.success() {
            bail!(
                "checksum verification failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        Ok(image)
    }

    /// Save image metadata to disk using streaming hash
    async fn save(&self, name: &str) -> Result<()> {
        let dirs = QleanDirs::new()?;
        let json_path = dirs.images.join(format!("{}.json", name));

        let json_content = serde_json::to_string_pretty(&self)
            .with_context(|| "failed to serialize image config to JSON")?;

        tokio::fs::write(&json_path, json_content)
            .await
            .with_context(|| format!("failed to write image config to {}", json_path.display()))?;

        // Use streaming hash for best performance (7-27% faster in release mode)
        let (image_hash, kernel_hash, initrd_hash) = match self.checksum.sha_type {
            ShaType::Sha256 => (
                compute_sha256_streaming(&self.path).await?,
                compute_sha256_streaming(&self.kernel).await?,
                compute_sha256_streaming(&self.initrd).await?,
            ),
            ShaType::Sha512 => (
                compute_sha512_streaming(&self.path).await?,
                compute_sha512_streaming(&self.kernel).await?,
                compute_sha512_streaming(&self.initrd).await?,
            ),
        };

        let image_filename = self
            .path
            .file_name()
            .with_context(|| "failed to get image filename")?
            .to_string_lossy();
        let kernel_filename = self
            .kernel
            .file_name()
            .with_context(|| "failed to get kernel filename")?
            .to_string_lossy();
        let initrd_filename = self
            .initrd
            .file_name()
            .with_context(|| "failed to get initrd filename")?
            .to_string_lossy();

        let checksum_content = format!(
            "{}  {}\n{}  {}\n{}  {}\n",
            image_hash, image_filename, kernel_hash, kernel_filename, initrd_hash, initrd_filename
        );

        tokio::fs::write(&self.checksum.path, checksum_content)
            .await
            .with_context(|| {
                format!(
                    "failed to write checksum file to {}",
                    self.checksum.path.display()
                )
            })?;

        Ok(())
    }
}

// Special create method for Custom images (non-Default trait)
impl<A: ImageAction> ImageMeta<A> {
    /// Create image with custom action for non-Default implementations
    pub async fn create_with_action(name: &str, action: A) -> Result<Self> {
        debug!("Fetching image {} with custom action ...", name);

        let dirs = QleanDirs::new()?;
        let image_dir = dirs.images.join(name);

        if image_dir.exists() {
            tokio::fs::remove_dir_all(&image_dir).await?;
        }
        tokio::fs::create_dir_all(&image_dir).await?;

        action.download(name).await?;

        let (kernel, initrd) = action.extract(name).await?;
        let image_path = image_dir.join(format!("{}.qcow2", name));
        let checksum_path = image_dir.join("checksums");
        let checksum = ShaSum {
            path: checksum_path,
            sha_type: ShaType::Sha512,
        };
        let image = ImageMeta {
            path: image_path,
            kernel,
            initrd,
            checksum,
            name: name.to_string(),
            vendor: action,
        };

        // Inline save with streaming hash
        let json_path = dirs.images.join(format!("{}.json", name));
        let json_content = serde_json::to_string_pretty(&image)?;
        tokio::fs::write(&json_path, json_content).await?;

        let (image_hash, kernel_hash, initrd_hash) = match image.checksum.sha_type {
            ShaType::Sha256 => (
                compute_sha256_streaming(&image.path).await?,
                compute_sha256_streaming(&image.kernel).await?,
                compute_sha256_streaming(&image.initrd).await?,
            ),
            ShaType::Sha512 => (
                compute_sha512_streaming(&image.path).await?,
                compute_sha512_streaming(&image.kernel).await?,
                compute_sha512_streaming(&image.initrd).await?,
            ),
        };

        let image_filename = image.path.file_name().unwrap().to_string_lossy();
        let kernel_filename = image.kernel.file_name().unwrap().to_string_lossy();
        let initrd_filename = image.initrd.file_name().unwrap().to_string_lossy();

        let checksum_content = format!(
            "{}  {}\n{}  {}\n{}  {}\n",
            image_hash, image_filename, kernel_hash, kernel_filename, initrd_hash, initrd_filename
        );

        tokio::fs::write(&image.checksum.path, checksum_content).await?;

        Ok(image)
    }
}

// ---------------------------------------------------------------------------
// Debian
// ---------------------------------------------------------------------------

#[derive(Debug, Default)]
pub struct Debian {}

impl ImageAction for Debian {
    async fn download(&self, name: &str) -> Result<()> {
        let checksums_url = "https://cloud.debian.org/images/cloud/trixie/latest/SHA512SUMS";
        let checksums_text = reqwest::get(checksums_url)
            .await
            .with_context(|| format!("failed to download SHA512SUMS from {}", checksums_url))?
            .text()
            .await
            .with_context(|| format!("failed to read SHA512SUMS text from {}", checksums_url))?;

        let target_filename = format!("{}.qcow2", name);
        let expected_sha512 = find_sha512_for_file(&checksums_text, &target_filename)
            .with_context(|| {
                format!(
                    "failed to find SHA512 checksum entry for {} in remote SHA512SUMS file",
                    target_filename
                )
            })?;

        let dirs = QleanDirs::new()?;
        let image_path = dirs.images.join(name).join(&target_filename);

        let download_url = format!(
            "https://cloud.debian.org/images/cloud/trixie/latest/{}.qcow2",
            name
        );

        // Single-pass download + hash computation
        let computed_sha512 =
            download_with_hash(&download_url, &image_path, ShaType::Sha512).await?;

        // Verify the downloaded file matches the expected checksum
        anyhow::ensure!(
            computed_sha512.to_lowercase() == expected_sha512.to_lowercase(),
            "downloaded image checksum mismatch: expected {}, got {}",
            expected_sha512,
            computed_sha512
        );

        Ok(())
    }

    async fn extract(&self, name: &str) -> Result<(PathBuf, PathBuf)> {
        let file_name = format!("{}.qcow2", name);
        let dirs = QleanDirs::new()?;
        let image_dir = dirs.images.join(name);

        let output = tokio::process::Command::new("guestfish")
            .env("LIBGUESTFS_BACKEND", "direct")
            .arg("--ro")
            .arg("-a")
            .arg(&file_name)
            .arg("-i")
            .arg("ls")
            .arg("/boot")
            .current_dir(&image_dir)
            .output()
            .await
            .with_context(|| "failed to execute guestfish")?;

        if !output.status.success() {
            bail!(
                "guestfish failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        let boot_files = String::from_utf8_lossy(&output.stdout);
        let mut kernel_name = None;
        let mut initrd_name = None;

        for line in boot_files.lines() {
            let file = line.trim();
            if file.starts_with("vmlinuz") {
                kernel_name = Some(file.to_string());
            } else if file.starts_with("initrd.img") {
                initrd_name = Some(file.to_string());
            }
        }

        let kernel_name =
            kernel_name.with_context(|| "failed to find kernel file (vmlinuz*) in /boot")?;
        let initrd_name =
            initrd_name.with_context(|| "failed to find initrd file (initrd.img*) in /boot")?;

        let kernel_src = format!("/boot/{}", kernel_name);
        let output = tokio::process::Command::new("virt-copy-out")
            .env("LIBGUESTFS_BACKEND", "direct")
            .arg("-a")
            .arg(&file_name)
            .arg(&kernel_src)
            .arg(".")
            .current_dir(&image_dir)
            .output()
            .await
            .with_context(|| format!("failed to execute virt-copy-out for {}", kernel_name))?;

        if !output.status.success() {
            bail!(
                "virt-copy-out failed for kernel: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        let initrd_src = format!("/boot/{}", initrd_name);
        let output = tokio::process::Command::new("virt-copy-out")
            .env("LIBGUESTFS_BACKEND", "direct")
            .arg("-a")
            .arg(&file_name)
            .arg(&initrd_src)
            .arg(".")
            .current_dir(&image_dir)
            .output()
            .await
            .with_context(|| format!("failed to execute virt-copy-out for {}", initrd_name))?;

        if !output.status.success() {
            bail!(
                "virt-copy-out failed for initrd: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        let kernel_path = image_dir.join(&kernel_name);
        let initrd_path = image_dir.join(&initrd_name);

        Ok((kernel_path, initrd_path))
    }

    fn distro(&self) -> Distro {
        Distro::Debian
    }
}

// ---------------------------------------------------------------------------
// Ubuntu - uses pre-extracted kernel/initrd from official cloud images
// ---------------------------------------------------------------------------

#[derive(Debug, Default)]
pub struct Ubuntu {}

impl ImageAction for Ubuntu {
    async fn download(&self, name: &str) -> Result<()> {
        let dirs = QleanDirs::new()?;
        let image_dir = dirs.images.join(name);

        // Ubuntu noble (24.04 LTS) cloud image base URL
        let base_url = "https://cloud-images.ubuntu.com/noble/current";

        // Download qcow2 image
        let qcow2_url = format!("{}/noble-server-cloudimg-amd64.img", base_url);
        let qcow2_path = image_dir.join(format!("{}.qcow2", name));
        download_file(&qcow2_url, &qcow2_path).await?;

        // Download pre-extracted kernel
        let kernel_url = format!(
            "{}/unpacked/noble-server-cloudimg-amd64-vmlinuz-generic",
            base_url
        );
        let kernel_path = image_dir.join("vmlinuz");
        download_file(&kernel_url, &kernel_path).await?;

        // Download pre-extracted initrd
        let initrd_url = format!(
            "{}/unpacked/noble-server-cloudimg-amd64-initrd-generic",
            base_url
        );
        let initrd_path = image_dir.join("initrd.img");
        download_file(&initrd_url, &initrd_path).await?;

        Ok(())
    }

    async fn extract(&self, name: &str) -> Result<(PathBuf, PathBuf)> {
        // Files already downloaded in download() phase
        let dirs = QleanDirs::new()?;
        let image_dir = dirs.images.join(name);

        let kernel = image_dir.join("vmlinuz");
        let initrd = image_dir.join("initrd.img");

        anyhow::ensure!(kernel.exists(), "kernel file not found after download");
        anyhow::ensure!(initrd.exists(), "initrd file not found after download");

        Ok((kernel, initrd))
    }

    fn distro(&self) -> Distro {
        Distro::Ubuntu
    }
}

// ---------------------------------------------------------------------------
// Fedora - uses pre-extracted kernel/initrd from official cloud images
// ---------------------------------------------------------------------------

#[derive(Debug, Default)]
pub struct Fedora {}

impl ImageAction for Fedora {
    async fn download(&self, name: &str) -> Result<()> {
        let dirs = QleanDirs::new()?;
        let image_dir = dirs.images.join(name);

        let resolved = resolve_latest_fedora_cloud_qcow2().await?;
        debug!(
            "Resolved Fedora Cloud qcow2 (sha256={}): {} mirror(s)",
            resolved.sha256,
            resolved.urls.len()
        );

        // Download + verify sha256 in one pass.
        let qcow2_path = image_dir.join(format!("{}.qcow2", name));
        let (_hash, used_url) = download_with_hash_multi(
            &resolved.urls,
            &qcow2_path,
            ShaType::Sha256,
            Some(&resolved.sha256),
        )
        .await
        .with_context(|| "failed to download Fedora cloud image from all mirrors")?;
        debug!(
            "Fedora cloud image downloaded successfully from {}",
            used_url
        );

        // Fedora cloud images don't provide pre-extracted boot files
        // We'll need to extract them using guestfish
        Ok(())
    }

    async fn extract(&self, name: &str) -> Result<(PathBuf, PathBuf)> {
        let file_name = format!("{}.qcow2", name);
        let dirs = QleanDirs::new()?;
        let image_dir = dirs.images.join(name);

        // Use guestfish to list boot files
        let output = tokio::process::Command::new("guestfish")
            .env("LIBGUESTFS_BACKEND", "direct")
            .arg("--ro")
            .arg("-a")
            .arg(&file_name)
            .arg("-i")
            .arg("ls")
            .arg("/boot")
            .current_dir(&image_dir)
            .output()
            .await
            .with_context(|| "failed to execute guestfish")?;

        if !output.status.success() {
            bail!(
                "guestfish failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        let boot_files = String::from_utf8_lossy(&output.stdout);
        let mut kernel_name = None;
        let mut initrd_name = None;

        for line in boot_files.lines() {
            let file = line.trim();
            if file.starts_with("vmlinuz") {
                kernel_name = Some(file.to_string());
            } else if file.starts_with("initramfs") {
                initrd_name = Some(file.to_string());
            }
        }

        let kernel_name =
            kernel_name.with_context(|| "failed to find kernel file (vmlinuz*) in /boot")?;
        let initrd_name =
            initrd_name.with_context(|| "failed to find initrd file (initramfs*) in /boot")?;

        // Extract kernel
        let kernel_src = format!("/boot/{}", kernel_name);
        let output = tokio::process::Command::new("virt-copy-out")
            .env("LIBGUESTFS_BACKEND", "direct")
            .arg("-a")
            .arg(&file_name)
            .arg(&kernel_src)
            .arg(".")
            .current_dir(&image_dir)
            .output()
            .await
            .with_context(|| format!("failed to execute virt-copy-out for {}", kernel_name))?;

        if !output.status.success() {
            bail!(
                "virt-copy-out failed for kernel: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        // Extract initrd
        let initrd_src = format!("/boot/{}", initrd_name);
        let output = tokio::process::Command::new("virt-copy-out")
            .env("LIBGUESTFS_BACKEND", "direct")
            .arg("-a")
            .arg(&file_name)
            .arg(&initrd_src)
            .arg(".")
            .current_dir(&image_dir)
            .output()
            .await
            .with_context(|| format!("failed to execute virt-copy-out for {}", initrd_name))?;

        if !output.status.success() {
            bail!(
                "virt-copy-out failed for initrd: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        let kernel_path = image_dir.join(&kernel_name);
        let initrd_path = image_dir.join(&initrd_name);

        Ok((kernel_path, initrd_path))
    }

    fn distro(&self) -> Distro {
        Distro::Fedora
    }
}

// ---------------------------------------------------------------------------
// Arch - uses official cloud images
// ---------------------------------------------------------------------------

#[derive(Debug, Default)]
pub struct Arch {}

impl ImageAction for Arch {
    async fn download(&self, name: &str) -> Result<()> {
        let dirs = QleanDirs::new()?;
        let image_dir = dirs.images.join(name);

        let resolved = resolve_latest_arch_cloudimg().await?;
        debug!(
            "Resolved Arch cloudimg (sha256={}): {} mirror(s)",
            resolved.sha256,
            resolved.urls.len()
        );

        // Download + verify sha256 in one pass.
        let qcow2_path = image_dir.join(format!("{}.qcow2", name));
        let (_hash, used_url) = download_with_hash_multi(
            &resolved.urls,
            &qcow2_path,
            ShaType::Sha256,
            Some(&resolved.sha256),
        )
        .await
        .with_context(|| "failed to download Arch cloud image from all mirrors")?;
        debug!("Arch cloud image downloaded successfully from {}", used_url);

        Ok(())
    }

    async fn extract(&self, name: &str) -> Result<(PathBuf, PathBuf)> {
        let file_name = format!("{}.qcow2", name);
        let dirs = QleanDirs::new()?;
        let image_dir = dirs.images.join(name);

        // Use guestfish to list boot files
        let output = tokio::process::Command::new("guestfish")
            .env("LIBGUESTFS_BACKEND", "direct")
            .arg("--ro")
            .arg("-a")
            .arg(&file_name)
            .arg("-i")
            .arg("ls")
            .arg("/boot")
            .current_dir(&image_dir)
            .output()
            .await
            .with_context(|| "failed to execute guestfish")?;

        if !output.status.success() {
            bail!(
                "guestfish failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        let boot_files = String::from_utf8_lossy(&output.stdout);
        let mut kernel_name = None;
        let mut initrd_name = None;

        for line in boot_files.lines() {
            let file = line.trim();
            // Arch uses vmlinuz-linux
            if file.starts_with("vmlinuz") {
                kernel_name = Some(file.to_string());
            } else if file.starts_with("initramfs") && file.contains("linux.img") {
                initrd_name = Some(file.to_string());
            }
        }

        let kernel_name =
            kernel_name.with_context(|| "failed to find kernel file (vmlinuz*) in /boot")?;
        let initrd_name = initrd_name
            .with_context(|| "failed to find initrd file (initramfs*linux.img) in /boot")?;

        // Extract kernel
        let kernel_src = format!("/boot/{}", kernel_name);
        let output = tokio::process::Command::new("virt-copy-out")
            .env("LIBGUESTFS_BACKEND", "direct")
            .arg("-a")
            .arg(&file_name)
            .arg(&kernel_src)
            .arg(".")
            .current_dir(&image_dir)
            .output()
            .await
            .with_context(|| format!("failed to execute virt-copy-out for {}", kernel_name))?;

        if !output.status.success() {
            bail!(
                "virt-copy-out failed for kernel: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        // Extract initrd
        let initrd_src = format!("/boot/{}", initrd_name);
        let output = tokio::process::Command::new("virt-copy-out")
            .env("LIBGUESTFS_BACKEND", "direct")
            .arg("-a")
            .arg(&file_name)
            .arg(&initrd_src)
            .arg(".")
            .current_dir(&image_dir)
            .output()
            .await
            .with_context(|| format!("failed to execute virt-copy-out for {}", initrd_name))?;

        if !output.status.success() {
            bail!(
                "virt-copy-out failed for initrd: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        let kernel_path = image_dir.join(&kernel_name);
        let initrd_path = image_dir.join(&initrd_name);

        Ok((kernel_path, initrd_path))
    }

    fn distro(&self) -> Distro {
        Distro::Arch
    }
}

// ---------------------------------------------------------------------------
// Custom - user-provided image with flexible configuration (WSL-friendly)
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub struct Custom {
    pub config: CustomImageConfig,
}

impl Custom {
    pub fn new(config: CustomImageConfig) -> Self {
        Custom { config }
    }
}

impl ImageAction for Custom {
    async fn download(&self, name: &str) -> Result<()> {
        let dirs = QleanDirs::new()?;
        let image_dir = dirs.images.join(name);

        // Download main image file
        let image_path = image_dir.join(format!("{}.qcow2", name));
        download_or_copy_with_hash(
            &self.config.image_source,
            &image_path,
            &self.config.image_hash,
            self.config.image_hash_type.clone(),
        )
        .await?;

        // Download kernel if provided
        if let (Some(kernel_src), Some(kernel_hash)) =
            (&self.config.kernel_source, &self.config.kernel_hash)
        {
            let kernel_path = image_dir.join("vmlinuz");
            download_or_copy_with_hash(
                kernel_src,
                &kernel_path,
                kernel_hash,
                self.config.image_hash_type.clone(),
            )
            .await?;
        }

        // Download initrd if provided
        if let (Some(initrd_src), Some(initrd_hash)) =
            (&self.config.initrd_source, &self.config.initrd_hash)
        {
            let initrd_path = image_dir.join("initrd.img");
            download_or_copy_with_hash(
                initrd_src,
                &initrd_path,
                initrd_hash,
                self.config.image_hash_type.clone(),
            )
            .await?;
        }

        Ok(())
    }

    async fn extract(&self, name: &str) -> Result<(PathBuf, PathBuf)> {
        let dirs = QleanDirs::new()?;
        let image_dir = dirs.images.join(name);

        // Check if kernel/initrd were pre-provided
        let kernel_path = image_dir.join("vmlinuz");
        let initrd_path = image_dir.join("initrd.img");

        if kernel_path.exists() && initrd_path.exists() {
            debug!("Using pre-provided kernel and initrd files");
            return Ok((kernel_path, initrd_path));
        }

        // Otherwise, try to extract using guestfish
        let file_name = format!("{}.qcow2", name);

        let output = tokio::process::Command::new("guestfish")
            .env("LIBGUESTFS_BACKEND", "direct")
            .arg("--ro")
            .arg("-a")
            .arg(&file_name)
            .arg("-i")
            .arg("ls")
            .arg("/boot")
            .current_dir(&image_dir)
            .output()
            .await;

        if let Ok(output) = output
            && output.status.success()
        {
            let boot_files = String::from_utf8_lossy(&output.stdout);
            let mut kernel_name = None;
            let mut initrd_name = None;

            // Generic kernel/initrd detection
            for line in boot_files.lines() {
                let file = line.trim();
                if kernel_name.is_none()
                    && (file.starts_with("vmlinuz") || file.starts_with("bzImage"))
                {
                    kernel_name = Some(file.to_string());
                }
                if initrd_name.is_none()
                    && (file.starts_with("initrd") || file.starts_with("initramfs"))
                {
                    initrd_name = Some(file.to_string());
                }
            }

            if let (Some(kernel), Some(initrd)) = (kernel_name, initrd_name) {
                // Extract using virt-copy-out
                for (file, desc) in [(&kernel, "kernel"), (&initrd, "initrd")] {
                    let src = format!("/boot/{}", file);
                    let output = tokio::process::Command::new("virt-copy-out")
                        .env("LIBGUESTFS_BACKEND", "direct")
                        .arg("-a")
                        .arg(&file_name)
                        .arg(&src)
                        .arg(".")
                        .current_dir(&image_dir)
                        .output()
                        .await?;

                    if !output.status.success() {
                        bail!("virt-copy-out failed for {}", desc);
                    }
                }

                return Ok((image_dir.join(&kernel), image_dir.join(&initrd)));
            }
        }

        // Guestfish not available or failed - provide helpful error
        bail!(
            "Custom image requires either:\n\
             \n\
             1. Pre-extracted boot files (RECOMMENDED for WSL):\n\
                - Provide kernel_source, kernel_hash, initrd_source, initrd_hash in config\n\
                - See documentation for examples\n\
             \n\
             2. Guestfish for extraction (native Linux only):\n\
                - Install: sudo apt install libguestfs-tools\n\
                - Provide only image_source/image_hash in config\n\
                - Not supported on WSL/WSL2"
        );
    }

    fn distro(&self) -> Distro {
        Distro::Custom
    }
}

// Helper function to download a file
async fn download_file(url: &str, dest: &PathBuf) -> Result<()> {
    debug!("Downloading {} to {}", url, dest.display());
    let response = reqwest::get(url)
        .await
        .with_context(|| format!("failed to download from {}", url))?;

    let mut file = File::create(dest)
        .await
        .with_context(|| format!("failed to create file at {}", dest.display()))?;

    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.with_context(|| "failed to read chunk from stream")?;
        file.write_all(&chunk)
            .await
            .with_context(|| "failed to write to file")?;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Image wrapper enum
// ---------------------------------------------------------------------------

/// Wrapper enum for different Image types
#[derive(Debug)]
pub enum Image {
    Debian(ImageMeta<Debian>),
    Ubuntu(ImageMeta<Ubuntu>),
    Fedora(ImageMeta<Fedora>),
    Arch(ImageMeta<Arch>),
    Custom(ImageMeta<Custom>),
}

impl Image {
    /// Get the underlying name regardless of distro
    pub fn name(&self) -> &str {
        match self {
            Image::Debian(img) => &img.name,
            Image::Ubuntu(img) => &img.name,
            Image::Fedora(img) => &img.name,
            Image::Arch(img) => &img.name,
            Image::Custom(img) => &img.name,
        }
    }

    /// Get the underlying image path regardless of distro
    pub fn path(&self) -> &PathBuf {
        match self {
            Image::Debian(img) => &img.path,
            Image::Ubuntu(img) => &img.path,
            Image::Fedora(img) => &img.path,
            Image::Arch(img) => &img.path,
            Image::Custom(img) => &img.path,
        }
    }

    /// Get the kernel path regardless of distro
    pub fn kernel(&self) -> &PathBuf {
        match self {
            Image::Debian(img) => &img.kernel,
            Image::Ubuntu(img) => &img.kernel,
            Image::Fedora(img) => &img.kernel,
            Image::Arch(img) => &img.kernel,
            Image::Custom(img) => &img.kernel,
        }
    }

    /// Get the initrd path regardless of distro
    pub fn initrd(&self) -> &PathBuf {
        match self {
            Image::Debian(img) => &img.initrd,
            Image::Ubuntu(img) => &img.initrd,
            Image::Fedora(img) => &img.initrd,
            Image::Arch(img) => &img.initrd,
            Image::Custom(img) => &img.initrd,
        }
    }
}

/// Factory function to create Image instances based on distro
pub async fn create_image(distro: Distro, name: &str) -> Result<Image> {
    match distro {
        Distro::Debian => {
            let image = ImageMeta::<Debian>::create(name).await?;
            Ok(Image::Debian(image))
        }
        Distro::Ubuntu => {
            let image = ImageMeta::<Ubuntu>::create(name).await?;
            Ok(Image::Ubuntu(image))
        }
        Distro::Fedora => {
            let image = ImageMeta::<Fedora>::create(name).await?;
            Ok(Image::Fedora(image))
        }
        Distro::Arch => {
            let image = ImageMeta::<Arch>::create(name).await?;
            Ok(Image::Arch(image))
        }
        Distro::Custom => {
            bail!("use create_custom_image() for custom images");
        }
    }
}

/// Factory function for custom images
pub async fn create_custom_image(name: &str, config: CustomImageConfig) -> Result<Image> {
    let action = Custom::new(config);
    let image = ImageMeta::create_with_action(name, action).await?;
    Ok(Image::Custom(image))
}

/// Calculate SHA256 with command line tool `sha256sum`
pub async fn get_sha256(path: &PathBuf) -> Result<String> {
    let output = tokio::process::Command::new("sha256sum")
        .arg(path)
        .output()
        .await
        .with_context(|| format!("failed to execute sha256sum on {}", path.display()))?;

    if !output.status.success() {
        bail!(
            "sha256sum failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let sha256 = stdout
        .split_whitespace()
        .next()
        .with_context(|| "failed to parse sha256sum output")?
        .to_string();

    Ok(sha256)
}

/// Calculate SHA512 with command line tool `sha512sum`
pub async fn get_sha512(path: &PathBuf) -> Result<String> {
    let output = tokio::process::Command::new("sha512sum")
        .arg(path)
        .output()
        .await
        .with_context(|| format!("failed to execute sha512sum on {}", path.display()))?;

    if !output.status.success() {
        bail!(
            "sha512sum failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let sha512 = stdout
        .split_whitespace()
        .next()
        .with_context(|| "failed to parse sha512sum output")?
        .to_string();

    Ok(sha512)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    fn test_subscriber_init() {
        // Keep test logging setup local to this module to avoid coupling
        // image unit tests to integration-test helpers.
        use std::sync::Once;
        use tracing_subscriber::{EnvFilter, fmt::time::LocalTime};

        static INIT: Once = Once::new();
        INIT.call_once(|| {
            tracing_subscriber::fmt()
                .with_env_filter(EnvFilter::from_default_env())
                .with_timer(LocalTime::rfc_3339())
                .try_init()
                .ok();
        });
    }

    #[test]
    fn test_find_sha512_for_exact_filename() {
        let checksums = "\
748f52b959f63352e1e121508cedeae2e66d3e90be00e6420a0b8b9f14a0f84dc54ed801fb5be327866876268b808543465b1613c8649efeeb5f987ff9df1549  debian-13-generic-amd64.json
\
f0442f3cd0087a609ecd5241109ddef0cbf4a1e05372e13d82c97fc77b35b2d8ecff85aea67709154d84220059672758508afbb0691c41ba8aa6d76818d89d65  debian-13-generic-amd64.qcow2";
        let result = find_sha512_for_file(checksums, "debian-13-generic-amd64.qcow2");
        assert_eq!(
            result,
            Some("f0442f3cd0087a609ecd5241109ddef0cbf4a1e05372e13d82c97fc77b35b2d8ecff85aea67709154d84220059672758508afbb0691c41ba8aa6d76818d89d65".to_string())
        );
    }

    #[test]
    fn test_custom_image_config_serde() {
        let config = CustomImageConfig {
            image_source: ImageSource::Url("https://example.com/image.qcow2".to_string()),
            image_hash: "abcdef123456".to_string(),
            image_hash_type: ShaType::Sha256,
            kernel_source: Some(ImageSource::Url("https://example.com/vmlinuz".to_string())),
            kernel_hash: Some("kernel123".to_string()),
            initrd_source: Some(ImageSource::Url("https://example.com/initrd".to_string())),
            initrd_hash: Some("initrd456".to_string()),
        };

        let json = serde_json::to_string(&config).unwrap();
        let decoded: CustomImageConfig = serde_json::from_str(&json).unwrap();

        assert_eq!(decoded, config);
    }

    #[test]
    fn test_find_hash_for_file_formats() {
        // Format 1: "<hex>  <filename>"
        let f1 = "abc123  foo.bin\n012345  bar.bin";
        assert_eq!(
            find_hash_for_file(f1, "bar.bin"),
            Some("012345".to_string())
        );

        // Format 2: "SHA256 (<filename>) = <hex>"
        let f2 = "SHA256 (image.qcow2) = deadbeef\nSHA256 (other) = 00";
        assert_eq!(
            find_hash_for_file(f2, "image.qcow2"),
            Some("deadbeef".to_string())
        );

        // Format 2: SHA512 variant
        let f3 = "SHA512 (k) = aaa\nSHA512 (initrd.img) = bbb";
        assert_eq!(
            find_hash_for_file(f3, "initrd.img"),
            Some("bbb".to_string())
        );
    }

    #[test]
    fn test_parse_fedora_cloud_listing() {
        let html = r#"
            <a href=\"Fedora-Cloud-43-1.6-x86_64-CHECKSUM\">Fedora-Cloud-43-1.6-x86_64-CHECKSUM</a>
            <a href=\"Fedora-Cloud-Base-Generic-43-1.6.x86_64.qcow2\">Fedora-Cloud-Base-Generic-43-1.6.x86_64.qcow2</a>
        "#;
        let (qcow2, checksum) = parse_fedora_cloud_listing(html, "43").unwrap();
        assert_eq!(qcow2, "Fedora-Cloud-Base-Generic-43-1.6.x86_64.qcow2");
        assert_eq!(checksum, "Fedora-Cloud-43-1.6-x86_64-CHECKSUM");
    }

    #[tokio::test]
    async fn test_streaming_sha256_empty_file() -> Result<()> {
        let tmp = tempfile::NamedTempFile::new()?;
        let path = tmp.path();

        let hash = compute_sha256_streaming(path).await?;

        // SHA-256 of empty file
        assert_eq!(
            hash,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );

        Ok(())
    }

    #[tokio::test]
    #[serial]
    async fn test_streaming_vs_shell_sha256() -> Result<()> {
        let tmp = tempfile::NamedTempFile::new()?;
        let path = tmp.path().to_path_buf();

        {
            use std::io::Write;
            let mut f = std::fs::File::create(&path)?;
            f.write_all(b"streaming hash test data")?;
        }

        let shell = get_sha256(&path).await?;
        let stream = compute_sha256_streaming(&path).await?;

        assert_eq!(shell, stream, "streaming must match shell");

        Ok(())
    }

    #[tokio::test]
    #[serial]
    async fn test_streaming_vs_shell_sha512() -> Result<()> {
        let tmp = tempfile::NamedTempFile::new()?;
        let path = tmp.path().to_path_buf();

        {
            use std::io::Write;
            let mut f = std::fs::File::create(&path)?;
            f.write_all(b"streaming hash test data")?;
        }

        let shell = get_sha512(&path).await?;
        let stream = compute_sha512_streaming(&path).await?;

        assert_eq!(shell, stream, "streaming must match shell");

        Ok(())
    }

    #[tokio::test]
    #[serial]
    async fn test_custom_image_nonexistent_local_path() -> Result<()> {
        test_subscriber_init();

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
        test_subscriber_init();

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
}
