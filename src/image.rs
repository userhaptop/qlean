use std::{
    ffi::OsStr,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use futures::StreamExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};
use tokio::{
    fs::File,
    io::AsyncWriteExt,
    time::{Duration, timeout},
};
use tracing::{debug, info, warn};

use crate::utils::{QleanDirs, ensure_extraction_prerequisites};

fn default_root_arg() -> String {
    "root=/dev/vda1".to_string()
}

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
    #[serde(default = "default_root_arg")]
    pub root_arg: String,
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

/// Normalize checksum entry names across common checksum file formats.
fn normalize_checksum_name(name: &str) -> &str {
    name.trim_start_matches('*').trim_start_matches("./")
}

fn checksum_name_matches(entry_name: &str, wanted: &str) -> bool {
    let entry = normalize_checksum_name(entry_name);
    let wanted = normalize_checksum_name(wanted);
    if entry == wanted {
        return true;
    }
    if !wanted.contains('/')
        && let Some(base) = entry.rsplit('/').next()
    {
        return base == wanted;
    }
    false
}

/// Parses checksum text and returns the hash for a filename.
pub fn find_sha512_for_file(checksums_text: &str, filename: &str) -> Option<String> {
    find_hash_for_file(checksums_text, filename)
}

/// Parse a checksum file and return the hash for a given filename.
///
/// Supports common formats:
/// 1) "<hex>  <filename>" (including "*filename" and "./filename")
/// 2) "SHA256 (<filename>) = <hex>" / "SHA512 (<filename>) = <hex>"
pub fn find_hash_for_file(checksums_text: &str, filename: &str) -> Option<String> {
    let mut parts = checksums_text.split_whitespace();
    while let Some(hash) = parts.next() {
        let Some(fname) = parts.next() else { break };
        if checksum_name_matches(fname, filename) {
            return Some(hash.to_string());
        }
    }

    for line in checksums_text.lines() {
        let line = line.trim();
        for prefix in ["SHA256 (", "SHA512 ("] {
            if let Some(rest) = line.strip_prefix(prefix)
                && let Some((entry_name, hash_part)) = rest.split_once(") = ")
                && checksum_name_matches(entry_name, filename)
            {
                return Some(hash_part.trim().to_string());
            }
        }
    }

    None
}

fn join_url(base: &str, path: &str) -> String {
    format!(
        "{}/{}",
        base.trim_end_matches('/'),
        path.trim_start_matches('/')
    )
}

async fn fetch_ubuntu_sha256sums(base_url: &str) -> Result<String> {
    let primary = join_url(base_url, "SHA256SUMS");
    match fetch_text(&primary).await {
        Ok(text) => Ok(text),
        Err(primary_err) => {
            let fallback = join_url(base_url, "SHA256SUMS.txt");
            fetch_text(&fallback).await.with_context(|| {
                format!(
                    "failed to fetch Ubuntu checksums from {} or {} ({:#})",
                    primary, fallback, primary_err
                )
            })
        }
    }
}

#[derive(Debug, Clone)]
struct ResolvedUbuntuCloudImage {
    base_url: String,
    disk_name: String,
    kernel_name: String,
    initrd_name: String,
    disk_sha256: String,
    kernel_sha256: Option<String>,
    initrd_sha256: Option<String>,
}

fn pick_existing_ubuntu_name(checksums: &str, candidates: &[&str]) -> Option<String> {
    candidates
        .iter()
        .find(|name| {
            checksums.contains(&format!(" {}", name)) || checksums.contains(&format!(" *{}", name))
        })
        .map(|name| (*name).to_string())
}

async fn resolve_ubuntu_noble_cloudimg() -> Result<ResolvedUbuntuCloudImage> {
    let bases = [
        "https://cloud-images.ubuntu.com/releases/noble/release",
        "https://cloud-images.ubuntu.com/noble/current",
        "https://cloud-images.ubuntu.com/daily/server/releases/noble/release",
    ];

    let mut last_err: Option<anyhow::Error> = None;

    for (idx, base) in bases.iter().enumerate() {
        info!("Ubuntu metadata source {}/{}", idx + 1, bases.len());

        let checksums = match fetch_ubuntu_sha256sums(base).await {
            Ok(v) => v,
            Err(e) => {
                last_err = Some(e);
                continue;
            }
        };

        let disk_name = match pick_existing_ubuntu_name(
            &checksums,
            &[
                "ubuntu-24.04-server-cloudimg-amd64.img",
                "noble-server-cloudimg-amd64.img",
            ],
        ) {
            Some(v) => v,
            None => {
                last_err = Some(anyhow::anyhow!(
                    "Ubuntu SHA256SUMS did not contain amd64 cloud image entry"
                ));
                continue;
            }
        };

        let stem = disk_name.strip_suffix(".img").unwrap_or(&disk_name);
        let kernel_name = format!("{}-vmlinuz-generic", stem);
        let initrd_name = format!("{}-initrd-generic", stem);

        let disk_sha256 = match ubuntu_sha256_for(&checksums, &disk_name) {
            Ok(v) => v,
            Err(e) => {
                last_err = Some(e);
                continue;
            }
        };
        let kernel_sha256 = ubuntu_sha256_for(&checksums, &format!("unpacked/{}", kernel_name))
            .or_else(|_| ubuntu_sha256_for(&checksums, &kernel_name))
            .ok();
        if kernel_sha256.is_none() {
            warn!(
                "Ubuntu SHA256SUMS did not include kernel checksum for {}; proceeding without kernel hash verification",
                kernel_name
            );
        }

        let initrd_sha256 = ubuntu_sha256_for(&checksums, &format!("unpacked/{}", initrd_name))
            .or_else(|_| ubuntu_sha256_for(&checksums, &initrd_name))
            .ok();
        if initrd_sha256.is_none() {
            warn!(
                "Ubuntu SHA256SUMS did not include initrd checksum for {}; proceeding without initrd hash verification",
                initrd_name
            );
        }

        return Ok(ResolvedUbuntuCloudImage {
            base_url: (*base).to_string(),
            disk_name,
            kernel_name,
            initrd_name,
            disk_sha256,
            kernel_sha256,
            initrd_sha256,
        });
    }

    Err(last_err
        .unwrap_or_else(|| anyhow::anyhow!("failed to resolve Ubuntu cloud image metadata")))
}

fn ubuntu_sha256_for(checksums: &str, filename: &str) -> Result<String> {
    find_hash_for_file(checksums, filename)
        .with_context(|| format!("Ubuntu SHA256SUMS did not contain hash for {}", filename))
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
const FALLBACK_FEDORA_RELEASE: &str = "43";

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
    match fetch_text(url).await {
        Ok(body) => {
            let parsed: EolResp = serde_json::from_str(&body)
                .with_context(|| "failed to parse Fedora release JSON")?;

            let latest = parsed
                .result
                .releases
                .into_iter()
                .find(|r| r.is_maintained && !r.is_eol)
                .map(|r| r.name)
                .with_context(|| "could not determine latest maintained Fedora release")?;

            Ok(latest)
        }
        Err(err) => {
            warn!(
                "failed to query endoflife.date for latest Fedora release ({}); falling back to {}",
                err, FALLBACK_FEDORA_RELEASE
            );
            Ok(FALLBACK_FEDORA_RELEASE.to_string())
        }
    }
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

    // Build base URLs. Prefer bases where listing worked, but also try the
    // full candidate set as a fallback (a mirror may block directory listing
    // but still serve the file).
    let mut bases = good_bases;
    for c in &candidates {
        if !bases.iter().any(|b| b == c) {
            bases.push(c.clone());
        }
    }

    // Fetch CHECKSUM across mirrors too. Relying on a single mirror defeats
    // the multi-mirror resilience we provide for the qcow2 download.
    let sha256 = fetch_fedora_checksum_sha256(&bases, &checksum_name, &qcow2_name).await?;

    let urls = bases
        .into_iter()
        .map(|base| format!("{}{}", base, qcow2_name))
        .collect::<Vec<_>>();

    Ok(ResolvedRemote { urls, sha256 })
}

async fn fetch_fedora_checksum_sha256(
    bases: &[String],
    checksum_name: &str,
    qcow2_name: &str,
) -> Result<String> {
    let mut last_err: Option<anyhow::Error> = None;

    for base in bases {
        let checksum_url = format!("{}{}", base, checksum_name);
        match fetch_text(&checksum_url).await {
            Ok(text) => {
                if let Some(sha) = find_hash_for_file(&text, qcow2_name) {
                    return Ok(sha);
                }

                last_err = Some(anyhow::anyhow!(
                    "checksum file {} did not contain hash for {}",
                    checksum_url,
                    qcow2_name
                ));
            }
            Err(e) => {
                debug!("Fedora CHECKSUM fetch failed for {}: {:#}", checksum_url, e);
                last_err = Some(e);
            }
        }
    }

    Err(last_err.unwrap_or_else(|| anyhow::anyhow!("failed to fetch Fedora CHECKSUM from mirrors")))
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
    let bases = [
        "https://mirrors.tuna.tsinghua.edu.cn/archlinux/images/latest",
        "https://mirrors.ustc.edu.cn/archlinux/images/latest",
        "https://mirrors.sjtug.sjtu.edu.cn/archlinux/images/latest",
        "https://fastly.mirror.pkgbuild.com/images/latest",
        "https://geo.mirror.pkgbuild.com/images/latest",
        "https://mirror.citrahost.com/archlinux/images/latest",
        "https://mirrors.teamcloud.am/archlinux/images/latest",
        "https://mirror.umd.edu/archlinux/images/latest",
        "https://ftp.jaist.ac.jp/pub/Linux/ArchLinux/images/latest",
    ];
    let filename = "Arch-Linux-x86_64-cloudimg.qcow2";

    info!("Resolving Arch cloud image metadata");

    let mut last_err: Option<anyhow::Error> = None;
    let mut selected_base: Option<&str> = None;
    let mut sha256: Option<String> = None;

    for (idx, base) in bases.iter().enumerate() {
        info!("Arch metadata mirror {}/{}", idx + 1, bases.len());
        let sha_url = format!("{}/{}.SHA256", base, filename);
        match fetch_text(&sha_url).await {
            Ok(text) => {
                if let Some(hash) = find_hash_for_file(&text, filename) {
                    selected_base = Some(*base);
                    sha256 = Some(hash);
                    break;
                }
                last_err = Some(anyhow::anyhow!("invalid checksum format at {}", sha_url));
            }
            Err(e) => {
                debug!("Arch metadata fetch failed for {}: {:#}", sha_url, e);
                last_err = Some(e);
            }
        }
    }

    let selected_base = selected_base.ok_or_else(|| {
        last_err.unwrap_or_else(|| anyhow::anyhow!("no Arch mirror metadata succeeded"))
    })?;
    let sha256 = sha256.expect("sha256 must exist when metadata resolves");

    let mut urls = vec![format!("{}/{}", selected_base, filename)];
    for base in bases {
        if base != selected_base {
            urls.push(format!("{}/{}", base, filename));
        }
    }

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

    info!("Downloading image from {}", url);
    let response = tokio::time::timeout(std::time::Duration::from_secs(30), client.get(url).send())
        .await
        .with_context(|| format!("timed out before response headers from {}", url))?
        .with_context(|| format!("failed to download from {}", url))?;

    let status = response.status();
    let total_size = response.content_length();
    anyhow::ensure!(status.is_success(), "GET {} failed: {}", url, status);
    if let Some(total) = total_size {
        info!("Remote size: {} MiB ({})", total / (1024 * 1024), url);
    }

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
    let idle = std::time::Duration::from_secs(60);
    let mut downloaded: u64 = 0;
    let mut last_report: u64 = 0;
    // Report download progress in reasonably small increments. On slower links (or in CI/WSL),
    // 64MiB can take long enough that the test runner prints a scary "running over 60 seconds"
    // warning with no other output.
    let report_step: u64 = 8 * 1024 * 1024; // 8 MiB
    let started_at = std::time::Instant::now();
    let mut last_report_at = started_at;

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
                let now = std::time::Instant::now();
                if downloaded - last_report >= report_step
                    || (downloaded > 0
                        && now.duration_since(last_report_at) >= std::time::Duration::from_secs(10))
                {
                    last_report = downloaded;
                    last_report_at = now;
                    if let Some(total) = total_size {
                        info!(
                            "Download progress: {}/{} MiB ({})",
                            downloaded / (1024 * 1024),
                            total / (1024 * 1024),
                            url
                        );
                    } else {
                        info!(
                            "Download progress: {} MiB ({})",
                            downloaded / (1024 * 1024),
                            url
                        );
                    }
                }
                if started_at.elapsed() >= std::time::Duration::from_secs(90)
                    && downloaded < 32 * 1024 * 1024
                {
                    anyhow::bail!(
                        "download too slow for {} ({} MiB in {:?}); trying next mirror",
                        url,
                        downloaded / (1024 * 1024),
                        started_at.elapsed()
                    );
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
                let now = std::time::Instant::now();
                if downloaded - last_report >= report_step
                    || (downloaded > 0
                        && now.duration_since(last_report_at) >= std::time::Duration::from_secs(10))
                {
                    last_report = downloaded;
                    last_report_at = now;
                    if let Some(total) = total_size {
                        info!(
                            "Download progress: {}/{} MiB ({})",
                            downloaded / (1024 * 1024),
                            total / (1024 * 1024),
                            url
                        );
                    } else {
                        info!(
                            "Download progress: {} MiB ({})",
                            downloaded / (1024 * 1024),
                            url
                        );
                    }
                }
                if started_at.elapsed() >= std::time::Duration::from_secs(90)
                    && downloaded < 32 * 1024 * 1024
                {
                    anyhow::bail!(
                        "download too slow for {} ({} MiB in {:?}); trying next mirror",
                        url,
                        downloaded / (1024 * 1024),
                        started_at.elapsed()
                    );
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

    info!(
        "Download complete: {} MiB ({})",
        downloaded / (1024 * 1024),
        url
    );
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

        info!("Trying mirror {}/{}", idx + 1, urls.len());
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
                let existing = match &hash_type {
                    ShaType::Sha256 => compute_sha256_streaming(dest).await,
                    ShaType::Sha512 => compute_sha512_streaming(dest).await,
                };
                if let Ok(h) = existing
                    && h.eq_ignore_ascii_case(expected_hash)
                {
                    return Ok(());
                }
            }

            let computed = download_with_hash(url, dest, hash_type.clone()).await?;
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

/// Download or copy file from ImageSource without hash verification.
async fn download_or_copy_without_hash(source: &ImageSource, dest: &PathBuf) -> Result<()> {
    match source {
        ImageSource::Url(url) => {
            if dest.exists() {
                return Ok(());
            }
            let _ = download_with_hash(url, dest, ShaType::Sha256).await?;
        }
        ImageSource::LocalPath(src) => {
            anyhow::ensure!(src.exists(), "file does not exist: {}", src.display());
            tokio::fs::copy(src, dest).await?;
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

        let image_path = image_dir.join(format!("{}.qcow2", name));
        let (kernel, initrd) = distro_action.extract(name).await?;
        let checksum_path = image_dir.join("checksums");
        let root_arg = detect_root_arg(&image_path)
            .await
            .unwrap_or_else(|_| default_root_arg());
        let checksum = ShaSum {
            path: checksum_path,
            sha_type: ShaType::Sha512,
        };
        let image = ImageMeta {
            path: image_path,
            kernel,
            initrd,
            root_arg,
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

        let kernel_ok = image.kernel.exists()
            && std::fs::metadata(&image.kernel)
                .map(|m| m.len() > 0)
                .unwrap_or(false);
        let initrd_ok = image.initrd.exists()
            && std::fs::metadata(&image.initrd)
                .map(|m| m.len() > 0)
                .unwrap_or(false);
        if !kernel_ok || !initrd_ok {
            bail!("cached image is missing kernel/initrd markers; recreate is required");
        }

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

        let image_path = image_dir.join(format!("{}.qcow2", name));
        let (kernel, initrd) = action.extract(name).await?;
        let checksum_path = image_dir.join("checksums");
        let root_arg = detect_root_arg(&image_path)
            .await
            .unwrap_or_else(|_| default_root_arg());
        let checksum = ShaSum {
            path: checksum_path,
            sha_type: ShaType::Sha512,
        };
        let image = ImageMeta {
            path: image_path,
            kernel,
            initrd,
            root_arg,
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

async fn ensure_fixed_guestfs_appliance() -> Result<PathBuf> {
    for dir in [
        "/usr/lib/guestfs/appliance",
        "/usr/lib/x86_64-linux-gnu/guestfs/appliance",
    ] {
        let p = PathBuf::from(dir);
        if p.join("kernel").exists() && p.join("initrd").exists() {
            return Ok(p);
        }
    }

    let dirs = QleanDirs::new()?;
    let appliance_dir = dirs.base.join("guestfs-appliance");
    if appliance_dir.join("kernel").exists() && appliance_dir.join("initrd").exists() {
        return Ok(appliance_dir);
    }

    let output = tokio::process::Command::new("libguestfs-make-fixed-appliance")
        .arg(&appliance_dir)
        .output()
        .await
        .with_context(|| "failed to execute libguestfs-make-fixed-appliance")?;
    if !output.status.success() {
        bail!(
            "libguestfs fixed appliance build failed: {}\nInstall package: libguestfs-appliance (or libguestfs-tools) and retry.",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(appliance_dir)
}

async fn run_guestfs_tool(
    program: &str,
    args: &[&OsStr],
    current_dir: &Path,
) -> Result<std::process::Output> {
    async fn run_once(
        program: &str,
        args: &[&OsStr],
        current_dir: &Path,
        appliance: Option<&Path>,
    ) -> Result<std::process::Output> {
        let mut cmd = tokio::process::Command::new(program);
        cmd.env("LIBGUESTFS_BACKEND", "direct")
            .current_dir(current_dir);
        if let Some(appliance_dir) = appliance {
            cmd.env("LIBGUESTFS_PATH", appliance_dir);
        }
        for a in args {
            cmd.arg(a);
        }
        let child = cmd.output();
        let out = timeout(Duration::from_secs(180), child)
            .await
            .with_context(|| format!("{} timed out after 180s (libguestfs)", program))?
            .with_context(|| format!("failed to execute {}", program))?;
        Ok(out)
    }

    let first = run_once(program, args, current_dir, None).await?;
    if !first.status.success() {
        warn!(
            "{} failed (direct backend): {}",
            program,
            String::from_utf8_lossy(&first.stderr)
        );
    }
    if first.status.success() {
        return Ok(first);
    }

    let stderr = String::from_utf8_lossy(&first.stderr);
    let needs_fixed = stderr.contains("supermin exited with error status")
        || stderr.contains("/usr/bin/supermin");
    if needs_fixed && std::env::var_os("LIBGUESTFS_PATH").is_none() {
        let appliance_dir = ensure_fixed_guestfs_appliance().await?;
        return run_once(program, args, current_dir, Some(&appliance_dir)).await;
    }

    Ok(first)
}

async fn guestfish_ls_boot(image_dir: &Path, file_name: &str) -> Result<String> {
    let args = [
        OsStr::new("--ro"),
        OsStr::new("-a"),
        OsStr::new(file_name),
        OsStr::new("-i"),
        OsStr::new("ls"),
        OsStr::new("/boot"),
    ];
    let output = run_guestfs_tool("guestfish", &args, image_dir).await?;
    if !output.status.success() {
        bail!(
            "guestfish failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

async fn virt_copy_out(image_dir: &Path, file_name: &str, src: &str, kind: &str) -> Result<()> {
    let args = [
        OsStr::new("-a"),
        OsStr::new(file_name),
        OsStr::new(src),
        OsStr::new("."),
    ];
    let output = run_guestfs_tool("virt-copy-out", &args, image_dir).await?;
    if !output.status.success() {
        bail!(
            "virt-copy-out failed for {}: {}",
            kind,
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(())
}

async fn write_unavailable_boot_artifacts(
    image_dir: &Path,
    reason: &str,
) -> Result<(PathBuf, PathBuf)> {
    let kernel = image_dir.join("vmlinuz.unavailable");
    let initrd = image_dir.join("initrd.img.unavailable");
    let note = format!("qlean boot artifact unavailable: {}\n", reason);

    tokio::fs::write(&kernel, note.as_bytes())
        .await
        .with_context(|| format!("failed to write {}", kernel.display()))?;
    tokio::fs::write(&initrd, note.as_bytes())
        .await
        .with_context(|| format!("failed to write {}", initrd.display()))?;

    Ok((kernel, initrd))
}

async fn detect_root_arg(image_path: &Path) -> Result<String> {
    let image_dir = image_path.parent().with_context(|| "missing image dir")?;
    let file_name = image_path
        .file_name()
        .and_then(|v| v.to_str())
        .with_context(|| "invalid image filename")?;
    let args = [
        OsStr::new("--ro"),
        OsStr::new("-a"),
        OsStr::new(file_name),
        OsStr::new("-i"),
        OsStr::new("mountpoints"),
    ];
    let output = run_guestfs_tool("guestfish", &args, image_dir).await?;
    if !output.status.success() {
        return Ok(default_root_arg());
    }
    let text = String::from_utf8_lossy(&output.stdout);
    for line in text.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 2 {
            continue;
        }
        let mut dev = None;
        if parts[0].starts_with("/dev/") && parts[1] == "/" {
            dev = Some(parts[0]);
        }
        if parts[1].starts_with("/dev/") && parts[0] == "/" {
            dev = Some(parts[1]);
        }
        if let Some(d) = dev {
            let virt = if let Some(rest) = d.strip_prefix("/dev/sd") {
                format!("/dev/vd{}", rest)
            } else {
                d.to_string()
            };
            return Ok(format!("root={}", virt));
        }
    }
    Ok(default_root_arg())
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
        ensure_extraction_prerequisites().await?;

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

        let resolved = resolve_ubuntu_noble_cloudimg().await?;
        debug!(
            "Resolved Ubuntu cloud image from {}: disk={}, kernel={}, initrd={}",
            resolved.base_url, resolved.disk_name, resolved.kernel_name, resolved.initrd_name
        );

        let qcow2_path = image_dir.join(format!("{}.qcow2", name));
        let qcow2_url = join_url(&resolved.base_url, &resolved.disk_name);
        download_or_copy_with_hash(
            &ImageSource::Url(qcow2_url),
            &qcow2_path,
            &resolved.disk_sha256,
            ShaType::Sha256,
        )
        .await?;

        let kernel_path = image_dir.join("vmlinuz");
        let kernel_url = join_url(
            &resolved.base_url,
            &format!("unpacked/{}", resolved.kernel_name),
        );
        if let Some(kernel_sha256) = resolved.kernel_sha256.as_deref() {
            download_or_copy_with_hash(
                &ImageSource::Url(kernel_url),
                &kernel_path,
                kernel_sha256,
                ShaType::Sha256,
            )
            .await?;
        } else {
            download_or_copy_without_hash(&ImageSource::Url(kernel_url), &kernel_path).await?;
        }

        let initrd_path = image_dir.join("initrd.img");
        let initrd_url = join_url(
            &resolved.base_url,
            &format!("unpacked/{}", resolved.initrd_name),
        );
        if let Some(initrd_sha256) = resolved.initrd_sha256.as_deref() {
            download_or_copy_with_hash(
                &ImageSource::Url(initrd_url),
                &initrd_path,
                initrd_sha256,
                ShaType::Sha256,
            )
            .await?;
        } else {
            download_or_copy_without_hash(&ImageSource::Url(initrd_url), &initrd_path).await?;
        }

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

        Ok(())
    }

    async fn extract(&self, name: &str) -> Result<(PathBuf, PathBuf)> {
        ensure_extraction_prerequisites().await?;

        let file_name = format!("{}.qcow2", name);
        let dirs = QleanDirs::new()?;
        let image_dir = dirs.images.join(name);

        let extract_result = async {
            let boot_files = guestfish_ls_boot(&image_dir, &file_name)
                .await
                .with_context(|| "failed to read /boot from Fedora image with guestfish")?;
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

            let kernel_src = format!("/boot/{}", kernel_name);
            virt_copy_out(&image_dir, &file_name, &kernel_src, "kernel").await?;

            let initrd_src = format!("/boot/{}", initrd_name);
            virt_copy_out(&image_dir, &file_name, &initrd_src, "initrd").await?;

            let kernel_path = image_dir.join(&kernel_name);
            let initrd_path = image_dir.join(&initrd_name);
            Ok::<(PathBuf, PathBuf), anyhow::Error>((kernel_path, initrd_path))
        }
        .await;

        match extract_result {
            Ok(paths) => Ok(paths),
            Err(e) => {
                warn!(
                    "Fedora kernel/initrd extraction failed: {:#}. Using disk boot fallback.",
                    e
                );
                write_unavailable_boot_artifacts(&image_dir, "fedora extraction failed").await
            }
        }
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
        ensure_extraction_prerequisites().await?;

        let file_name = format!("{}.qcow2", name);
        let dirs = QleanDirs::new()?;
        let image_dir = dirs.images.join(name);

        let extract_result = async {
            let boot_files = guestfish_ls_boot(&image_dir, &file_name)
                .await
                .with_context(|| "failed to read /boot from Arch image with guestfish")?;
            let mut kernel_name = None;
            let mut initrd_name = None;

            for line in boot_files.lines() {
                let file = line.trim();
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

            let kernel_src = format!("/boot/{}", kernel_name);
            virt_copy_out(&image_dir, &file_name, &kernel_src, "kernel").await?;

            let initrd_src = format!("/boot/{}", initrd_name);
            virt_copy_out(&image_dir, &file_name, &initrd_src, "initrd").await?;

            let kernel_path = image_dir.join(&kernel_name);
            let initrd_path = image_dir.join(&initrd_name);
            Ok::<(PathBuf, PathBuf), anyhow::Error>((kernel_path, initrd_path))
        }
        .await;

        match extract_result {
            Ok(paths) => Ok(paths),
            Err(e) => {
                warn!(
                    "Arch kernel/initrd extraction failed: {:#}. Using disk boot fallback.",
                    e
                );
                write_unavailable_boot_artifacts(&image_dir, "arch extraction failed").await
            }
        }
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

        let kernel_path = image_dir.join("vmlinuz");
        let initrd_path = image_dir.join("initrd.img");
        if kernel_path.exists() && initrd_path.exists() {
            debug!("Using pre-provided kernel and initrd files");
            return Ok((kernel_path, initrd_path));
        }

        ensure_extraction_prerequisites().await?;
        let file_name = format!("{}.qcow2", name);
        let boot_files = guestfish_ls_boot(&image_dir, &file_name).await?;

        let mut kernel_name = None;
        let mut initrd_name = None;
        for line in boot_files.lines() {
            let file = line.trim();
            if kernel_name.is_none() && (file.starts_with("vmlinuz") || file.starts_with("bzImage"))
            {
                kernel_name = Some(file.to_string());
            }
            if initrd_name.is_none()
                && (file.starts_with("initrd") || file.starts_with("initramfs"))
            {
                initrd_name = Some(file.to_string());
            }
        }

        let kernel = kernel_name.with_context(|| "failed to find kernel file in /boot")?;
        let initrd = initrd_name.with_context(|| "failed to find initrd file in /boot")?;

        let kernel_src = format!("/boot/{}", kernel);
        virt_copy_out(&image_dir, &file_name, &kernel_src, "kernel").await?;
        let initrd_src = format!("/boot/{}", initrd);
        virt_copy_out(&image_dir, &file_name, &initrd_src, "initrd").await?;

        Ok((image_dir.join(&kernel), image_dir.join(&initrd)))
    }

    fn distro(&self) -> Distro {
        Distro::Custom
    }
}

// Helper function to download a file
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

    pub fn root_arg(&self) -> &str {
        match self {
            Image::Debian(img) => &img.root_arg,
            Image::Ubuntu(img) => &img.root_arg,
            Image::Fedora(img) => &img.root_arg,
            Image::Arch(img) => &img.root_arg,
            Image::Custom(img) => &img.root_arg,
        }
    }

    pub fn prefer_direct_kernel_boot(&self) -> bool {
        match self {
            Image::Debian(_) | Image::Ubuntu(_) => true,
            Image::Fedora(_) | Image::Arch(_) | Image::Custom(_) => false,
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
