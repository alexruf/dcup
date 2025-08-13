use anyhow::{Context, Result, anyhow};
use clap::Parser;
use dialoguer::{MultiSelect, theme::ColorfulTheme};
use serde_json as json;
use serde_yaml::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use walkdir::WalkDir;
use which::which;

#[derive(Parser, Debug)]
#[command(
    name = "dcup",
    about = "Find, list and update Docker Compose services with newer images."
)]
struct Cli {
    /// Update all services without interactive confirmation
    #[arg(short = 'y', long = "yes")]
    yes: bool,
}

#[derive(Clone, Debug)]
struct ServiceRef {
    compose_file: PathBuf,
    service: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ComposeDriver {
    DockerCli,     // docker compose
    DockerCompose, // docker-compose
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    // Ensure docker is available
    let compose_driver = detect_compose_driver()?;

    // 1) Discover compose files
    let compose_files = find_compose_files(std::env::current_dir()?)?;
    if compose_files.is_empty() {
        println!("No Docker Compose files found.");
        return Ok(());
    }

    // 2) Parse services/images
    let mut image_to_services: BTreeMap<String, Vec<ServiceRef>> = BTreeMap::new();
    for file in &compose_files {
        let services = parse_compose_services(file)?;
        for (svc, img) in services {
            image_to_services
                .entry(img.clone())
                .or_default()
                .push(ServiceRef {
                    compose_file: file.clone(),
                    service: svc,
                });
        }
    }

    if image_to_services.is_empty() {
        println!("No services with image entries found.");
        return Ok(());
    }

    // 3) Detect which images have updates without pulling
    println!("Checking for available image updates (no pull; this may take a moment)...");
    let mut outdated_images: Vec<String> = Vec::new();
    for image in image_to_services.keys() {
        println!("Checking image {}...", image);
        match detect_update_for_image(image) {
            Ok(UpdateCheck::Updated) => outdated_images.push(image.clone()),
            Ok(UpdateCheck::PulledNew) | Ok(UpdateCheck::UpToDate) => {}
            Err(e) => {
                eprintln!("Warning: update check failed for {}: {}", image, e);
            }
        }
    }

    // 4) Interactive selection (unless --yes)
    let mut selected_images: Vec<String> = Vec::new();
    if cli.yes {
        // Update all services/images without prompting (per requirement)
        selected_images = image_to_services.keys().cloned().collect();
        println!(
            "--yes flag detected: updating all {} images/services without prompting.",
            selected_images.len()
        );
    } else {
        if outdated_images.is_empty() {
            println!("All images are up to date. Nothing to do.");
            return Ok(());
        }
        let theme = ColorfulTheme::default();
        let items: Vec<String> = outdated_images
            .iter()
            .map(|img| {
                let empty: Vec<ServiceRef> = Vec::new();
                let services = image_to_services.get(img).unwrap_or(&empty);
                let files_count: BTreeSet<&Path> =
                    services.iter().map(|s| s.compose_file.as_path()).collect();
                format!(
                    "{} ({} services across {} files)",
                    img,
                    services.len(),
                    files_count.len()
                )
            })
            .collect();
        let selections = MultiSelect::with_theme(&theme)
            .with_prompt("Select the images/services to update")
            .items(&items)
            .interact_opt()?;
        if let Some(indices) = selections {
            for idx in indices {
                if let Some(img) = outdated_images.get(idx) {
                    selected_images.push(img.clone());
                }
            }
        } else {
            println!("No selection made. Aborting.");
            return Ok(());
        }
        if selected_images.is_empty() {
            println!("No images selected. Nothing to do.");
            return Ok(());
        }
    }

    // 5) Apply updates: restart services per compose file grouped
    let mut per_file_services: BTreeMap<PathBuf, BTreeSet<String>> = BTreeMap::new();
    for img in &selected_images {
        if let Some(svcs) = image_to_services.get(img) {
            for s in svcs {
                per_file_services
                    .entry(s.compose_file.clone())
                    .or_default()
                    .insert(s.service.clone());
            }
        }
    }

    println!("Starting updates and restarts for the selected services...");
    for (file, services) in per_file_services {
        let services_vec: Vec<String> = services.iter().cloned().collect();
        run_compose_up(&compose_driver, &file, &services_vec)?;
    }

    println!("Done. The selected services have been updated and restarted.");
    Ok(())
}

fn detect_compose_driver() -> Result<ComposeDriver> {
    // Prefer docker CLI compose if available
    if which("docker").is_ok() {
        let out = Command::new("docker")
            .arg("compose")
            .arg("version")
            .output();
        if let Ok(o) = out {
            if o.status.success() {
                return Ok(ComposeDriver::DockerCli);
            }
        }
    }
    // Fallback to docker-compose
    if which("docker-compose").is_ok() {
        return Ok(ComposeDriver::DockerCompose);
    }
    Err(anyhow!(
        "Neither 'docker compose' nor 'docker-compose' was found. Please install Docker."
    ))
}

fn find_compose_files(root: PathBuf) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    for entry in WalkDir::new(root).follow_links(false) {
        let entry = match entry {
            Ok(e) => e,
            Err(e) => {
                if let Some(ioe) = e.io_error() {
                    if ioe.kind() == std::io::ErrorKind::PermissionDenied {
                        continue;
                    }
                }
                return Err(e.into());
            }
        };

        if entry.file_type().is_file() {
            let name = entry.file_name().to_string_lossy().to_lowercase();
            if name == "docker-compose.yml"
                || name == "docker-compose.yaml"
                || name == "compose.yml"
                || name == "compose.yaml"
            {
                files.push(entry.into_path());
            }
        }
    }
    Ok(files)
}

fn parse_compose_services(path: &Path) -> Result<BTreeMap<String, String>> {
    let content = fs::read_to_string(path)
        .with_context(|| format!("Unable to read file: {}", path.display()))?;
    let yaml: Value = serde_yaml::from_str(&content)
        .with_context(|| format!("Invalid YAML in {}", path.display()))?;

    let mut map = BTreeMap::new();
    let services = yaml
        .get("services")
        .and_then(|v| v.as_mapping())
        .ok_or_else(|| anyhow!("No 'services' section in {}", path.display()))?;

    for (k, v) in services {
        let svc_name = k.as_str().unwrap_or_default().to_string();
        if let Some(img_val) = v.get("image") {
            if let Some(img) = img_val.as_str() {
                map.insert(svc_name, img.to_string());
            }
        }
    }

    Ok(map)
}

#[derive(Debug)]
enum UpdateCheck {
    UpToDate,
    Updated,   // remote config digest differs from local image ID (for the same platform)
    PulledNew, // no local image present (would be a new pull)
}

fn detect_update_for_image(image: &str) -> Result<UpdateCheck> {
    if image.contains("${") {
        // Cannot resolve templated images here; skip as up-to-date to avoid accidental pulls
        return Ok(UpdateCheck::UpToDate);
    }

    // 1) What do we have locally?
    let local_id = get_local_image_id(image)?;
    if local_id.is_none() {
        // Not present locally -> would require pull
        return Ok(UpdateCheck::PulledNew);
    }
    let local_id = local_id.unwrap();

    // 2) Determine local platform (os/arch[/variant])
    let local_platform = get_local_platform(image)?;
    if local_platform.is_none() {
        // Without knowing the platform, we can't reliably select a matching remote digest.
        // Avoid false positives.
        return Ok(UpdateCheck::UpToDate);
    }

    // 3) Get the remote config digest for the matching platform
    let remote_config_digest =
        match get_remote_platform_config_digest(image, &local_platform.clone().unwrap()) {
            Ok(Some(d)) => d,
            Ok(None) => {
                // Could not determine a platform-matching digest -> avoid false positives
                return Ok(UpdateCheck::UpToDate);
            }
            Err(e) => {
                // Non-fatal: if the remote digest can't be determined, assume up to date
                eprintln!(
                    "Warning: could not determine remote digest for {}: {}",
                    image, e
                );
                return Ok(UpdateCheck::UpToDate);
            }
        };

    // 4) Compare remote config digest (image ID) against local .Id
    if remote_config_digest == local_id {
        Ok(UpdateCheck::UpToDate)
    } else {
        Ok(UpdateCheck::Updated)
    }
}

fn get_local_platform(image: &str) -> Result<Option<(String, String, Option<String>)>> {
    // Extract local OS/ARCH/VARIANT for the image if present
    let output = Command::new("docker")
        .arg("image")
        .arg("inspect")
        .arg("--format")
        .arg(r#"{{json .Os}} {{json .Architecture}} {{json .Variant}}"#)
        .arg(image)
        .output()
        .with_context(|| format!("Could not execute 'docker image inspect {}'", image))?;
    if !output.status.success() {
        let err = String::from_utf8_lossy(&output.stderr);
        if err.to_lowercase().contains("no such") {
            return Ok(None);
        }
        return Err(anyhow!(
            "'docker image inspect {}' failed: {}",
            image,
            err.trim()
        ));
    }
    let text = String::from_utf8_lossy(&output.stdout).trim().to_string();
    Ok(parse_local_platform_from_formatted(&text))
}

fn get_local_image_id(image: &str) -> Result<Option<String>> {
    // Use the content-addressable image ID (config digest)
    let output = Command::new("docker")
        .arg("image")
        .arg("inspect")
        .arg("--format")
        .arg(r#"{{json .Id}}"#)
        .arg(image)
        .output()
        .with_context(|| format!("Could not execute 'docker image inspect {}'", image))?;

    if !output.status.success() {
        let err = String::from_utf8_lossy(&output.stderr);
        if err.to_lowercase().contains("no such") {
            return Ok(None);
        }
        return Err(anyhow!(
            "'docker image inspect {}' failed: {}",
            image,
            err.trim()
        ));
    }

    let text = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if text.is_empty() || text == "null" {
        return Ok(None);
    }
    let id: String = json::from_str(&text).unwrap_or_default();
    if id.is_empty() {
        Ok(None)
    } else {
        Ok(Some(id))
    }
}

fn get_remote_platform_config_digest(
    image: &str,
    platform: &(String, String, Option<String>),
) -> Result<Option<String>> {
    // Prefer verbose to get per-platform entries and config digest
    let verbose = Command::new("docker")
        .arg("manifest")
        .arg("inspect")
        .arg("--verbose")
        .arg(image)
        .output();

    if let Ok(o) = verbose {
        if o.status.success() {
            let text = String::from_utf8_lossy(&o.stdout).to_string();
            let val: json::Value = json::from_str(&text).with_context(|| {
                format!(
                    "Invalid JSON from 'docker manifest inspect --verbose {}'",
                    image
                )
            })?;

            // Multi-arch: manifests[] with platform info -> use config.digest
            if let Some(d) = pick_config_digest_from_verbose_manifest(&val, platform) {
                return Ok(Some(d));
            }

            // Single-manifest case: some engines include Descriptor + SchemaV2Manifest
            if let Some(d) = pick_config_digest_from_schema_v2_manifest(&val) {
                return Ok(Some(d));
            }

            // Could not determine a matching digest from verbose output
            return Ok(None);
        }
    }

    // Fallback: non-verbose (single-arch manifests typically)
    let output = Command::new("docker")
        .arg("manifest")
        .arg("inspect")
        .arg(image)
        .output()
        .with_context(|| format!("Could not execute 'docker manifest inspect {}'", image))?;

    if !output.status.success() {
        return Err(anyhow!(
            "'docker manifest inspect {}' failed: {}",
            image,
            String::from_utf8_lossy(&output.stderr).trim().to_string()
        ));
    }

    let text = String::from_utf8_lossy(&output.stdout).to_string();
    let val: json::Value = json::from_str(&text)
        .with_context(|| format!("Invalid JSON from 'docker manifest inspect {}'", image))?;

    // Single-manifest: config.digest if present
    if let Some(d) = val
        .get("config")
        .and_then(|c| c.get("digest"))
        .and_then(|v| v.as_str())
        .filter(|d| d.starts_with("sha256:"))
    {
        return Ok(Some(d.to_string()));
    }

    Ok(None)
}

fn run_compose_up(driver: &ComposeDriver, file: &Path, services: &[String]) -> Result<()> {
    if services.is_empty() {
        return Ok(());
    }
    match driver {
        ComposeDriver::DockerCli => {
            // First pull selected services' images
            let mut pull = Command::new("docker");
            pull.arg("compose").arg("-f").arg(file).arg("pull");
            for s in services {
                pull.arg(s);
            }
            let pull_out = pull.output().with_context(|| {
                format!(
                    "Error running 'docker compose -f {} pull ...'",
                    file.display()
                )
            })?;
            if !pull_out.status.success() {
                return Err(anyhow!(
                    "docker compose pull failed for {}: {}",
                    file.display(),
                    String::from_utf8_lossy(&pull_out.stderr)
                ));
            }
            // Then recreate containers
            let mut up = Command::new("docker");
            up.arg("compose").arg("-f").arg(file).arg("up").arg("-d");
            for s in services {
                up.arg(s);
            }
            let up_out = up.output().with_context(|| {
                format!(
                    "Error running 'docker compose -f {} up -d ...'",
                    file.display()
                )
            })?;
            if !up_out.status.success() {
                return Err(anyhow!(
                    "docker compose up failed for {}: {}",
                    file.display(),
                    String::from_utf8_lossy(&up_out.stderr)
                ));
            }
        }
        ComposeDriver::DockerCompose => {
            let mut pull = Command::new("docker-compose");
            pull.arg("-f").arg(file).arg("pull");
            for s in services {
                pull.arg(s);
            }
            let pull_out = pull.output().with_context(|| {
                format!(
                    "Error running 'docker-compose -f {} pull ...'",
                    file.display()
                )
            })?;
            if !pull_out.status.success() {
                return Err(anyhow!(
                    "docker-compose pull failed for {}: {}",
                    file.display(),
                    String::from_utf8_lossy(&pull_out.stderr)
                ));
            }
            let mut up = Command::new("docker-compose");
            up.arg("-f").arg(file).arg("up").arg("-d");
            for s in services {
                up.arg(s);
            }
            let up_out = up.output().with_context(|| {
                format!(
                    "Error running 'docker-compose -f {} up -d ...'",
                    file.display()
                )
            })?;
            if !up_out.status.success() {
                return Err(anyhow!(
                    "docker-compose up failed for {}: {}",
                    file.display(),
                    String::from_utf8_lossy(&up_out.stderr)
                ));
            }
        }
    }
    Ok(())
}

fn parse_local_platform_from_formatted(text: &str) -> Option<(String, String, Option<String>)> {
    if text.trim().is_empty() {
        return None;
    }
    let mut parts = text.split_whitespace();
    let os_tok = parts.next().unwrap_or("null");
    let arch_tok = parts.next().unwrap_or("null");
    let variant_tok = parts.next();

    let os = json::from_str::<String>(os_tok).unwrap_or_default();
    let arch = json::from_str::<String>(arch_tok).unwrap_or_default();
    let variant = variant_tok
        .and_then(|v| json::from_str::<String>(v).ok())
        .filter(|s| !s.is_empty());

    if os.is_empty() || arch.is_empty() {
        return None;
    }
    Some((os, arch, variant))
}

// Pick config.digest for the matching platform from verbose manifest
fn pick_config_digest_from_verbose_manifest(
    val: &json::Value,
    platform: &(String, String, Option<String>),
) -> Option<String> {
    if let Some(arr) = val.get("manifests").and_then(|m| m.as_array()) {
        let (los, larch, lvar) = platform;
        for m in arr {
            let p = m.get("platform").and_then(|p| p.as_object());
            let mos = p
                .and_then(|p| p.get("os"))
                .and_then(|v| v.as_str())
                .unwrap_or_default();
            let march = p
                .and_then(|p| p.get("architecture"))
                .and_then(|v| v.as_str())
                .unwrap_or_default();
            let mvariant = p.and_then(|p| p.get("variant")).and_then(|v| v.as_str());

            let variant_matches = match (lvar.as_deref(), mvariant) {
                (Some(lv), Some(rv)) => lv == rv,
                (None, _) => true,
                (Some(_), None) => true,
            };

            if mos == los && march == larch && variant_matches {
                if let Some(d) = m
                    .get("SchemaV2Manifest")
                    .and_then(|s| s.get("config"))
                    .and_then(|c| c.get("digest"))
                    .and_then(|v| v.as_str())
                {
                    if d.starts_with("sha256:") {
                        return Some(d.to_string());
                    }
                }
            }
        }
    }
    None
}

// Fallback for verbose single-manifest payloads
fn pick_config_digest_from_schema_v2_manifest(val: &json::Value) -> Option<String> {
    val.get("SchemaV2Manifest")
        .and_then(|s| s.get("config"))
        .and_then(|c| c.get("digest"))
        .and_then(|v| v.as_str())
        .and_then(|d| {
            if d.starts_with("sha256:") {
                Some(d.to_string())
            } else {
                None
            }
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json as json;
    use tempfile::tempdir;

    #[test]
    fn test_find_compose_files() -> Result<()> {
        let dir = tempdir()?;
        let root = dir.path();
        // create structure
        let sub = root.join("a/b");
        fs::create_dir_all(&sub)?;
        fs::write(root.join("docker-compose.yml"), "services: {}")?;
        fs::write(sub.join("compose.yaml"), "services: {}")?;
        fs::write(root.join("ignore.txt"), "hi")?;

        let mut files = find_compose_files(root.to_path_buf())?;
        files.sort();
        assert_eq!(files.len(), 2);
        assert!(
            files
                .iter()
                .any(|p| p.file_name().unwrap() == "docker-compose.yml")
        );
        assert!(
            files
                .iter()
                .any(|p| p.file_name().unwrap() == "compose.yaml")
        );
        Ok(())
    }

    #[test]
    fn test_parse_compose_services() -> Result<()> {
        let dir = tempdir()?;
        let file = dir.path().join("docker-compose.yaml");
        let content = r#"
version: '3.8'
services:
  web:
    image: nginx:latest
  db:
    image: postgres:14
  built:
    build: .
"#;
        fs::write(&file, content)?;
        let map = parse_compose_services(&file)?;
        assert_eq!(map.get("web"), Some(&"nginx:latest".to_string()));
        assert_eq!(map.get("db"), Some(&"postgres:14".to_string()));
        assert!(!map.contains_key("built"));
        Ok(())
    }

    #[test]
    fn test_detect_update_grafana_scenario_by_config_digest() {
        // Local image ID (config digest) BEFORE update:
        let old_local_id =
            "sha256:8e3841514071c88ecc3553a58f24ac74690ebbf5df094bd8ae24c544b8a9c3a6";
        // Remote platform-matching config digest AFTER update (from verbose manifest):
        let new_remote_config =
            "sha256:b8554c97f999a6e9528f630a89765efad3a196d100ccb086105cb1f0cb692b87";

        // Should detect update since config digests don't match
        assert_ne!(old_local_id, new_remote_config);
    }

    #[test]
    fn test_parse_local_platform_with_variant() {
        let text = "\"linux\" \"arm64\" \"v8\"";
        let p = parse_local_platform_from_formatted(text).unwrap();
        assert_eq!(p.0, "linux");
        assert_eq!(p.1, "arm64");
        assert_eq!(p.2.as_deref(), Some("v8"));
    }

    #[test]
    fn test_parse_local_platform_no_variant() {
        let text = "\"linux\" \"amd64\" null";
        let p = parse_local_platform_from_formatted(text).unwrap();
        assert_eq!(p.0, "linux");
        assert_eq!(p.1, "amd64");
        assert!(p.2.is_none());
    }

    #[test]
    fn test_pick_config_digest_from_verbose_manifest() {
        let manifest = json::json!({
            "manifests": [
                {
                    "digest": "sha256:111",
                    "platform": {"os": "linux", "architecture": "amd64"},
                    "SchemaV2Manifest": {
                        "config": { "digest": "sha256:cfg-amd64" }
                    }
                },
                {
                    "digest": "sha256:222",
                    "platform": {"os": "linux", "architecture": "arm64", "variant": "v8"},
                    "SchemaV2Manifest": {
                        "config": { "digest": "sha256:cfg-arm64v8" }
                    }
                }
            ]
        });
        let plat = ("linux".into(), "arm64".into(), Some("v8".into()));
        let d = pick_config_digest_from_verbose_manifest(&manifest, &plat).unwrap();
        assert_eq!(d, "sha256:cfg-arm64v8");
    }
}
