//! Developer tooling depends only on the portable protocol, never the desktop or application crates.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::{Cursor, Read, Write};
use std::path::{Component, Path, PathBuf};

use kerminal_plugin_protocol::{
    ApiRequirement, ExternalPluginManifest, Platform, ValidatedManifest, validate_package_path,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const MAX_PACKAGE_BYTES: usize = 64 * 1024 * 1024;
const MAX_INDEX_BYTES: usize = 512 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum ToolError {
    #[error("{0}")]
    Invalid(&'static str),
    #[error("File operation failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("Manifest validation failed: {0}")]
    Protocol(#[from] kerminal_plugin_protocol::ProtocolError),
    #[error("Signature or key validation failed")]
    Signature,
}
pub type ToolResult<T> = Result<T, ToolError>;

pub struct PackedPlugin {
    pub bytes: Vec<u8>,
    pub manifest: ValidatedManifest,
}

/// Only explicitly inventoried files are packaged; recursive directory collection could leak developer secrets.
pub fn pack(template: &[u8], assets: &Path) -> ToolResult<PackedPlugin> {
    if template.len() > kerminal_plugin_protocol::MAX_MANIFEST_BYTES {
        return Err(ToolError::Invalid("Manifest exceeds size limit"));
    }
    let mut manifest: ExternalPluginManifest = serde_json::from_slice(template)
        .map_err(|_| ToolError::Invalid("Invalid manifest template"))?;
    if manifest.files.len() > 4096 {
        return Err(ToolError::Invalid("Too many package files"));
    }
    ensure_directory(assets)?;
    let mut files = BTreeMap::new();
    let mut folded = BTreeSet::new();
    let mut total = 0usize;
    for entry in &mut manifest.files {
        validate_package_path(&entry.path)?;
        if entry.path.eq_ignore_ascii_case("manifest.json")
            || !folded.insert(entry.path.to_ascii_lowercase())
        {
            return Err(ToolError::Invalid("Duplicate or reserved inventory path"));
        }
        let path = safe_asset_path(assets, &entry.path)?;
        let bytes = read_bounded(&path, MAX_PACKAGE_BYTES)?;
        total = total
            .checked_add(bytes.len())
            .ok_or(ToolError::Invalid("Package size overflow"))?;
        if total > MAX_PACKAGE_BYTES {
            return Err(ToolError::Invalid("Package exceeds size limit"));
        }
        entry.sha256 = sha256(&bytes);
        entry.size = bytes.len() as u64;
        files.insert(entry.path.clone(), bytes);
    }
    for path in files.keys() {
        let mut parent = path.as_str();
        while let Some((prefix, _)) = parent.rsplit_once('/') {
            if folded.contains(&prefix.to_ascii_lowercase()) {
                return Err(ToolError::Invalid("File and directory inventory conflict"));
            }
            parent = prefix;
        }
    }
    manifest
        .files
        .sort_by(|left, right| left.path.cmp(&right.path));
    let manifest = manifest.validate()?;
    let declaration = serde_json::to_vec_pretty(manifest.manifest())
        .map_err(|_| ToolError::Invalid("Manifest cannot be encoded"))?;
    if declaration.len() > kerminal_plugin_protocol::MAX_MANIFEST_BYTES {
        return Err(ToolError::Invalid("Generated manifest exceeds size limit"));
    }
    files.insert("manifest.json".into(), declaration);
    let mut archive = tar::Builder::new(Vec::new());
    for (path, bytes) in files {
        let mut header = tar::Header::new_ustar();
        header.set_mode(0o644);
        header.set_uid(0);
        header.set_gid(0);
        header.set_mtime(0);
        header.set_size(bytes.len() as u64);
        header.set_entry_type(tar::EntryType::Regular);
        header.set_cksum();
        archive.append_data(&mut header, path, Cursor::new(bytes))?;
    }
    let bytes = archive.into_inner()?;
    if bytes.len() > MAX_PACKAGE_BYTES {
        return Err(ToolError::Invalid(
            "Archive including headers exceeds size limit",
        ));
    }
    Ok(PackedPlugin { bytes, manifest })
}

/// Verification covers the original tar bytes before parsing, matching the host's detached modern minisign contract.
pub fn verify(archive: &[u8], signature: &str, public_key: &str) -> ToolResult<ValidatedManifest> {
    if archive.len() > MAX_PACKAGE_BYTES || signature.len() > 16 * 1024 || public_key.len() > 4096 {
        return Err(ToolError::Invalid(
            "Package or signature exceeds size limit",
        ));
    }
    verify_signature(archive, signature, public_key)?;
    let files = read_archive(archive)?;
    let manifest = ExternalPluginManifest::parse(
        files
            .get("manifest.json")
            .ok_or(ToolError::Invalid("Package has no manifest.json"))?,
    )?;
    if files.len() != manifest.manifest().files.len() + 1 {
        return Err(ToolError::Invalid("Package file inventory is not exact"));
    }
    for entry in &manifest.manifest().files {
        let bytes = files
            .get(&entry.path)
            .ok_or(ToolError::Invalid("Inventoried file is missing"))?;
        if bytes.len() as u64 != entry.size || !sha256(bytes).eq_ignore_ascii_case(&entry.sha256) {
            return Err(ToolError::Invalid("Inventoried file hash or size mismatch"));
        }
    }
    Ok(manifest)
}

/// Catalogs need the same byte-exact signature check as packages, without interpreting JSON as a tar archive.
pub fn verify_signature(input: &[u8], signature: &str, public_key: &str) -> ToolResult<()> {
    if input.len() > MAX_PACKAGE_BYTES || signature.len() > 16 * 1024 || public_key.len() > 4096 {
        return Err(ToolError::Invalid("Signing input exceeds size limit"));
    }
    let key = minisign_verify::PublicKey::decode(public_key).map_err(|_| ToolError::Signature)?;
    let signature =
        minisign_verify::Signature::decode(signature).map_err(|_| ToolError::Signature)?;
    key.verify(input, &signature, false)
        .map_err(|_| ToolError::Signature)
}

/// Publisher initialization refuses replacement and empty passwords; keep both outputs outside the package inventory.
pub fn keygen(secret: &Path, public: &Path, password: String) -> ToolResult<()> {
    if password.is_empty() || secret == public || secret.try_exists()? || public.try_exists()? {
        return Err(ToolError::Invalid(
            "New distinct key paths and a nonempty password are required",
        ));
    }
    let keys = minisign::KeyPair::generate_encrypted_keypair(Some(password))
        .map_err(|_| ToolError::Signature)?;
    let secret_box = keys
        .sk
        .to_box(Some("Kerminal plugin publisher"))
        .map_err(|_| ToolError::Signature)?;
    let public_box = keys.pk.to_box().map_err(|_| ToolError::Signature)?;
    // tempfile creates a private file on Unix; Windows publishers should use a private parent directory ACL.
    write_new(secret, secret_box.to_string().as_bytes())?;
    write_new(public, public_box.to_string().as_bytes())
}

/// Signing accepts an existing encrypted key; passwords never appear in arguments or generated package metadata.
pub fn sign(
    input: &[u8],
    secret_key: &Path,
    public_key: &Path,
    password: Option<String>,
) -> ToolResult<String> {
    if input.len() > MAX_PACKAGE_BYTES {
        return Err(ToolError::Invalid("Signing input exceeds size limit"));
    }
    let public_text =
        String::from_utf8(read_bounded(public_key, 4096)?).map_err(|_| ToolError::Signature)?;
    let secret_text = String::from_utf8(read_bounded(secret_key, 16 * 1024)?)
        .map_err(|_| ToolError::Signature)?;
    let public_key = minisign::PublicKeyBox::from_string(&public_text)
        .and_then(|key| key.into_public_key())
        .map_err(|_| ToolError::Signature)?;
    let secret_key = minisign::SecretKeyBox::from_string(&secret_text)
        .and_then(|key| key.into_secret_key(password))
        .map_err(|_| ToolError::Signature)?;
    minisign::sign(
        Some(&public_key),
        &secret_key,
        Cursor::new(input),
        Some("Kerminal plugin artifact"),
        None,
    )
    .map(|signature| signature.to_string())
    .map_err(|_| ToolError::Signature)
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CatalogSpec {
    pub source_id: String,
    pub sequence: u64,
    pub published_at: u64,
    pub expires_at: u64,
    pub allowed_origins: Vec<String>,
    pub plugin_prefixes: Vec<String>,
    pub packages: Vec<CatalogPackage>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CatalogPackage {
    pub archive: PathBuf,
    pub signature: PathBuf,
    pub public_key: PathBuf,
    pub key_id: String,
    pub archive_url: String,
    pub signature_url: String,
    #[serde(default)]
    pub description: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Catalog {
    pub schema_version: u32,
    pub source_id: String,
    pub sequence: u64,
    pub published_at: u64,
    pub expires_at: u64,
    pub plugins: Vec<CatalogEntry>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CatalogEntry {
    pub id: String,
    pub name: String,
    pub description: String,
    pub version: String,
    pub platforms: Vec<Platform>,
    pub api: ApiRequirement,
    pub package_key_id: String,
    pub archive_url: String,
    pub signature_url: String,
    pub sha256: String,
    pub archive_bytes: u64,
}

/// Catalog metadata comes from verified packages, preventing a hand-written index from accidentally describing different bytes.
pub fn catalog(spec: CatalogSpec, base: &Path) -> ToolResult<Vec<u8>> {
    if !kerminal_plugin_protocol::valid_identifier(&spec.source_id)
        || spec.packages.len() > 1024
        || spec.allowed_origins.is_empty()
        || spec.allowed_origins.len() > 16
        || spec.plugin_prefixes.is_empty()
        || spec.plugin_prefixes.len() > 32
        || spec
            .plugin_prefixes
            .iter()
            .any(|prefix| !kerminal_plugin_protocol::valid_identifier(prefix))
        || spec.expires_at <= spec.published_at
        || spec.expires_at - spec.published_at > 31 * 86400
    {
        return Err(ToolError::Invalid(
            "Invalid catalog identity, lifetime or limits",
        ));
    }
    let origins = spec
        .allowed_origins
        .iter()
        .map(|raw| {
            let url = https_url(raw)?;
            if url.path() != "/" || url.query().is_some() {
                return Err(ToolError::Invalid(
                    "Allowed origin must contain no path or query",
                ));
            }
            Ok(url.origin().ascii_serialization())
        })
        .collect::<ToolResult<BTreeSet<_>>>()?;
    let mut plugins = Vec::new();
    let mut identities = BTreeSet::new();
    for package in spec.packages {
        if !kerminal_plugin_protocol::valid_identifier(&package.key_id)
            || package.description.len() > 4096
            || package.description.contains('\0')
            || !origins.contains(
                &https_url(&package.archive_url)?
                    .origin()
                    .ascii_serialization(),
            )
            || !origins.contains(
                &https_url(&package.signature_url)?
                    .origin()
                    .ascii_serialization(),
            )
        {
            return Err(ToolError::Invalid(
                "Catalog package source is outside declared origins",
            ));
        }
        let archive = read_bounded(&base.join(&package.archive), MAX_PACKAGE_BYTES)?;
        let signature = String::from_utf8(read_bounded(&base.join(&package.signature), 16 * 1024)?)
            .map_err(|_| ToolError::Signature)?;
        let key = String::from_utf8(read_bounded(&base.join(&package.public_key), 4096)?)
            .map_err(|_| ToolError::Signature)?;
        let manifest = verify(&archive, &signature, &key)?;
        let manifest = manifest.manifest();
        if !spec.plugin_prefixes.iter().any(|prefix| {
            &manifest.id == prefix
                || manifest
                    .id
                    .strip_prefix(prefix)
                    .is_some_and(|rest| rest.starts_with('.'))
        }) || !identities.insert((
            manifest.id.to_ascii_lowercase(),
            manifest.version.to_ascii_lowercase(),
        )) {
            return Err(ToolError::Invalid(
                "Catalog package identity is duplicated or outside its namespace",
            ));
        }
        plugins.push(CatalogEntry {
            id: manifest.id.clone(),
            name: manifest.name.clone(),
            description: package.description,
            version: manifest.version.clone(),
            platforms: manifest.platforms.clone(),
            api: manifest.api,
            package_key_id: package.key_id,
            archive_url: package.archive_url,
            signature_url: package.signature_url,
            sha256: sha256(&archive),
            archive_bytes: archive.len() as u64,
        });
    }
    plugins.sort_by(|left, right| (&left.id, &left.version).cmp(&(&right.id, &right.version)));
    let bytes = serde_json::to_vec_pretty(&Catalog {
        schema_version: 1,
        source_id: spec.source_id,
        sequence: spec.sequence,
        published_at: spec.published_at,
        expires_at: spec.expires_at,
        plugins,
    })
    .map_err(|_| ToolError::Invalid("Catalog cannot be encoded"))?;
    if bytes.len() > MAX_INDEX_BYTES {
        return Err(ToolError::Invalid("Catalog exceeds size limit"));
    }
    Ok(bytes)
}

/// Outputs are staged and published without replacement; a mistaken output path cannot overwrite keys or release artifacts.
pub fn write_new(path: &Path, bytes: &[u8]) -> ToolResult<()> {
    let absolute = std::path::absolute(path)?;
    let parent = absolute
        .parent()
        .ok_or(ToolError::Invalid("Output path has no parent"))?;
    ensure_directory(parent)?;
    let mut staging = tempfile::NamedTempFile::new_in(parent)?;
    staging.write_all(bytes)?;
    staging.as_file().sync_all()?;
    staging
        .persist_noclobber(absolute)
        .map_err(|error| ToolError::Io(error.error))?;
    Ok(())
}

/// Bounded regular-file reads protect the packer from accidental devices, pipes, symlinks and oversized inputs.
pub fn read_bounded(path: &Path, limit: usize) -> ToolResult<Vec<u8>> {
    let metadata = fs::symlink_metadata(path)?;
    if !safe_metadata(&metadata) || !metadata.is_file() || metadata.len() > limit as u64 {
        return Err(ToolError::Invalid("Input must be a bounded regular file"));
    }
    let mut bytes = Vec::new();
    File::open(path)?
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err(ToolError::Invalid("Input grew beyond its limit"));
    }
    Ok(bytes)
}

/// Stable SHA-256 identifies the exact archive, independently of signature metadata or manifest ordering.
pub fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

/// Every asset path component is checked so directory symlinks or Windows junctions cannot include outside files.
fn safe_asset_path(root: &Path, relative: &str) -> ToolResult<PathBuf> {
    let mut path = root.to_path_buf();
    for component in Path::new(relative).components() {
        let Component::Normal(segment) = component else {
            return Err(ToolError::Invalid("Invalid relative asset path"));
        };
        path.push(segment);
        if !safe_metadata(&fs::symlink_metadata(&path)?) {
            return Err(ToolError::Invalid(
                "Asset path contains a link or reparse point",
            ));
        }
    }
    Ok(path)
}

/// A developer-provided package root is explicit, but it still cannot silently redirect through a link.
fn ensure_directory(path: &Path) -> ToolResult<()> {
    let metadata = fs::symlink_metadata(path)?;
    if !safe_metadata(&metadata) || !metadata.is_dir() {
        return Err(ToolError::Invalid("Expected a regular directory"));
    }
    Ok(())
}

/// Windows junctions are not always reported as symlinks, so reject the entire reparse attribute class.
fn safe_metadata(metadata: &fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        !metadata.file_type().is_symlink() && metadata.file_attributes() & 0x400 == 0
    }
    #[cfg(not(windows))]
    {
        !metadata.file_type().is_symlink()
    }
}

/// Catalog URLs never contain embedded credentials or fragments and are constrained to HTTPS.
fn https_url(raw: &str) -> ToolResult<url::Url> {
    let url = url::Url::parse(raw).map_err(|_| ToolError::Invalid("Invalid HTTPS URL"))?;
    if raw.len() > 4096
        || url.scheme() != "https"
        || url.host().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err(ToolError::Invalid("Unsafe catalog URL"));
    }
    Ok(url)
}

/// Raw tar entries reject all extensions and link types, matching the host's deliberately small package format.
fn read_archive(bytes: &[u8]) -> ToolResult<BTreeMap<String, Vec<u8>>> {
    if bytes.len() < 1024
        || !bytes.len().is_multiple_of(512)
        || bytes[bytes.len() - 1024..].iter().any(|byte| *byte != 0)
    {
        return Err(ToolError::Invalid("Missing tar end blocks"));
    }
    let mut archive = tar::Archive::new(Cursor::new(bytes));
    let mut files = BTreeMap::new();
    let mut folded = BTreeSet::new();
    let mut total = 0usize;
    for entry in archive.entries()?.raw(true) {
        let mut entry = entry?;
        if !entry.header().entry_type().is_file() || entry.header().link_name()?.is_some() {
            return Err(ToolError::Invalid("Archive contains a non-regular entry"));
        }
        let path = std::str::from_utf8(entry.path_bytes().as_ref())
            .map_err(|_| ToolError::Invalid("Invalid archive path encoding"))?
            .to_owned();
        validate_package_path(&path)?;
        if !folded.insert(path.to_ascii_lowercase())
            || files.len() >= 4097
            || entry.size() > MAX_PACKAGE_BYTES as u64
            || (path == "manifest.json"
                && entry.size() > kerminal_plugin_protocol::MAX_MANIFEST_BYTES as u64)
        {
            return Err(ToolError::Invalid(
                "Archive file count, path or size is invalid",
            ));
        }
        total = total
            .checked_add(entry.size() as usize)
            .ok_or(ToolError::Invalid("Archive size overflow"))?;
        if total > MAX_PACKAGE_BYTES {
            return Err(ToolError::Invalid("Archive exceeds unpacked size limit"));
        }
        let mut content = Vec::new();
        entry.read_to_end(&mut content)?;
        if content.len() as u64 != entry.size() {
            return Err(ToolError::Invalid("Truncated archive file"));
        }
        files.insert(path, content);
    }
    let offset = archive.into_inner().position() as usize;
    if bytes
        .get(offset..)
        .is_none_or(|tail| tail.iter().any(|byte| *byte != 0))
    {
        return Err(ToolError::Invalid("Hidden data after tar terminator"));
    }
    for path in files.keys() {
        let mut parent = path.as_str();
        while let Some((prefix, _)) = parent.rsplit_once('/') {
            if folded.contains(&prefix.to_ascii_lowercase()) {
                return Err(ToolError::Invalid("Archive file and directory conflict"));
            }
            parent = prefix;
        }
    }
    Ok(files)
}

#[cfg(test)]
#[path = "../tests/support/package_tools_unit.rs"]
mod tests;
