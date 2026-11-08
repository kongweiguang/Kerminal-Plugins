use super::*;
use serde_json::json;

#[test]
/// A signed catalog is JSON rather than a package; changed bytes and a different publisher must both fail.
fn catalog_signature_verification_is_byte_exact() {
    let bytes = b"{\"sequence\":1}";
    let (public, signature) = signed(bytes);
    verify_signature(bytes, &signature, &public).unwrap();
    assert!(verify_signature(b"{\"sequence\":2}", &signature, &public).is_err());
    let (other, _) = signed(bytes);
    assert!(verify_signature(bytes, &signature, &other).is_err());
}

#[test]
/// Initializing a publisher must create an actually encrypted usable key without replacing existing material.
fn publisher_key_initialization_preserves_existing_keys() {
    let directory = tempfile::tempdir().unwrap();
    let secret = directory.path().join("publisher.key");
    let public = directory.path().join("publisher.pub");
    assert!(keygen(&secret, &public, String::new()).is_err());
    assert!(!secret.exists());
    keygen(&secret, &public, "test-only-password".into()).unwrap();
    let before = fs::read(&secret).unwrap();
    assert!(keygen(&secret, &public, "different".into()).is_err());
    assert_eq!(fs::read(&secret).unwrap(), before);
    assert!(sign(b"catalog", &secret, &public, Some("wrong".into())).is_err());
    let signature = sign(
        b"catalog",
        &secret,
        &public,
        Some("test-only-password".into()),
    )
    .unwrap();
    verify_signature(
        b"catalog",
        &signature,
        &fs::read_to_string(&public).unwrap(),
    )
    .unwrap();
}

/// An explicit inventory must never pick up an unrelated developer secret from the asset directory.
fn template() -> Vec<u8> {
    serde_json::to_vec(&json!({"schema_version":1,"id":"example.demo","name":"Demo","version":"1.0.0","api":{"major":1,"min_minor":0},"platforms":["windows_x86_64","linux_x86_64"],"entrypoints":{},"files":[{"path":"readme.txt","sha256":"","size":0}]})).unwrap()
}

/// Tests generate ephemeral keys in memory and never serialize a private key into a fixture or repository file.
fn signed(bytes: &[u8]) -> (String, String) {
    let keypair = minisign::KeyPair::generate_unencrypted_keypair().unwrap();
    let signature = minisign::sign(
        Some(&keypair.pk),
        &keypair.sk,
        Cursor::new(bytes),
        Some("isolated test"),
        None,
    )
    .unwrap()
    .to_string();
    (keypair.pk.to_box().unwrap().to_string(), signature)
}

#[test]
/// Deterministic metadata makes identical explicit inputs produce the same signed artifact identity.
fn pack_verify_is_deterministic_and_uses_only_explicit_inventory() {
    let root = tempfile::tempdir().unwrap();
    fs::write(root.path().join("readme.txt"), b"example content").unwrap();
    fs::write(root.path().join("developer-secret.env"), b"never ship this").unwrap();
    let first = pack(&template(), root.path()).unwrap();
    let second = pack(&template(), root.path()).unwrap();
    assert_eq!(first.bytes, second.bytes);
    let (key, signature) = signed(&first.bytes);
    let manifest = verify(&first.bytes, &signature, &key).unwrap();
    assert_eq!(manifest.manifest().files.len(), 1);
    assert_eq!(
        manifest.manifest().files[0].sha256,
        sha256(b"example content")
    );
    assert!(
        !first
            .bytes
            .windows(b"never ship this".len())
            .any(|bytes| bytes == b"never ship this")
    );
    let mut tampered = first.bytes.clone();
    tampered[512] ^= 1;
    assert!(matches!(
        verify(&tampered, &signature, &key),
        Err(ToolError::Signature)
    ));
}

#[test]
/// Even authentic signatures cannot authorize extra archive entries absent from the exact manifest inventory.
fn verified_package_rejects_signed_unlisted_files() {
    let root = tempfile::tempdir().unwrap();
    fs::write(root.path().join("readme.txt"), b"example content").unwrap();
    let packed = pack(&template(), root.path()).unwrap();
    let mut files = read_archive(&packed.bytes).unwrap();
    files.insert("unexpected.txt".into(), b"extra".to_vec());
    let mut archive = tar::Builder::new(Vec::new());
    for (path, bytes) in files {
        let mut header = tar::Header::new_ustar();
        header.set_size(bytes.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        archive
            .append_data(&mut header, path, Cursor::new(bytes))
            .unwrap();
    }
    let bytes = archive.into_inner().unwrap();
    let (key, signature) = signed(&bytes);
    assert!(matches!(
        verify(&bytes, &signature, &key),
        Err(ToolError::Invalid(_))
    ));
}

#[test]
/// Authoring errors fail before publishing, and release outputs cannot replace preexisting keys or artifacts.
fn pack_rejects_escape_and_output_preserves_existing_file() {
    let root = tempfile::tempdir().unwrap();
    let mut input: serde_json::Value = serde_json::from_slice(&template()).unwrap();
    input["files"][0]["path"] = json!("../outside");
    assert!(pack(&serde_json::to_vec(&input).unwrap(), root.path()).is_err());
    let path = root.path().join("artifact.tar");
    fs::write(&path, b"existing artifact").unwrap();
    assert!(write_new(&path, b"replacement").is_err());
    assert_eq!(fs::read(path).unwrap(), b"existing artifact");
}

#[test]
/// Index entries are derived from authenticated artifacts and retain the host repository's exact JSON spelling.
fn index_uses_verified_package_metadata_and_limits_sources() {
    let root = tempfile::tempdir().unwrap();
    fs::write(root.path().join("readme.txt"), b"example content").unwrap();
    let packed = pack(&template(), root.path()).unwrap();
    let (key, signature) = signed(&packed.bytes);
    fs::write(root.path().join("demo.tar"), &packed.bytes).unwrap();
    fs::write(root.path().join("demo.tar.minisig"), signature).unwrap();
    fs::write(root.path().join("publisher.pub"), key).unwrap();
    let spec = CatalogSpec {
        source_id: "example-source".into(),
        sequence: 1,
        published_at: 1000,
        expires_at: 2000,
        allowed_origins: vec!["https://example.test".into()],
        plugin_prefixes: vec!["example".into()],
        packages: vec![CatalogPackage {
            archive: "demo.tar".into(),
            signature: "demo.tar.minisig".into(),
            public_key: "publisher.pub".into(),
            key_id: "release-key".into(),
            archive_url: "https://example.test/demo.tar".into(),
            signature_url: "https://example.test/demo.tar.minisig".into(),
            description: "Demo package".into(),
        }],
    };
    let value: serde_json::Value =
        serde_json::from_slice(&catalog(spec.clone(), root.path()).unwrap()).unwrap();
    assert_eq!(value["sourceId"], "example-source");
    assert_eq!(value["plugins"][0]["archiveBytes"], packed.bytes.len());
    assert_eq!(value["plugins"][0]["sha256"], sha256(&packed.bytes));
    assert_eq!(value["plugins"][0]["packageKeyId"], "release-key");
    let mut bad = spec;
    bad.packages[0].archive_url = "https://other.test/demo.tar".into();
    assert!(catalog(bad, root.path()).is_err());
}

#[test]
/// The shipped example must remain a valid five-contribution package as the independent protocol evolves.
fn workbench_example_manifest_covers_all_five_contributions() {
    let template = include_bytes!("../../../examples/workbench-demo/manifest.template.json");
    let value: serde_json::Value = serde_json::from_slice(template).unwrap();
    let root = tempfile::tempdir().unwrap();
    for entry in value["files"].as_array().unwrap() {
        let path = root.path().join(entry["path"].as_str().unwrap());
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, b"isolated manifest validation fixture").unwrap();
    }
    let package = pack(template, root.path()).unwrap();
    let contributions = &package.manifest.manifest().contributions;
    assert_eq!(contributions.host_types.len(), 1);
    assert_eq!(contributions.content_types.len(), 2);
    assert_eq!(contributions.tools.len(), 1);
    assert_eq!(contributions.settings_pages.len(), 1);
    assert_eq!(contributions.commands.len(), 1);
}

#[test]
/// Real key-box loading and detached signing use a temporary OS directory, never the repository or package inventory.
fn signing_key_files_are_separate_and_match_verifier() {
    let assets = tempfile::tempdir().unwrap();
    fs::write(assets.path().join("readme.txt"), b"example content").unwrap();
    let package = pack(&template(), assets.path()).unwrap();
    let keys = tempfile::tempdir().unwrap();
    let keypair = minisign::KeyPair::generate_encrypted_keypair(Some(String::new())).unwrap();
    let public = keypair.pk.to_box().unwrap().to_string();
    let public_path = keys.path().join("test.pub");
    let secret_path = keys.path().join("test.key");
    fs::write(&public_path, &public).unwrap();
    fs::write(
        &secret_path,
        keypair
            .sk
            .to_box(Some("isolated test"))
            .unwrap()
            .to_string(),
    )
    .unwrap();
    let signature = sign(
        &package.bytes,
        &secret_path,
        &public_path,
        Some(String::new()),
    )
    .unwrap();
    assert_eq!(
        verify(&package.bytes, &signature, &public)
            .unwrap()
            .manifest()
            .id,
        "example.demo"
    );
}
