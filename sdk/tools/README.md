# Plugin developer tools

`kerminal-plugin-tools` depends on the portable protocol crate, not Kerminal application internals. It builds the exact package format accepted by the installer.

```powershell
cargo test -p kerminal-plugin-tools
cargo build -p kerminal-plugin-tools --bin kerminal-plugin
```

The CLI also initializes encrypted publisher keys and verifies catalog signatures:

```text
kerminal-plugin pack --manifest manifest.template.json --assets staging --out plugin-1.0.0.tar
kerminal-plugin sign --input plugin-1.0.0.tar --secret-key /private/publisher.key --public-key publisher.pub --out plugin-1.0.0.tar.minisig
kerminal-plugin verify --archive plugin-1.0.0.tar --signature plugin-1.0.0.tar.minisig --public-key publisher.pub
kerminal-plugin index --spec release-spec.json --out index.json
kerminal-plugin verify-signature --input index.json --signature index.json.minisig --public-key publisher.pub
kerminal-plugin keygen --secret-key /private/publisher.key --public-key /private/publisher.pub --password-stdin
```

`pack` reads only paths explicitly listed in `manifest.files`, computes their SHA-256 and sizes, validates the resulting manifest, and includes it as `manifest.json`. Template hashes and sizes are replaced in the archive; the template itself is untouched. It does not scan and upload an entire project directory. Paths use portable ASCII spelling. Links, junctions, device names, traversal, duplicate paths and case aliases are rejected. The archive is uncompressed USTAR with deterministic ordering, ownership, timestamps and modes. A USTAR path must fit its standard prefix/name fields.

`keygen` creates a minisign key pair with a required nonempty password supplied through stdin. Use a private directory outside the repository; on Windows restrict its ACL before creation. Existing files are never replaced. If public-key creation fails after the encrypted secret is written, preserve it and recover the public key with minisign rather than deleting or replacing the secret. `sign` uses that encrypted secret key. CI may supply its password through stdin with `--password-stdin`; never pass passwords on the command line. These commands do not change source trust, upload files, or publish a release. Public and private keys must remain separate; keep secret keys outside the repository and package inventory.

`verify` checks a modern detached minisign signature over the complete raw tar, then checks the exact file inventory and manifest. This confirms package integrity for the supplied public key. Installation additionally requires a trusted source and its permitted namespace.

`index` reads a local specification, verifies every referenced package using its supplied public key, and derives IDs, versions, platform support, byte counts and archive hashes from those packages. Its output must then be separately signed with `sign`. Paths in the specification are relative to the specification file. All four commands refuse to overwrite an existing output file.

Catalog specification shape:

```json
{
  "sourceId": "your-publisher",
  "sequence": 1,
  "publishedAt": 1794067200,
  "expiresAt": 1794153600,
  "allowedOrigins": ["https://plugins.example.invalid"],
  "pluginPrefixes": ["example"],
  "packages": [{
    "archive": "plugin-1.0.0.tar",
    "signature": "plugin-1.0.0.tar.minisig",
    "publicKey": "publisher.pub",
    "keyId": "release-2026",
    "archiveUrl": "https://plugins.example.invalid/plugin-1.0.0.tar",
    "signatureUrl": "https://plugins.example.invalid/plugin-1.0.0.tar.minisig",
    "description": "A short description."
  }]
}
```

These timestamps and the `.invalid` domain are documentation placeholders. Replace them with the actual publisher’s values. The repository's GitHub example source and publishing instructions are in `marketplace/github.md`. Expiration must follow publication by at most 31 days. Increment the sequence for every changed catalog. Never replace the bytes of an already released plugin ID/version.
