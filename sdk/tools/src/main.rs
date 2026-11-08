use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};

use kerminal_plugin_tools::{
    MAX_PACKAGE_BYTES, ToolError, ToolResult, catalog, keygen, pack, read_bounded, sha256, sign,
    verify, verify_signature, write_new,
};

/// A nonzero exit code is the only failure signal; no partially successful release publication is implied.
fn main() {
    if let Err(error) = execute() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

/// Commands accept explicit named paths and reject unknown or repeated options before reading keys or writing files.
fn execute() -> ToolResult<()> {
    let mut args = std::env::args().skip(1);
    let command = args.next().unwrap_or_else(|| "help".into());
    if matches!(command.as_str(), "help" | "--help" | "-h") {
        println!(
            "kerminal-plugin pack --manifest FILE --assets DIR --out FILE\nkerminal-plugin verify --archive FILE --signature FILE --public-key FILE\nkerminal-plugin verify-signature --input FILE --signature FILE --public-key FILE\nkerminal-plugin keygen --secret-key FILE --public-key FILE --password-stdin\nkerminal-plugin sign --input FILE --secret-key FILE --public-key FILE --out FILE [--password-stdin]\nkerminal-plugin index --spec FILE --out FILE\nOutputs must not already exist. Signing prompts for an encrypted-key password unless --password-stdin is set."
        );
        return Ok(());
    }
    let allowed: &[&str] = match command.as_str() {
        "pack" => &["--manifest", "--assets", "--out"],
        "verify" => &["--archive", "--signature", "--public-key"],
        "verify-signature" => &["--input", "--signature", "--public-key"],
        "keygen" => &["--secret-key", "--public-key", "--password-stdin"],
        "sign" => &[
            "--input",
            "--secret-key",
            "--public-key",
            "--out",
            "--password-stdin",
        ],
        "index" => &["--spec", "--out"],
        _ => return Err(ToolError::Invalid("Unknown command; use --help")),
    };
    let mut options = BTreeMap::new();
    while let Some(option) = args.next() {
        if !allowed.contains(&option.as_str()) || options.contains_key(&option) {
            return Err(ToolError::Invalid("Unknown or repeated option"));
        }
        let value = if option == "--password-stdin" {
            String::new()
        } else {
            args.next()
                .filter(|value| !value.starts_with("--"))
                .ok_or(ToolError::Invalid("Missing option value"))?
        };
        options.insert(option, value);
    }
    match command.as_str() {
        "keygen" => {
            if !options.contains_key("--password-stdin") {
                return Err(ToolError::Invalid("Key creation requires --password-stdin"));
            }
            keygen(
                &path(&options, "--secret-key")?,
                &path(&options, "--public-key")?,
                password_stdin()?,
            )?;
            println!("Created encrypted publisher key; keep it outside the repository");
        }
        "verify-signature" => {
            verify_signature(
                &read_bounded(&path(&options, "--input")?, MAX_PACKAGE_BYTES)?,
                &text_file(&path(&options, "--signature")?, 16 * 1024)?,
                &text_file(&path(&options, "--public-key")?, 4096)?,
            )?;
            println!("Verified artifact signature");
        }
        "pack" => {
            let manifest = read_bounded(
                &path(&options, "--manifest")?,
                kerminal_plugin_protocol::MAX_MANIFEST_BYTES,
            )?;
            let packed = pack(&manifest, &path(&options, "--assets")?)?;
            write_new(&path(&options, "--out")?, &packed.bytes)?;
            println!(
                "{} {} {}",
                packed.manifest.manifest().id,
                packed.manifest.manifest().version,
                sha256(&packed.bytes)
            );
        }
        "verify" => {
            let archive = read_bounded(&path(&options, "--archive")?, MAX_PACKAGE_BYTES)?;
            let signature = text_file(&path(&options, "--signature")?, 16 * 1024)?;
            let key = text_file(&path(&options, "--public-key")?, 4096)?;
            let manifest = verify(&archive, &signature, &key)?;
            println!(
                "Verified {} {} {}",
                manifest.manifest().id,
                manifest.manifest().version,
                sha256(&archive)
            );
        }
        "sign" => {
            let input = read_bounded(&path(&options, "--input")?, MAX_PACKAGE_BYTES)?;
            let password = if options.contains_key("--password-stdin") {
                Some(password_stdin()?)
            } else {
                None
            };
            let signature = sign(
                &input,
                &path(&options, "--secret-key")?,
                &path(&options, "--public-key")?,
                password,
            )?;
            write_new(&path(&options, "--out")?, signature.as_bytes())?;
            println!("Signed artifact {}", sha256(&input));
        }
        "index" => {
            let spec_path = path(&options, "--spec")?;
            let spec = serde_json::from_slice(&read_bounded(&spec_path, 1024 * 1024)?)
                .map_err(|_| ToolError::Invalid("Invalid catalog specification"))?;
            let bytes = catalog(spec, spec_path.parent().unwrap_or(Path::new(".")))?;
            write_new(&path(&options, "--out")?, &bytes)?;
            println!("Generated signed-catalog input {}", sha256(&bytes));
        }
        _ => unreachable!(),
    }
    Ok(())
}

/// Secrets travel through a bounded stdin pipe, never shell arguments or diagnostic output.
fn password_stdin() -> ToolResult<String> {
    let mut bytes = Vec::new();
    std::io::stdin()
        .take(16 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > 16 * 1024 {
        return Err(ToolError::Invalid("Password input exceeds limit"));
    }
    Ok(String::from_utf8(bytes)
        .map_err(|_| ToolError::Invalid("Password must be UTF-8"))?
        .trim_end_matches(['\r', '\n'])
        .to_owned())
}

/// Missing required paths fail before a command can accidentally use a working-directory default.
fn path(options: &BTreeMap<String, String>, name: &str) -> ToolResult<PathBuf> {
    options
        .get(name)
        .map(PathBuf::from)
        .ok_or(ToolError::Invalid("Missing required option; use --help"))
}

/// Public keys and detached signatures have explicit text limits independent of archive size.
fn text_file(path: &Path, limit: usize) -> ToolResult<String> {
    String::from_utf8(read_bounded(path, limit)?)
        .map_err(|_| ToolError::Invalid("Expected UTF-8 text file"))
}
