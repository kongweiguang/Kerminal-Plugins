//! Signed package metadata is declarative; parsing it never loads executable code.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    ConfigurationSchema, NativeView, ProtocolError, valid_identifier, valid_label,
    validate_value_bounds,
};

pub const MANIFEST_SCHEMA_VERSION: u32 = 1;
pub const HOST_API_MAJOR: u32 = 1;
pub const HOST_API_MINOR: u32 = 0;
pub const MAX_MANIFEST_BYTES: usize = 1_048_576;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalPluginManifest {
    pub schema_version: u32,
    pub id: String,
    pub name: String,
    pub version: String,
    /// Private plugin storage is not migrated by the host; omitted legacy declarations use the first data format.
    #[serde(default = "initial_data_version")]
    pub data_version: u32,
    pub api: ApiRequirement,
    pub platforms: Vec<Platform>,
    #[serde(default)]
    pub permissions: Vec<Permission>,
    pub entrypoints: Entrypoints,
    #[serde(default)]
    pub contributions: Contributions,
    #[serde(default)]
    pub configuration: ConfigurationSchemas,
    pub files: Vec<PackageFile>,
    /// Unknown descriptive extensions survive without being interpreted as permissions or runtime features.
    #[serde(default)]
    pub extensions: BTreeMap<String, Value>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApiRequirement {
    pub major: u32,
    pub min_minor: u32,
}

/// Older packages predate explicit private-data versioning and therefore belong to the original data contract.
fn initial_data_version() -> u32 {
    1
}

impl ApiRequirement {
    /// Minor requirements are lower bounds so future hosts retain older plugins; unsupported execution still preserves static schemas.
    pub fn is_supported(&self) -> bool {
        self.major == HOST_API_MAJOR && self.min_minor.cmp(&HOST_API_MINOR).is_le()
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Platform {
    WindowsX86_64,
    WindowsAarch64,
    LinuxX86_64,
    LinuxAarch64,
    MacosX86_64,
    MacosAarch64,
}

impl Platform {
    /// The host build target is explicit; unsupported architectures never fall back to another executable.
    pub fn current() -> Option<Self> {
        match (std::env::consts::OS, std::env::consts::ARCH) {
            ("windows", "x86_64") => Some(Self::WindowsX86_64),
            ("windows", "aarch64") => Some(Self::WindowsAarch64),
            ("linux", "x86_64") => Some(Self::LinuxX86_64),
            ("linux", "aarch64") => Some(Self::LinuxAarch64),
            ("macos", "x86_64") => Some(Self::MacosX86_64),
            ("macos", "aarch64") => Some(Self::MacosAarch64),
            _ => None,
        }
    }
}

/// Permissions constrain host APIs; native sidecars still require an explicit installation trust decision.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Permission {
    HostRead,
    HostConnect,
    SettingsRead,
    SettingsWrite,
    SecretRead { slot: String },
    UiDialogs,
    PathPicker,
    ClipboardRead,
    ClipboardWrite,
    OpenExternal,
    Network,
    Process,
    Filesystem,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Entrypoints {
    #[serde(default)]
    pub process: Vec<ProcessEntry>,
    #[serde(default)]
    pub views: BTreeMap<String, ViewEntry>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessEntry {
    pub platform: Platform,
    pub path: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ViewEntry {
    Native { view: NativeView },
    Webview { path: String, bridge_version: u32 },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackageFile {
    pub path: String,
    pub sha256: String,
    pub size: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigurationSchemas {
    #[serde(default)]
    pub host_types: BTreeMap<String, ConfigurationSchema>,
    pub settings: Option<ConfigurationSchema>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Contributions {
    #[serde(default)]
    pub host_types: Vec<HostContribution>,
    #[serde(default)]
    pub content_types: Vec<ContentContribution>,
    #[serde(default)]
    pub tools: Vec<ToolContribution>,
    #[serde(default)]
    pub settings_pages: Vec<SettingsContribution>,
    #[serde(default)]
    pub commands: Vec<CommandContribution>,
    #[serde(default)]
    pub placements: Vec<PlacementContribution>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostContribution {
    pub id: String,
    pub name: String,
    pub configuration_type: String,
    pub content_type: Option<String>,
    pub form: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContentContribution {
    pub id: String,
    pub name: String,
    pub view: String,
    pub kinds: Vec<ContentKind>,
    pub state: ConfigurationSchema,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContentKind {
    Page,
    Tab,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolContribution {
    pub id: String,
    pub name: String,
    pub view: String,
    pub icon: String,
    pub content_type: Option<String>,
    pub scope: ToolScope,
    pub state: ConfigurationSchema,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolScope {
    Window,
    Tab,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SettingsContribution {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub keywords: Vec<String>,
    #[serde(default)]
    pub fields: Vec<FieldAnchor>,
    #[serde(default)]
    pub order: i32,
    pub view: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FieldAnchor {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub keywords: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommandContribution {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub keywords: Vec<String>,
    pub scope: CommandScope,
    pub target: CommandTarget,
    pub default_keybinding: Option<DefaultKeybinding>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "id",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum CommandScope {
    App,
    Workspace,
    Terminal,
    Content(String),
    Tool(String),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommandTarget {
    Window,
    Host,
    Tab,
    Terminal,
    Files,
    Content,
    Tool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DefaultKeybinding {
    #[serde(default)]
    pub binding: String,
    #[serde(default)]
    pub windows: String,
    #[serde(default)]
    pub macos: String,
    pub linux: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlacementContribution {
    pub command: String,
    pub location: CommandLocation,
    pub group: String,
    #[serde(default)]
    pub order: i32,
    pub label: Option<String>,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "id",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum CommandLocation {
    CommandPalette,
    HostMenu,
    TabMenu,
    FileMenu,
    ToolHeader(String),
}

/// This type proves declarative validity only; a verified signature is a distinct installer capability.
#[derive(Clone, Debug, PartialEq)]
pub struct ValidatedManifest(ExternalPluginManifest);

impl ValidatedManifest {
    /// Keep the validated declaration immutable so adapters cannot bypass validation by mutating a field.
    pub fn manifest(&self) -> &ExternalPluginManifest {
        &self.0
    }
}

impl ExternalPluginManifest {
    /// Limit input before parsing and avoid echoing parser excerpts that could contain private metadata.
    pub fn parse(bytes: &[u8]) -> Result<ValidatedManifest, ProtocolError> {
        if bytes.len() > MAX_MANIFEST_BYTES {
            return Err(ProtocolError("manifest exceeds byte limit".into()));
        }
        let manifest: Self = serde_json::from_slice(bytes)
            .map_err(|_| ProtocolError("invalid manifest JSON".into()))?;
        manifest.validate()
    }

    /// Freeze declaration identity independently of platform support, enablement and process availability.
    pub fn validate(self) -> Result<ValidatedManifest, ProtocolError> {
        if self.schema_version != MANIFEST_SCHEMA_VERSION
            || !valid_identifier(&self.id)
            || self.id.eq_ignore_ascii_case("kerminal")
            || self.id.to_ascii_lowercase().starts_with("kerminal.")
            || !valid_label(&self.name, 256)
            || self.version.len() > 128
            || semver::Version::parse(&self.version).is_err()
            || self.data_version == 0
            || self.api.major == 0
        {
            return Err(ProtocolError(
                "invalid manifest identity or schema version".into(),
            ));
        }
        if self.platforms.is_empty()
            || self.platforms.len() > 6
            || self.platforms.iter().collect::<BTreeSet<_>>().len() != self.platforms.len()
        {
            return Err(ProtocolError("invalid manifest platform set".into()));
        }
        if self.permissions.len() > 64
            || self.permissions.iter().collect::<BTreeSet<_>>().len() != self.permissions.len()
        {
            return Err(ProtocolError("invalid manifest permission set".into()));
        }
        for permission in &self.permissions {
            if let Permission::SecretRead { slot } = permission
                && self
                    .configuration
                    .settings
                    .as_ref()
                    .is_none_or(|schema| !schema.secret_slots.iter().any(|entry| &entry.id == slot))
            {
                return Err(ProtocolError(
                    "permission references undeclared secret slot".into(),
                ));
            }
        }
        for (key, value) in &self.extensions {
            if !valid_identifier(key) {
                return Err(ProtocolError("invalid extension metadata key".into()));
            }
            validate_value_bounds(value)?;
        }
        self.validate_files()?;
        self.validate_contributions()?;
        Ok(ValidatedManifest(self))
    }

    /// Existing schemas stay identical until actual data preflight exists: even optional additions can collide with preserved unknown values.
    pub fn validate_data_compatibility_with(&self, current: &Self) -> Result<(), ProtocolError> {
        let compatible = self.id == current.id
            && self.data_version == current.data_version
            && current
                .configuration
                .host_types
                .iter()
                .all(|(id, schema)| self.configuration.host_types.get(id) == Some(schema))
            && current
                .configuration
                .settings
                .as_ref()
                .is_none_or(|schema| self.configuration.settings.as_ref() == Some(schema))
            && current.contributions.host_types.iter().all(|old| {
                self.contributions.host_types.iter().any(|new| {
                    new.id == old.id
                        && new.configuration_type == old.configuration_type
                        && new.content_type == old.content_type
                })
            })
            && current.contributions.content_types.iter().all(|old| {
                self.contributions.content_types.iter().any(|new| {
                    new.id == old.id
                        && new.state == old.state
                        && old.kinds.iter().all(|kind| new.kinds.contains(kind))
                })
            })
            && current.contributions.tools.iter().all(|old| {
                self.contributions.tools.iter().any(|new| {
                    new.id == old.id
                        && new.state == old.state
                        && new.scope == old.scope
                        && new.content_type == old.content_type
                })
            });
        if compatible {
            Ok(())
        } else {
            Err(ProtocolError(
                "replacement requires an unsupported plugin data migration".into(),
            ))
        }
    }

    /// Every executable and web entry must be covered by the signed exact file inventory.
    fn validate_files(&self) -> Result<(), ProtocolError> {
        if self.files.len() > 4096 {
            return Err(ProtocolError("invalid package file count".into()));
        }
        let mut paths = BTreeSet::new();
        for file in &self.files {
            validate_package_path(&file.path)?;
            if file.path.eq_ignore_ascii_case("manifest.json")
                || !paths.insert(file.path.to_ascii_lowercase())
                || file.sha256.len() != 64
                || !file.sha256.bytes().all(|byte| byte.is_ascii_hexdigit())
                || file.size > 536_870_912
            {
                return Err(ProtocolError(
                    "invalid or duplicate package file entry".into(),
                ));
            }
        }
        let contains = |path: &str| self.files.iter().any(|file| file.path == path);
        let mut process_platforms = BTreeSet::new();
        for process in &self.entrypoints.process {
            if !self.platforms.contains(&process.platform)
                || !process_platforms.insert(process.platform)
                || !contains(&process.path)
            {
                return Err(ProtocolError("invalid process entrypoint".into()));
            }
        }
        for (id, view) in &self.entrypoints.views {
            owned_id(&self.id, id)?;
            if let ViewEntry::Webview {
                path,
                bridge_version,
            } = view
                && (*bridge_version != crate::PROTOCOL_VERSION || !contains(path))
            {
                return Err(ProtocolError("invalid webview entrypoint".into()));
            }
        }
        Ok(())
    }

    /// Validate cross-references before host registries see a partially registered provider.
    fn validate_contributions(&self) -> Result<(), ProtocolError> {
        let entries = &self.contributions;
        if self.api.is_supported()
            && (!entries.host_types.is_empty() || !entries.commands.is_empty())
            && self.platforms.iter().any(|platform| {
                !self
                    .entrypoints
                    .process
                    .iter()
                    .any(|process| &process.platform == platform)
            })
        {
            return Err(ProtocolError(
                "host or command contribution requires a backend on every supported platform"
                    .into(),
            ));
        }
        let named = entries
            .host_types
            .iter()
            .map(|entry| (&entry.id, &entry.name))
            .chain(
                entries
                    .content_types
                    .iter()
                    .map(|entry| (&entry.id, &entry.name)),
            )
            .chain(entries.tools.iter().map(|entry| (&entry.id, &entry.name)))
            .chain(
                entries
                    .settings_pages
                    .iter()
                    .map(|entry| (&entry.id, &entry.name)),
            )
            .chain(
                entries
                    .commands
                    .iter()
                    .map(|entry| (&entry.id, &entry.name)),
            );
        let mut ids = BTreeSet::new();
        for (id, name) in named {
            owned_id(&self.id, id)?;
            if !valid_label(name, 256) || !ids.insert(id) || ids.len() > 256 {
                return Err(ProtocolError("invalid or duplicate contribution".into()));
            }
        }
        let commands = entries
            .commands
            .iter()
            .map(|entry| entry.id.as_str())
            .collect::<BTreeSet<_>>();
        let contents = entries
            .content_types
            .iter()
            .map(|entry| entry.id.as_str())
            .collect::<BTreeSet<_>>();
        let tools = entries
            .tools
            .iter()
            .map(|entry| entry.id.as_str())
            .collect::<BTreeSet<_>>();
        let mut configuration_types = BTreeSet::new();
        for host in &entries.host_types {
            owned_id(&self.id, &host.configuration_type)?;
            if !configuration_types.insert(&host.configuration_type)
                || host
                    .content_type
                    .as_ref()
                    .is_some_and(|id| !contents.contains(id.as_str()))
            {
                return Err(ProtocolError("invalid host contribution reference".into()));
            }
            let schema = self
                .configuration
                .host_types
                .get(&host.configuration_type)
                .ok_or_else(|| ProtocolError("host configuration schema is missing".into()))?;
            schema.validate_host_definition()?;
            if !schema.secret_slots.is_empty() {
                return Err(ProtocolError(
                    "host secrets require a host credential contract".into(),
                ));
            }
            self.validate_view(&host.form, &commands, Some(schema))?;
            self.validate_local_view(&host.form)?;
        }
        if configuration_types.len() != self.configuration.host_types.len() {
            return Err(ProtocolError("orphan host configuration schema".into()));
        }
        for content in &entries.content_types {
            if content.kinds.is_empty()
                || content.kinds.iter().collect::<BTreeSet<_>>().len() != content.kinds.len()
                || !content.state.secret_slots.is_empty()
            {
                return Err(ProtocolError(
                    "invalid content scope or private secret state".into(),
                ));
            }
            content.state.validate_definition()?;
            self.validate_view(&content.view, &commands, Some(&content.state))?;
        }
        for tool in &entries.tools {
            if !valid_identifier(&tool.icon)
                || tool
                    .content_type
                    .as_ref()
                    .is_some_and(|id| !contents.contains(id.as_str()))
                || !tool.state.secret_slots.is_empty()
            {
                return Err(ProtocolError(
                    "invalid tool reference, icon or private secret state".into(),
                ));
            }
            tool.state.validate_definition()?;
            self.validate_view(&tool.view, &commands, Some(&tool.state))?;
        }
        if let Some(schema) = &self.configuration.settings {
            schema.validate_definition()?;
        }
        for page in &entries.settings_pages {
            let schema =
                self.configuration.settings.as_ref().ok_or_else(|| {
                    ProtocolError("settings configuration schema is missing".into())
                })?;
            validate_search_metadata(&page.description, &page.keywords)?;
            let mut anchors = BTreeSet::new();
            for field in &page.fields {
                if !valid_identifier(&field.id)
                    || !valid_label(&field.name, 256)
                    || !anchors.insert(&field.id)
                {
                    return Err(ProtocolError("invalid settings field anchor".into()));
                }
                validate_search_metadata("", &field.keywords)?;
            }
            self.validate_view(&page.view, &commands, Some(schema))?;
            self.validate_local_view(&page.view)?;
        }
        for command in &entries.commands {
            validate_search_metadata(&command.description, &command.keywords)?;
            match &command.scope {
                CommandScope::Content(id) if !contents.contains(id.as_str()) => {
                    return Err(ProtocolError("unknown command content scope".into()));
                }
                CommandScope::Tool(id) if !tools.contains(id.as_str()) => {
                    return Err(ProtocolError("unknown command tool scope".into()));
                }
                _ => {}
            }
            if let Some(binding) = &command.default_keybinding {
                for value in [&binding.binding, &binding.windows, &binding.macos]
                    .into_iter()
                    .chain(binding.linux.iter())
                {
                    if value.len() > 256 || value.chars().any(char::is_control) {
                        return Err(ProtocolError("invalid default keybinding".into()));
                    }
                }
            }
        }
        let mut placements = BTreeSet::new();
        for placement in &entries.placements {
            if !commands.contains(placement.command.as_str())
                || !valid_identifier(&placement.group)
                || placement
                    .label
                    .as_ref()
                    .is_some_and(|label| !valid_label(label, 256))
                || !placements.insert((&placement.command, &placement.location))
            {
                return Err(ProtocolError("invalid command placement".into()));
            }
            if let CommandLocation::ToolHeader(id) = &placement.location
                && !tools.contains(id.as_str())
            {
                return Err(ProtocolError("unknown command toolbar target".into()));
            }
        }
        // An entry cannot escape validation by remaining unattached until a later runtime message.
        let referenced_views = entries
            .host_types
            .iter()
            .map(|entry| &entry.form)
            .chain(entries.content_types.iter().map(|entry| &entry.view))
            .chain(entries.tools.iter().map(|entry| &entry.view))
            .chain(entries.settings_pages.iter().map(|entry| &entry.view))
            .collect::<BTreeSet<_>>();
        if self
            .entrypoints
            .views
            .keys()
            .any(|id| !referenced_views.contains(id))
        {
            return Err(ProtocolError("orphan view entrypoint".into()));
        }
        Ok(())
    }

    /// Shared view references always retain the schema of their actual contribution surface.
    fn validate_view(
        &self,
        id: &str,
        commands: &BTreeSet<&str>,
        schema: Option<&ConfigurationSchema>,
    ) -> Result<(), ProtocolError> {
        match self.entrypoints.views.get(id) {
            Some(ViewEntry::Native { view }) => {
                if view.lifecycle.is_some()
                    && self.platforms.iter().any(|platform| {
                        !self
                            .entrypoints
                            .process
                            .iter()
                            .any(|entry| &entry.platform == platform)
                    })
                {
                    return Err(ProtocolError(
                        "native lifecycle requires a process on every supported platform".into(),
                    ));
                }
                view.validate(commands, schema)
            }
            Some(ViewEntry::Webview { .. }) => Ok(()),
            None => Err(ProtocolError("contribution view is missing".into())),
        }
    }

    /// Host and settings forms are transactional drafts; background lifecycle cannot replace their values.
    fn validate_local_view(&self, id: &str) -> Result<(), ProtocolError> {
        if matches!(self.entrypoints.views.get(id), Some(ViewEntry::Native { view }) if view.lifecycle.is_some())
        {
            return Err(ProtocolError(
                "transactional forms cannot declare runtime lifecycle".into(),
            ));
        }
        Ok(())
    }
}

/// Portable spellings reject Windows aliases, including ASCII-numbered devices, even when packages are built on another platform.
pub fn validate_package_path(path: &str) -> Result<(), ProtocolError> {
    if path.is_empty()
        || path.len() > 240
        || !path.is_ascii()
        || path.starts_with('/')
        || path.contains(['\\', ':', '\0'])
    {
        return Err(ProtocolError("invalid package path".into()));
    }
    for segment in path.split('/') {
        if segment.is_empty()
            || segment == "."
            || segment == ".."
            || segment.ends_with(['.', ' '])
            || segment
                .bytes()
                .any(|byte| byte < 32 || matches!(byte, b'<' | b'>' | b'"' | b'|' | b'?' | b'*'))
        {
            return Err(ProtocolError("invalid package path segment".into()));
        }
        let stem = segment
            .split('.')
            .next()
            .unwrap_or_default()
            .to_ascii_uppercase();
        if matches!(
            stem.as_str(),
            "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
        ) || (stem.len() == 4
            && (stem.starts_with("COM") || stem.starts_with("LPT"))
            && stem.as_bytes()[3].is_ascii_digit())
        {
            return Err(ProtocolError("reserved package path segment".into()));
        }
    }
    Ok(())
}

/// Namespacing prevents an external package from claiming an existing host or another provider's identity.
fn owned_id(provider: &str, id: &str) -> Result<(), ProtocolError> {
    if valid_identifier(id) && id.starts_with(&format!("{provider}.")) {
        Ok(())
    } else {
        Err(ProtocolError(
            "contribution is outside its provider namespace".into(),
        ))
    }
}

/// Search text remains data and is bounded independently of the number of contribution records.
fn validate_search_metadata(description: &str, keywords: &[String]) -> Result<(), ProtocolError> {
    if description.len() > 4096
        || description.contains('\0')
        || keywords.len() > 32
        || keywords.iter().any(|keyword| !valid_label(keyword, 128))
    {
        return Err(ProtocolError("invalid contribution search metadata".into()));
    }
    Ok(())
}
