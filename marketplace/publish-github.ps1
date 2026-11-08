#requires -Version 7.2
param(
    [string]$ArchivePath,
    [string]$PublicKeyPath,
    [string]$SecretKeyPath,
    [string]$PluginToolPath,
    [string]$OutputDirectory,
    [string]$GitHubCliPath = 'gh',
    [string]$Repository = 'kongweiguang/Kerminal-Plugins',
    [string]$SourceId = 'kerminal-github',
    [string]$KeyId = 'kerminal-examples-2026',
    [string]$PluginPrefix = 'example.workbench',
    [string]$PackageReleaseTag,
    [string]$CatalogReleaseTag = 'plugins-catalog-v1',
    [ValidateRange(1, 18446744073709551615)][uint64]$Sequence = 1,
    [ValidateRange(1, 31)][int]$ExpiresInDays = 30,
    [Security.SecureString]$SigningPassword,
    [switch]$Publish
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Invoke-PublisherProcess {
    # ArgumentList keeps filenames and release text out of shell evaluation; password bytes use stdin only.
    param([string]$Program, [string[]]$Arguments, [Security.SecureString]$Password)
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $Program
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $start.RedirectStandardInput = $null -ne $Password
    foreach ($argument in $Arguments) { $start.ArgumentList.Add($argument) }
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $start
    try {
        [void]$process.Start()
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        if ($null -ne $Password) {
            $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
            try { $process.StandardInput.WriteLine([Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer)) }
            finally {
                [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer)
                $process.StandardInput.Close()
            }
        }
        if (-not $process.WaitForExit(120000)) {
            $process.Kill($true)
            [void]$process.WaitForExit(10000)
            throw 'Publisher command timed out after 120 seconds; only its owned process tree was stopped.'
        }
        $outputText = $stdout.GetAwaiter().GetResult()
        $errorText = $stderr.GetAwaiter().GetResult()
        if ($process.ExitCode -ne 0) { throw "Publisher command failed ($($process.ExitCode)): $errorText" }
        return $outputText.Trim()
    }
    finally { $process.Dispose() }
}

function Assert-PublisherIdentity {
    # Release paths become public URLs, so accept only portable components and a fixed GitHub repository shape.
    param([string]$Repo, [string[]]$Identifiers)
    if ($Repo -cnotmatch '^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$') { throw 'Expected a GitHub owner/repository.' }
    foreach ($identity in $Identifiers) {
        if ($identity -cnotmatch '^[A-Za-z0-9][A-Za-z0-9._-]*[A-Za-z0-9]$' -or $identity.Contains('..')) {
            throw 'Source IDs, namespaces, tags and asset names must use safe portable components.'
        }
    }
}

function Write-PublisherJson {
    # Generated release metadata is UTF-8 without a BOM; signing and upload retain these exact bytes.
    param([string]$Path, $Value)
    [IO.File]::WriteAllText($Path, ($Value | ConvertTo-Json -Depth 40), [Text.UTF8Encoding]::new($false))
}

function Get-PublisherHash {
    # A prepared plan pins every public file, preventing review/publish drift without storing private key paths.
    param([string]$Path)
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Remove-PublisherTemporaryDirectory {
    # Only a task-named immediate child of the system temp directory may be recursively removed on Windows.
    param([string]$Path, [string]$ExpectedPrefix)
    $absolute = [IO.Path]::GetFullPath($Path)
    $parent = [IO.Path]::GetDirectoryName($absolute)
    $temporaryRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar)
    $comparison = if ($IsWindows) { [StringComparison]::OrdinalIgnoreCase } else { [StringComparison]::Ordinal }
    if (-not [string]::Equals($parent, $temporaryRoot, $comparison) -or
        -not [IO.Path]::GetFileName($absolute).StartsWith($ExpectedPrefix, [StringComparison]::Ordinal) -or
        $ExpectedPrefix -cnotmatch '^kerminal-[a-z-]+-$') {
        throw 'Refusing to remove a directory outside the owned publisher temporary namespace.'
    }
    Remove-Item -LiteralPath $absolute -Recurse -Force
}

function Assert-PreparedPublisherFiles {
    # Never publish changed bytes from an existing staging directory or accept path traversal through a plan.
    param([string]$Directory, $Plan)
    Assert-PublisherIdentity $Plan.repository @($Plan.archiveName)
    $expectedFiles = @($Plan.archiveName, "$($Plan.archiveName).minisig", 'publisher.pub', 'index.json', 'index.json.minisig', 'github-source.json', 'package-notes.md', 'catalog-notes.md')
    if (@(Compare-Object -CaseSensitive $expectedFiles @($Plan.files.PSObject.Properties.Name)).Count -ne 0) {
        throw 'Prepared plan must pin every public release file exactly once.'
    }
    foreach ($entry in $Plan.files.PSObject.Properties) {
        Assert-PublisherIdentity -Repo $Plan.repository -Identifiers @($entry.Name)
        $file = Join-Path $Directory $entry.Name
        if (-not [IO.File]::Exists($file) -or (Get-PublisherHash $file) -cne $entry.Value) {
            throw "Prepared release file changed or disappeared: $($entry.Name)"
        }
    }
    $catalog = Get-Content -LiteralPath (Join-Path $Directory 'index.json') -Raw | ConvertFrom-Json
    if ($catalog.sequence -ne $Plan.sequence -or $catalog.expiresAt -le [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()) {
        throw 'Prepared catalog is inconsistent or expired; prepare a new sequence.'
    }
}

function Get-PublisherRelease {
    # GitHub's tag endpoint may hide drafts; an authenticated list recovers owned drafts without mistaking auth/network errors for absence.
    param([string]$Cli, [string]$Repo, [string]$Tag)
    try {
        return Invoke-PublisherProcess $Cli @('api', "repos/$Repo/releases/tags/$Tag") | ConvertFrom-Json
    }
    catch {
        if ($_.Exception.Message -notmatch '\(HTTP 404\)') { throw }
    }
    $pages = Invoke-PublisherProcess $Cli @('api', '--paginate', '--slurp', "repos/$Repo/releases?per_page=100") | ConvertFrom-Json
    $matches = @(
        foreach ($page in $pages) {
            foreach ($release in $page) {
                if ($release.tag_name -ceq $Tag) { $release }
            }
        }
    )
    if ($matches.Count -gt 1) { throw 'More than one release owns this tag; resolve the drafts before publishing.' }
    if ($matches.Count -eq 1) { return $matches[0] }
    return $null
}

function Assert-RemotePublisherAsset {
    # Download and hash existing assets rather than trusting a filename; published package bytes are immutable.
    param([string]$Cli, [string]$Repo, $Release, [string]$Directory, [string]$Name)
    $assets = @($Release.assets | Where-Object { $_.name -ceq $Name })
    if ($assets.Count -ne 1) { throw "Expected exactly one existing release asset: $Name" }
    $temporary = Join-Path ([IO.Path]::GetTempPath()) ('kerminal-publish-' + [Guid]::NewGuid().ToString('N'))
    [void][IO.Directory]::CreateDirectory($temporary)
    try {
        [void](Invoke-PublisherProcess $Cli @('release', 'download', $Release.tag_name, '--repo', $Repo, '--pattern', $Name, '--dir', $temporary))
        if ((Get-PublisherHash (Join-Path $temporary $Name)) -cne (Get-PublisherHash (Join-Path $Directory $Name))) {
            throw "Existing release asset differs; bump the plugin version instead of replacing it: $Name"
        }
    }
    finally { Remove-PublisherTemporaryDirectory $temporary 'kerminal-publish-' }
}

function Publish-PreparedGitHubPlugin {
    # Publish immutable packages before the signed directory. A mismatched index/signature pair fails closed in the client.
    param([string]$Directory, [string]$Cli)
    $plan = Get-Content -LiteralPath (Join-Path $Directory 'release-plan.json') -Raw | ConvertFrom-Json
    Assert-PublisherIdentity $plan.repository @($plan.packageTag, $plan.catalogTag)
    Assert-PreparedPublisherFiles $Directory $plan
    $catalogRelease = Get-PublisherRelease $Cli $plan.repository $plan.catalogTag
    if ($null -ne $catalogRelease) {
        if (-not $catalogRelease.draft -or @($catalogRelease.assets | Where-Object { $_.name -ceq 'publisher.pub' }).Count -ne 0) {
            Assert-RemotePublisherAsset $Cli $plan.repository $catalogRelease $Directory 'publisher.pub'
        }
    }
    if ($null -ne $catalogRelease -and
        (-not $catalogRelease.draft -or @($catalogRelease.assets | Where-Object { $_.name -ceq 'index.json' }).Count -ne 0)) {
        # An empty owned draft is a recoverable upload stage; a published catalog must always contain its prior index.
        $temporary = Join-Path ([IO.Path]::GetTempPath()) ('kerminal-catalog-' + [Guid]::NewGuid().ToString('N'))
        [void][IO.Directory]::CreateDirectory($temporary)
        try {
            [void](Invoke-PublisherProcess $Cli @('release', 'download', $plan.catalogTag, '--repo', $plan.repository, '--pattern', 'index.json', '--dir', $temporary))
            $prior = Get-Content -LiteralPath (Join-Path $temporary 'index.json') -Raw | ConvertFrom-Json
            if ($prior.sourceId -cne $plan.sourceId -or $prior.sequence -gt $plan.sequence -or
                ($prior.sequence -eq $plan.sequence -and
                 (Get-PublisherHash (Join-Path $temporary 'index.json')) -cne $plan.files.'index.json')) {
                throw 'Changed catalogs require a higher sequence; only identical bytes can resume an interrupted publication.'
            }
            if (@($prior.plugins | Where-Object { $_.id -cne $plan.pluginId }).Count -ne 0) {
                throw 'This single-plugin publisher cannot discard other plugins; use a complete catalog specification.'
            }
            $current = Get-Content -LiteralPath (Join-Path $Directory 'index.json') -Raw | ConvertFrom-Json
            foreach ($old in $prior.plugins) {
                foreach ($new in $current.plugins) {
                    if ($old.id -ceq $new.id -and $old.version -ceq $new.version -and $old.sha256 -cne $new.sha256) {
                        throw 'A released plugin ID/version cannot be rebound to different package bytes.'
                    }
                }
            }
        }
        finally { Remove-PublisherTemporaryDirectory $temporary 'kerminal-catalog-' }
    }
    $packageRelease = Get-PublisherRelease $Cli $plan.repository $plan.packageTag
    if ($null -eq $packageRelease) {
        [void](Invoke-PublisherProcess $Cli @('release', 'create', $plan.packageTag, '--repo', $plan.repository, '--draft', '--prerelease', '--latest=false', '--title', $plan.packageTag, '--notes-file', (Join-Path $Directory 'package-notes.md')))
        $packageRelease = Get-PublisherRelease $Cli $plan.repository $plan.packageTag
        if ($null -eq $packageRelease) { throw 'The created draft is not yet readable; retry the same prepared directory.' }
    }
    foreach ($name in @($plan.archiveName, "$($plan.archiveName).minisig", 'publisher.pub')) {
        if (@($packageRelease.assets | Where-Object { $_.name -ceq $name }).Count -eq 0) {
            if (-not $packageRelease.draft) { throw "Published package release is missing an immutable asset: $name" }
            [void](Invoke-PublisherProcess $Cli @('release', 'upload', $plan.packageTag, (Join-Path $Directory $name), '--repo', $plan.repository))
        }
        else { Assert-RemotePublisherAsset $Cli $plan.repository $packageRelease $Directory $name }
    }
    if ($packageRelease.draft) {
        [void](Invoke-PublisherProcess $Cli @('release', 'edit', $plan.packageTag, '--repo', $plan.repository, '--draft=false', '--prerelease', '--latest=false'))
    }
    if ($null -eq $catalogRelease) {
        [void](Invoke-PublisherProcess $Cli @('release', 'create', $plan.catalogTag, '--repo', $plan.repository, '--draft', '--prerelease', '--latest=false', '--title', 'Kerminal plugin catalog', '--notes-file', (Join-Path $Directory 'catalog-notes.md')))
    }
    $upload = @('release', 'upload', $plan.catalogTag, '--repo', $plan.repository, '--clobber')
    foreach ($name in @('index.json', 'index.json.minisig', 'github-source.json', 'publisher.pub')) { $upload += Join-Path $Directory $name }
    [void](Invoke-PublisherProcess $Cli $upload)
    [void](Invoke-PublisherProcess $Cli @('release', 'edit', $plan.catalogTag, '--repo', $plan.repository, '--draft=false', '--prerelease', '--latest=false', '--notes-file', (Join-Path $Directory 'catalog-notes.md')))
    Write-Output "Published package: https://github.com/$($plan.repository)/releases/tag/$($plan.packageTag)"
    Write-Output "Published catalog: https://github.com/$($plan.repository)/releases/tag/$($plan.catalogTag)"
}

if ($MyInvocation.InvocationName -eq '.') { return }
if ([string]::IsNullOrWhiteSpace($OutputDirectory)) { throw 'Specify a new -OutputDirectory for preparation, or an existing prepared directory with -Publish.' }
$OutputDirectory = [IO.Path]::GetFullPath($OutputDirectory)
if (Test-Path -LiteralPath $OutputDirectory) {
    if (-not $Publish) { throw 'OutputDirectory already exists; use a new directory or explicitly publish the prepared result.' }
    Publish-PreparedGitHubPlugin $OutputDirectory $GitHubCliPath
    exit 0
}
foreach ($required in @($ArchivePath, $PublicKeyPath, $SecretKeyPath, $PluginToolPath)) {
    if ([string]::IsNullOrWhiteSpace($required) -or -not [IO.File]::Exists($required)) { throw 'Preparation needs existing ArchivePath, PublicKeyPath, SecretKeyPath and PluginToolPath files.' }
}
$ArchivePath = [IO.Path]::GetFullPath($ArchivePath)
$PublicKeyPath = [IO.Path]::GetFullPath($PublicKeyPath)
$SecretKeyPath = [IO.Path]::GetFullPath($SecretKeyPath)
$PluginToolPath = [IO.Path]::GetFullPath($PluginToolPath)
$archiveName = [IO.Path]::GetFileName($ArchivePath)
Assert-PublisherIdentity $Repository @($SourceId, $KeyId, $PluginPrefix, $CatalogReleaseTag, $archiveName)
[void][IO.Directory]::CreateDirectory($OutputDirectory)
Copy-Item -LiteralPath $ArchivePath -Destination (Join-Path $OutputDirectory $archiveName)
Copy-Item -LiteralPath $PublicKeyPath -Destination (Join-Path $OutputDirectory 'publisher.pub')
$signaturePath = Join-Path $OutputDirectory "$archiveName.minisig"
$signArgs = @('sign', '--input', (Join-Path $OutputDirectory $archiveName), '--secret-key', $SecretKeyPath, '--public-key', $PublicKeyPath, '--out', $signaturePath)
if ($null -ne $SigningPassword) { $signArgs += '--password-stdin' }
[void](Invoke-PublisherProcess $PluginToolPath $signArgs $SigningPassword)
$verified = Invoke-PublisherProcess $PluginToolPath @('verify', '--archive', (Join-Path $OutputDirectory $archiveName), '--signature', $signaturePath, '--public-key', $PublicKeyPath)
if ($verified -cnotmatch '^Verified ([A-Za-z0-9._-]+) ([A-Za-z0-9.+-]+) ([a-f0-9]{64})$') { throw 'Unexpected package verifier response.' }
$pluginId, $version = $Matches[1], $Matches[2]
if ([string]::IsNullOrWhiteSpace($PackageReleaseTag)) { $PackageReleaseTag = "plugin-workbench-v$version" }
Assert-PublisherIdentity $Repository @($PackageReleaseTag)
$base = "https://github.com/$Repository/releases/download"
$origins = @('https://github.com', 'https://release-assets.githubusercontent.com')
$now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
Write-PublisherJson (Join-Path $OutputDirectory 'catalog-spec.json') @{
    sourceId = $SourceId; sequence = $Sequence; publishedAt = $now; expiresAt = $now + $ExpiresInDays * 86400
    allowedOrigins = $origins; pluginPrefixes = @($PluginPrefix)
    packages = @(@{
        archive = $archiveName; signature = "$archiveName.minisig"; publicKey = 'publisher.pub'; keyId = $KeyId
        archiveUrl = "$base/$PackageReleaseTag/$archiveName"; signatureUrl = "$base/$PackageReleaseTag/$archiveName.minisig"
        description = '独立原生示例：主机、便笺 Tab、侧栏工具、设置、快捷键和宿主确认框。'
    })
}
[void](Invoke-PublisherProcess $PluginToolPath @('index', '--spec', (Join-Path $OutputDirectory 'catalog-spec.json'), '--out', (Join-Path $OutputDirectory 'index.json')))
$indexSign = @('sign', '--input', (Join-Path $OutputDirectory 'index.json'), '--secret-key', $SecretKeyPath, '--public-key', $PublicKeyPath, '--out', (Join-Path $OutputDirectory 'index.json.minisig'))
if ($null -ne $SigningPassword) { $indexSign += '--password-stdin' }
[void](Invoke-PublisherProcess $PluginToolPath $indexSign $SigningPassword)
[void](Invoke-PublisherProcess $PluginToolPath @('verify-signature', '--input', (Join-Path $OutputDirectory 'index.json'), '--signature', (Join-Path $OutputDirectory 'index.json.minisig'), '--public-key', $PublicKeyPath))
Write-PublisherJson (Join-Path $OutputDirectory 'github-source.json') @{
    id = $SourceId; name = 'Kerminal 插件市场'; indexUrl = "$base/$CatalogReleaseTag/index.json"
    indexSignatureUrl = "$base/$CatalogReleaseTag/index.json.minisig"; indexKeyId = $KeyId
    keys = @{ $KeyId = [IO.File]::ReadAllText($PublicKeyPath) }; pluginPrefixes = @($PluginPrefix); downloadOrigins = $origins
}
[IO.File]::WriteAllText((Join-Path $OutputDirectory 'package-notes.md'), "Independent native example for the Kerminal external plugin API v1. Requires a host build with external plugin support. Package ID: $pluginId; version: $version. Install through the signed plugin catalog; restarting applies the pending installation.")
[IO.File]::WriteAllText((Join-Path $OutputDirectory 'catalog-notes.md'), "Signed Kerminal example plugin catalog, sequence $Sequence. Expires at $([DateTimeOffset]::FromUnixTimeSeconds($now + $ExpiresInDays * 86400).ToString('u')). The source configuration pins its namespace, public key and permitted GitHub download origins. This catalog does not replace the application's release channel.")
$hashes = [ordered]@{}
foreach ($name in @($archiveName, "$archiveName.minisig", 'publisher.pub', 'index.json', 'index.json.minisig', 'github-source.json', 'package-notes.md', 'catalog-notes.md')) { $hashes[$name] = Get-PublisherHash (Join-Path $OutputDirectory $name) }
Write-PublisherJson (Join-Path $OutputDirectory 'release-plan.json') @{
    schemaVersion = 1; repository = $Repository; packageTag = $PackageReleaseTag; catalogTag = $CatalogReleaseTag
    sourceId = $SourceId; pluginId = $pluginId; archiveName = $archiveName; sequence = $Sequence; files = $hashes
}
Write-Output "Prepared signed release: $OutputDirectory"
Write-Output 'Review release-plan.json, index.json, github-source.json and the permission-bearing package manifest before publishing.'
if ($Publish) { Publish-PreparedGitHubPlugin $OutputDirectory $GitHubCliPath }
