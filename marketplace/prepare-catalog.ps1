#requires -Version 7.2
param(
    [Parameter(Mandatory)][string]$PluginToolPath,
    [Parameter(Mandatory)][string]$SecretKeyPath,
    [Parameter(Mandatory)][Security.SecureString]$SigningPassword,
    [Parameter(Mandatory)][ValidateRange(1, 18446744073709551615)][uint64]$Sequence,
    [Parameter(Mandatory)][string]$OutputDirectory,
    [ValidateRange(1, 31)][int]$ExpiresInDays = 30,
    [string]$ArtifactsDirectory
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Invoke-CatalogTool {
    # Argument arrays avoid shell expansion; signing secrets only cross an owned stdin pipe.
    param([string[]]$Arguments, [Security.SecureString]$Password)
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $script:toolPath
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
            throw 'Catalog tool timed out; its owned process tree was stopped.'
        }
        $result = $stdout.GetAwaiter().GetResult()
        $errorText = $stderr.GetAwaiter().GetResult()
        if ($process.ExitCode -ne 0) { throw "Catalog tool failed: $errorText" }
        return $result.Trim()
    }
    finally { $process.Dispose() }
}

function Write-CatalogJson {
    # Sign and publish these exact UTF-8 bytes; no serializer runs after signing.
    param([string]$Path, $Value)
    [IO.File]::WriteAllText($Path, ($Value | ConvertTo-Json -Depth 40), [Text.UTF8Encoding]::new($false))
}

function Receive-CatalogAsset {
    # Cached artifacts still pass identical signature, identity and digest checks; online redirects and streams stay bounded.
    param([uri]$Url, [string]$Destination, [long]$MaximumBytes)
    if ($null -ne $script:artifactRoot) {
        $name = [Uri]::UnescapeDataString($Url.Segments[-1])
        if ([IO.Path]::GetFileName($name) -cne $name -or $name -cnotmatch '^[A-Za-z0-9][A-Za-z0-9._+-]*$') { throw 'Unsafe cached asset name.' }
        $candidate = Join-Path $script:artifactRoot $name
        $file = Get-Item -LiteralPath $candidate
        if ($file.PSIsContainer -or $file.Length -gt $MaximumBytes) { throw 'Cached asset exceeds its reviewed bound.' }
        Copy-Item -LiteralPath $candidate -Destination $Destination
        return
    }
    $current = $Url
    $deadline = [Threading.CancellationTokenSource]::new(120000)
    try {
    for ($hop = 0; $hop -lt 6; $hop++) {
        if ($current.Scheme -cne 'https' -or $current.UserInfo -ne '' -or $current.Fragment -ne '' -or
            $script:source.downloadOrigins -cnotcontains $current.GetLeftPart([UriPartial]::Authority)) {
            throw 'Asset URL or redirect is outside the reviewed HTTPS download origins.'
        }
        $response = $script:client.GetAsync($current, [Net.Http.HttpCompletionOption]::ResponseHeadersRead, $deadline.Token).GetAwaiter().GetResult()
        try {
            $status = [int]$response.StatusCode
            if ($status -in @(301,302,303,307,308)) {
                if ($null -eq $response.Headers.Location) { throw 'Asset redirect has no target.' }
                $current = [uri]::new($current, $response.Headers.Location)
                continue
            }
            if ($status -ne 200) { throw "Asset download failed with HTTP $status." }
            if ($null -ne $response.Content.Headers.ContentLength -and $response.Content.Headers.ContentLength -gt $MaximumBytes) {
                throw 'Asset exceeds its reviewed byte bound.'
            }
            $inputStream = $response.Content.ReadAsStreamAsync().GetAwaiter().GetResult()
            $outputStream = [IO.File]::Open($Destination, [IO.FileMode]::CreateNew)
            try {
                $buffer = [byte[]]::new(65536)
                [long]$count = 0
                while (($read = $inputStream.ReadAsync($buffer, 0, $buffer.Length, $deadline.Token).GetAwaiter().GetResult()) -gt 0) {
                    $count += $read
                    if ($count -gt $MaximumBytes) { throw 'Asset exceeds its reviewed byte bound.' }
                    $outputStream.Write($buffer, 0, $read)
                }
            }
            finally { $inputStream.Dispose(); $outputStream.Dispose() }
            return
        }
        finally { $response.Dispose() }
    }
    throw 'Asset redirect limit exceeded.'
    }
    finally { $deadline.Dispose() }
}

$repositoryRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$script:artifactRoot = if ([string]::IsNullOrWhiteSpace($ArtifactsDirectory)) { $null } else { (Resolve-Path -LiteralPath $ArtifactsDirectory).Path }
$script:toolPath = (Resolve-Path -LiteralPath $PluginToolPath).Path
$secretPath = (Resolve-Path -LiteralPath $SecretKeyPath).Path
if ($secretPath.StartsWith($repositoryRoot + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Signing keys must remain outside this repository.'
}
$outputPath = [IO.Path]::GetFullPath($OutputDirectory)
if (Test-Path -LiteralPath $outputPath) { throw 'Choose a new output directory; prepared releases are never overwritten.' }
$script:source = Get-Content -LiteralPath (Join-Path $repositoryRoot 'catalog/github-source.json') -Raw | ConvertFrom-Json
$plugins = @(Get-Content -LiteralPath (Join-Path $repositoryRoot 'catalog/plugins.json') -Raw | ConvertFrom-Json)
$prior = Get-Content -LiteralPath (Join-Path $repositoryRoot 'catalog/index.json') -Raw | ConvertFrom-Json
if ($Sequence -le $prior.sequence) { throw 'Sequence must exceed the checked-in complete directory.' }
if ($plugins.Count -gt 1024) { throw 'Too many catalog entries.' }
[void][IO.Directory]::CreateDirectory($outputPath)
$handler = [Net.Http.HttpClientHandler]::new()
$handler.AllowAutoRedirect = $false
$script:client = [Net.Http.HttpClient]::new($handler)
$script:client.Timeout = [TimeSpan]::FromSeconds(120)
$script:client.DefaultRequestHeaders.UserAgent.ParseAdd('Kerminal-Plugins-Catalog/1')
$packages = @()
$identities = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
try {
    foreach ($plugin in $plugins) {
        if (-not $identities.Add("$($plugin.id)/$($plugin.version)")) { throw 'Duplicate plugin ID/version in source list.' }
        if ($plugin.sha256 -cnotmatch '^[a-f0-9]{64}$' -or $plugin.archiveBytes -lt 1 -or $plugin.archiveBytes -gt 67108864) {
            throw 'Each reviewed package needs a SHA-256 and a valid bounded size.'
        }
        $archive = "$($plugin.id)-$($plugin.version).tar"
        if ($archive -cnotmatch '^[A-Za-z0-9][A-Za-z0-9.+_-]*\.tar$' -or $archive.Contains('..')) { throw 'Unsafe package identity.' }
        $keyProperty = $source.keys.PSObject.Properties[$plugin.packageKeyId]
        if ($null -eq $keyProperty) { throw 'Package key is absent from reviewed source trust.' }
        $keyPath = Join-Path $outputPath "$archive.pub"
        [IO.File]::WriteAllText($keyPath, $keyProperty.Value, [Text.UTF8Encoding]::new($false))
        Receive-CatalogAsset $plugin.archiveUrl (Join-Path $outputPath $archive) $plugin.archiveBytes
        Receive-CatalogAsset $plugin.signatureUrl (Join-Path $outputPath "$archive.minisig") 16384
        if ((Get-Item -LiteralPath (Join-Path $outputPath $archive)).Length -ne $plugin.archiveBytes) { throw 'Package size differs from reviewed source.' }
        $verified = Invoke-CatalogTool @('verify', '--archive', (Join-Path $outputPath $archive), '--signature', (Join-Path $outputPath "$archive.minisig"), '--public-key', $keyPath)
        if ($verified -cne "Verified $($plugin.id) $($plugin.version) $($plugin.sha256)") { throw 'Verified package identity or digest differs from reviewed source.' }
        $packages += @{
            archive=$archive; signature="$archive.minisig"; publicKey="$archive.pub"; keyId=$plugin.packageKeyId
            archiveUrl=$plugin.archiveUrl; signatureUrl=$plugin.signatureUrl; description=$plugin.description
        }
    }
    $now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    $spec = @{
        sourceId=$source.id; sequence=$Sequence; publishedAt=$now; expiresAt=$now + $ExpiresInDays * 86400
        allowedOrigins=$source.downloadOrigins; pluginPrefixes=$source.pluginPrefixes; packages=$packages
    }
    Write-CatalogJson (Join-Path $outputPath 'catalog-spec.json') $spec
    [void](Invoke-CatalogTool @('index', '--spec', (Join-Path $outputPath 'catalog-spec.json'), '--out', (Join-Path $outputPath 'index.json')))
    $indexKey = $source.keys.PSObject.Properties[$source.indexKeyId]
    if ($null -eq $indexKey) { throw 'Index signing key is absent from source trust.' }
    [IO.File]::WriteAllText((Join-Path $outputPath 'publisher.pub'), $indexKey.Value, [Text.UTF8Encoding]::new($false))
    [void](Invoke-CatalogTool @('sign', '--input', (Join-Path $outputPath 'index.json'), '--secret-key', $secretPath, '--public-key', (Join-Path $outputPath 'publisher.pub'), '--out', (Join-Path $outputPath 'index.json.minisig'), '--password-stdin') $SigningPassword)
    [void](Invoke-CatalogTool @('verify-signature', '--input', (Join-Path $outputPath 'index.json'), '--signature', (Join-Path $outputPath 'index.json.minisig'), '--public-key', (Join-Path $outputPath 'publisher.pub')))
    Copy-Item -LiteralPath (Join-Path $repositoryRoot 'catalog/github-source.json') -Destination (Join-Path $outputPath 'github-source.json')
    $hashes = [ordered]@{}
    foreach ($name in @('index.json','index.json.minisig','github-source.json','publisher.pub')) {
        $hashes[$name] = (Get-FileHash -LiteralPath (Join-Path $outputPath $name) -Algorithm SHA256).Hash.ToLowerInvariant()
    }
    Write-CatalogJson (Join-Path $outputPath 'catalog-receipt.json') @{sourceId=$source.id; sequence=$Sequence; packages=$plugins.Count; files=$hashes}
    Write-Output "Prepared complete signed catalog ($($plugins.Count) entries): $outputPath"
    Write-Output 'No release was published. Review all entries, immutable versions and the remote sequence before publishing.'
}
finally { $client.Dispose(); $handler.Dispose() }
