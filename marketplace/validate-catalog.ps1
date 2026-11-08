#requires -Version 7.2
param([Parameter(Mandatory)][string]$PluginToolPath)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repositoryRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$tool = (Resolve-Path -LiteralPath $PluginToolPath).Path

function Assert-CatalogCommand {
    # The tool verifies exact committed bytes; a failed signature must fail the job rather than leave a green last command.
    param([string[]]$Arguments)
    & $script:tool @Arguments
    if ($LASTEXITCODE -ne 0) { throw 'Committed catalog or package verification failed.' }
}

$catalogRoot = Join-Path $repositoryRoot 'catalog'
$source = Get-Content -LiteralPath (Join-Path $catalogRoot 'github-source.json') -Raw | ConvertFrom-Json
$keyPath = Join-Path $catalogRoot 'publisher.pub'
$key = [IO.File]::ReadAllText($keyPath).Trim()
if ($source.keys.PSObject.Properties[$source.indexKeyId].Value.Trim() -cne $key) { throw 'Index key differs from the reviewed source.' }
Assert-CatalogCommand @('verify-signature', '--input', (Join-Path $catalogRoot 'index.json'), '--signature', (Join-Path $catalogRoot 'index.json.minisig'), '--public-key', $keyPath)
$catalog = Get-Content -LiteralPath (Join-Path $catalogRoot 'index.json') -Raw | ConvertFrom-Json
$plugins = @(Get-Content -LiteralPath (Join-Path $catalogRoot 'plugins.json') -Raw | ConvertFrom-Json)
if ($catalog.sourceId -cne $source.id -or @($catalog.plugins).Count -ne $plugins.Count) { throw 'Source list differs from the signed catalog.' }
foreach ($plugin in $plugins) {
    $matching = @($catalog.plugins | Where-Object { $_.id -ceq $plugin.id -and $_.version -ceq $plugin.version })
    if ($matching.Count -ne 1) { throw 'Each source entry must match one signed catalog entry.' }
    foreach ($field in @('id','name','description','version','packageKeyId','archiveUrl','signatureUrl','sha256','archiveBytes')) {
        if ([string]$matching[0].$field -cne [string]$plugin.$field) { throw "Reviewed source differs in $field." }
    }
    $url = [uri]$plugin.archiveUrl
    if ($url.Scheme -cne 'https' -or $source.downloadOrigins -cnotcontains $url.GetLeftPart([UriPartial]::Authority)) { throw 'Package origin is outside source trust.' }
    if ($url.Host -ceq 'raw.githubusercontent.com') {
        $marker = '/packages/'
        $offset = $url.AbsolutePath.IndexOf($marker, [StringComparison]::Ordinal)
        if ($offset -lt 0 -or $url.AbsolutePath -match '/(main|refs/heads/main)/') { throw 'Raw package mirrors require a version tag and a packages path.' }
        $relative = [Uri]::UnescapeDataString($url.AbsolutePath.Substring($offset + 1))
        $archive = [IO.Path]::GetFullPath((Join-Path $repositoryRoot $relative))
        if (-not $archive.StartsWith((Join-Path $repositoryRoot 'packages') + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) { throw 'Raw package path escapes packages.' }
        if ((Get-Item -LiteralPath $archive).Length -ne $plugin.archiveBytes -or (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant() -cne $plugin.sha256) { throw 'Raw package differs from the signed digest or size.' }
        if ($plugin.packageKeyId -cne $source.indexKeyId) { throw 'A separate publisher needs a separately reviewed public-key file.' }
        Assert-CatalogCommand @('verify', '--archive', $archive, '--signature', "$archive.minisig", '--public-key', $keyPath)
    }
}
Write-Output "Verified committed directory and $($plugins.Count) reviewed source entries."
