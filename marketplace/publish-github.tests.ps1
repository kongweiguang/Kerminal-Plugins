#requires -Version 7.2
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'publish-github.ps1')

function Assert-PublisherTestThrows {
    # Failure tests keep unsafe paths and review/publish drift executable without contacting GitHub or reading real keys.
    param([scriptblock]$Action)
    $failed = $false
    try { & $Action }
    catch { $failed = $true }
    if (-not $failed) { throw 'Expected publisher guard to reject the operation.' }
}

Assert-PublisherIdentity 'kongweiguang/Kerminal' @('example.workbench', 'plugin-workbench-v1.0.0', 'workbench-windows_x86_64.tar')
foreach ($unsafe in @('../secret', 'x/y', 'a#label', 'a?download', '-delete', 'unsafe..tag')) {
    Assert-PublisherTestThrows { Assert-PublisherIdentity 'kongweiguang/Kerminal' @($unsafe) }
}
Assert-PublisherTestThrows { Assert-PublisherIdentity 'github.com/owner/repo' @('example.workbench') }

$temporary = Join-Path ([IO.Path]::GetTempPath()) ('kerminal-publisher-tests-' + [Guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($temporary)
try {
    $indexPath = Join-Path $temporary 'index.json'
    Write-PublisherJson $indexPath @{ sequence = 7; expiresAt = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds() + 60 }
    $plan = [pscustomobject]@{
        repository = 'kongweiguang/Kerminal'; sequence = 7; archiveName = 'example.tar'
        files = [pscustomobject]@{ 'index.json' = Get-PublisherHash $indexPath }
    }
    Assert-PublisherTestThrows { Assert-PreparedPublisherFiles $temporary $plan }
    foreach ($name in @('example.tar', 'example.tar.minisig', 'publisher.pub', 'index.json.minisig', 'github-source.json', 'package-notes.md', 'catalog-notes.md')) {
        [IO.File]::WriteAllText((Join-Path $temporary $name), 'test-public-file')
        $plan.files | Add-Member -NotePropertyName $name -NotePropertyValue (Get-PublisherHash (Join-Path $temporary $name))
    }
    Assert-PreparedPublisherFiles $temporary $plan
    [IO.File]::AppendAllText($indexPath, ' ')
    Assert-PublisherTestThrows { Assert-PreparedPublisherFiles $temporary $plan }
    $plan.files.'index.json' = Get-PublisherHash $indexPath
    $plan.sequence = 8
    Assert-PublisherTestThrows { Assert-PreparedPublisherFiles $temporary $plan }
    $plan.sequence = 7
    Write-PublisherJson $indexPath @{ sequence = 7; expiresAt = 1 }
    $plan.files.'index.json' = Get-PublisherHash $indexPath
    Assert-PublisherTestThrows { Assert-PreparedPublisherFiles $temporary $plan }

    $pwsh = (Get-Command pwsh -ErrorAction Stop).Source
    $argument = 'literal $HOME `with quotes` and spaces'
    $echoScript = Join-Path $temporary 'echo-argument.ps1'
    [IO.File]::WriteAllText($echoScript, 'param([string]$Value) [Console]::Write($Value)')
    $actual = Invoke-PublisherProcess $pwsh @('-NoProfile', '-File', $echoScript, $argument)
    if ($actual -cne $argument) { throw 'Publisher process changed an argument.' }
    Assert-PublisherTestThrows { Invoke-PublisherProcess $pwsh @('-NoProfile', '-Command', 'exit 3') }
}
finally {
    Remove-PublisherTemporaryDirectory $temporary 'kerminal-publisher-tests-'
}

# Mock only the process boundary: the draft fallback and failure rules still execute the production lookup.
$originalProcess = ${function:Invoke-PublisherProcess}
try {
    $script:lookupCase = 'draft'
    $script:lookupCalls = 0
    function Invoke-PublisherProcess {
        # A synthetic GitHub transport distinguishes hidden drafts, absent tags and real service failures without credentials.
        param([string]$Program, [string[]]$Arguments, [Security.SecureString]$Password)
        $script:lookupCalls++
        if ($script:lookupCase -eq 'publish-draft') {
            if ($Arguments[0] -eq 'api') {
                $tag = $Arguments[1].Split('/')[-1]
                return (@{ id = 101; tag_name = $tag; draft = $true; assets = @() } | ConvertTo-Json)
            }
            $script:releaseOperations.Add($Arguments[1])
            return ''
        }
        if ($Arguments[1] -eq '--paginate') {
            if ($script:lookupCase -eq 'list-failure') { throw 'Publisher command failed (1): gh: HTTP 401' }
            if ($script:lookupCase -eq 'absent') { return '[[]]' }
            if ($script:lookupCase -eq 'duplicate') { return '[[{"id":101,"tag_name":"plugin-workbench-v1.0.0","draft":true,"assets":[]},{"id":102,"tag_name":"plugin-workbench-v1.0.0","draft":true,"assets":[]}]]' }
            return '[[{"id":1,"tag_name":"other","draft":false,"assets":[]}],[{"id":101,"tag_name":"plugin-workbench-v1.0.0","draft":true,"assets":[]}]]'
        }
        if ($script:lookupCase -eq 'network') { throw 'Publisher command failed (1): connection timed out' }
        if ($script:lookupCase -eq 'auth') { throw 'Publisher command failed (1): gh: HTTP 401' }
        throw 'Publisher command failed (1): gh: Not Found (HTTP 404)'
    }
    $draft = Get-PublisherRelease 'fake-gh' 'kongweiguang/Kerminal' 'plugin-workbench-v1.0.0'
    if ($draft.id -ne 101 -or -not $draft.draft -or $script:lookupCalls -ne 2) { throw 'Hidden draft was not recovered from the authenticated list.' }
    $script:lookupCase = 'absent'
    if ($null -ne (Get-PublisherRelease 'fake-gh' 'kongweiguang/Kerminal' 'missing')) { throw 'An absent release should remain absent.' }
    foreach ($failure in @('network', 'auth', 'list-failure', 'duplicate')) {
        $script:lookupCase = $failure
        Assert-PublisherTestThrows { Get-PublisherRelease 'fake-gh' 'kongweiguang/Kerminal' 'plugin-workbench-v1.0.0' }
    }
    $temporary = Join-Path ([IO.Path]::GetTempPath()) ('kerminal-publisher-tests-' + [Guid]::NewGuid().ToString('N'))
    [void][IO.Directory]::CreateDirectory($temporary)
    try {
        $script:lookupCase = 'publish-draft'
        $script:releaseOperations = [Collections.Generic.List[string]]::new()
        $hashes = @{}
        foreach ($name in @('example.tar', 'example.tar.minisig', 'publisher.pub', 'index.json', 'index.json.minisig', 'github-source.json', 'package-notes.md', 'catalog-notes.md')) {
            $file = Join-Path $temporary $name
            if ($name -eq 'index.json') { Write-PublisherJson $file @{ sequence = 7; expiresAt = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds() + 60 } }
            else { [IO.File]::WriteAllText($file, 'test-public-file') }
            $hashes[$name] = Get-PublisherHash $file
        }
        Write-PublisherJson (Join-Path $temporary 'release-plan.json') @{
            repository = 'kongweiguang/Kerminal'; packageTag = 'plugin-workbench-v1.0.0'; catalogTag = 'plugins-catalog-v1'
            archiveName = 'example.tar'; sequence = 7; sourceId = 'kerminal-github'; pluginId = 'example.workbench'; files = $hashes
        }
        [void](Publish-PreparedGitHubPlugin $temporary 'fake-gh')
        if (@($script:releaseOperations | Where-Object { $_ -eq 'upload' }).Count -ne 4 -or
            @($script:releaseOperations | Where-Object { $_ -eq 'edit' }).Count -ne 2 -or
            @($script:releaseOperations | Where-Object { $_ -eq 'create' }).Count -ne 0) {
            throw 'Existing empty drafts must resume uploads rather than create duplicate releases.'
        }
    }
    finally { Remove-PublisherTemporaryDirectory $temporary 'kerminal-publisher-tests-' }
}
finally { ${function:Invoke-PublisherProcess} = $originalProcess }
Write-Output 'Publisher tests passed: paths, file integrity, sequence, expiry, literal arguments, process failure and hidden-draft recovery.'
