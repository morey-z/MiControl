[CmdletBinding()]
param(
    [string]$Version = '2.0.8',
    [string]$OutputPath = 'SOURCE_MANIFEST.json'
)

$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$output = [IO.Path]::GetFullPath((Join-Path $repoRoot $OutputPath))
$excluded = @('.git', 'node_modules', 'dist', 'target', 'SOURCE_MANIFEST.json')
$entries = @()
$archivePath = Join-Path ([IO.Path]::GetTempPath()) ('micontrol-source-manifest-' + [guid]::NewGuid().ToString('N') + '.zip')
$extractRoot = Join-Path ([IO.Path]::GetTempPath()) ('micontrol-source-manifest-' + [guid]::NewGuid().ToString('N'))
try {
    git -c core.quotePath=false -C $repoRoot archive --format=zip --output $archivePath HEAD
    if ($LASTEXITCODE -ne 0) { throw 'git archive failed.' }
    Expand-Archive -LiteralPath $archivePath -DestinationPath $extractRoot
    $packageRoot = Get-Item -LiteralPath $extractRoot
    foreach ($relative in @(git -c core.quotePath=false -C $repoRoot ls-files)) {
        $relative = $relative.Replace([string][char]92, '/')
        if ($excluded | Where-Object { $relative -eq $_ -or $relative.StartsWith("$_/") }) { continue }
        $file = Get-Item -LiteralPath (Join-Path $packageRoot.FullName $relative)
        $hash = Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256
        $entries += [ordered]@{
            path = $relative
            bytes = $file.Length
            sha256 = $hash.Hash
        }
    }
} finally {
    if (Test-Path -LiteralPath $archivePath) { Remove-Item -LiteralPath $archivePath -Force }
    if (Test-Path -LiteralPath $extractRoot) { Remove-Item -LiteralPath $extractRoot -Recurse -Force }
}
$manifest = [ordered]@{
    schema = 'micontrol-source-manifest/v2'
    product = 'MiControl'
    version = $Version
    repository = 'https://github.com/morey-z/MiControl'
    baseRevision = 'ce5a9de934c95062a6bc303cc22b44a0e1cfb63f'
    entryCount = $entries.Count
    totalBytes = ($entries | ForEach-Object { [int64]$_.bytes } | Measure-Object -Sum).Sum
    manifestSelfExcluded = $true
    entries = $entries
    notes = @(
        'Entries use package-relative paths and SHA-256; no machine-local paths, user state, logs, credentials, or recordings are included.',
        'The release package also contains generated artifact hashes in RELEASE_MANIFEST.json.'
    )
}
$json = $manifest | ConvertTo-Json -Depth 8
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[IO.File]::WriteAllText($output, $json, $utf8NoBom)
Write-Output $output
