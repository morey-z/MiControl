[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string]$InstallerPath,

    [string]$OutputPath,

    [string]$TargetDirectory = 'target-candidate-2.0.6'
)

$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$OutputPath = if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    Join-Path $repoRoot 'dist/micontrol-2.0.6-x64-manifest.json'
} else {
    $OutputPath
}
$package = Get-Content -LiteralPath (Join-Path $repoRoot 'package.json') -Raw | ConvertFrom-Json
$installer = (Resolve-Path -LiteralPath $InstallerPath).Path
$relativeInstaller = $installer.Substring($repoRoot.Length).TrimStart([char[]]"/\")
$artifacts = @(
    [ordered]@{
        path = $relativeInstaller.Replace('\', '/')
        sha256 = (Get-FileHash -LiteralPath $installer -Algorithm SHA256).Hash.ToLowerInvariant()
        bytes = (Get-Item -LiteralPath $installer).Length
    }
)
$targetRoot = if ([IO.Path]::IsPathRooted($TargetDirectory)) {
    [IO.Path]::GetFullPath($TargetDirectory)
} else {
    [IO.Path]::GetFullPath((Join-Path $repoRoot $TargetDirectory))
}
$app = Join-Path $targetRoot 'release/micontrol-windows-app.exe'
if (Test-Path -LiteralPath $app -PathType Leaf) {
    $relativeApp = $app.Substring($repoRoot.Length).TrimStart([char[]]"/\")
    $artifacts += [ordered]@{
        path = $relativeApp.Replace('\', '/')
        sha256 = (Get-FileHash -LiteralPath $app -Algorithm SHA256).Hash.ToLowerInvariant()
        bytes = (Get-Item -LiteralPath $app).Length
    }
}

$manifest = [ordered]@{
    schema = 'micontrol-release-manifest/v1'
    product = 'MiControl'
    version = [string]$package.version
    target = 'x86_64-pc-windows-msvc'
    packageManager = [string]$package.packageManager
    service = [ordered]@{
        name = 'MiControlRC003HidTap'
        installRoot = '%ProgramFiles%\MiControlRC003HidService'
        brokerProtocol = 4
        ownerServiceRights = 'SERVICE_QUERY_STATUS|SERVICE_START'
    }
    builtAtUtc = [DateTime]::UtcNow.ToString('o')
    artifacts = $artifacts
}

$destination = if ([IO.Path]::IsPathRooted($OutputPath)) {
    [IO.Path]::GetFullPath($OutputPath)
} else {
    [IO.Path]::GetFullPath((Join-Path (Get-Location) $OutputPath))
}
$parent = Split-Path -Parent $destination
New-Item -ItemType Directory -Force -Path $parent | Out-Null
$json = $manifest | ConvertTo-Json -Depth 8
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[IO.File]::WriteAllText($destination, $json, $utf8NoBom)
Write-Output $destination
