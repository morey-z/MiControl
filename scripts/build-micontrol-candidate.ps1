[CmdletBinding()]
param(
    [string]$Version = '2.0.7',
    [ValidateSet('rc1', 'rc2', 'rc3', 'rc4', 'rc5', 'rc6')]
    [string]$CandidateLabel = 'rc1',
    [string]$TargetDirectory,
    [string]$ReportPath,
    [string]$NsisExtractorPath = $env:MICONTROL_NSIS_EXTRACTOR_PATH,
    [switch]$PlanOnly,
    [switch]$KeepTemporary
)

$ErrorActionPreference = 'Stop'

function Get-AbsolutePath([string]$Path) { return [IO.Path]::GetFullPath($Path) }

function Write-Utf8NoBom([string]$Path, [string]$Contents) {
    $encoding = New-Object System.Text.UTF8Encoding($false)
    [IO.File]::WriteAllText($Path, $Contents, $encoding)
}

function Get-HashRecord([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "预检失败：文件不存在：$Path" }
    $item = Get-Item -LiteralPath $Path
    $hash = Get-FileHash -LiteralPath $Path -Algorithm SHA256
    return [ordered]@{ path = $item.FullName; sha256 = $hash.Hash; bytes = $item.Length }
}

function Get-CargoWorkspaceVersion([string]$Path) {
    $text = Get-Content -LiteralPath $Path -Raw -Encoding UTF8
    $match = [regex]::Match($text, '(?ms)^\[workspace\.package\].*?^\s*version\s*=\s*"([^"]+)"')
    if (-not $match.Success) { throw "预检失败：无法读取 workspace.package.version：$Path" }
    return $match.Groups[1].Value
}

function Get-CargoLockPackageVersion([string]$Path, [string]$PackageName) {
    $text = Get-Content -LiteralPath $Path -Raw -Encoding UTF8
    $pattern = '(?ms)\[\[package\]\]\s+name\s*=\s*"' + [regex]::Escape($PackageName) + '"\s+version\s*=\s*"([^"]+)"'
    $match = [regex]::Match($text, $pattern)
    if (-not $match.Success) { throw "预检失败：Cargo.lock 中找不到本地包 $PackageName" }
    return $match.Groups[1].Value
}

function Assert-SameVersion([string]$Name, [string]$Actual, [string]$Expected) {
    if ($Actual -ne $Expected) { throw "候选构建预检失败：$Name 当前为 $Actual，期待 $Expected；请先统一更新版本元数据。脚本未启动 pnpm/cargo。" }
}

function Assert-File([string]$Path, [string]$Label) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "构建产物预检失败：$Label 不存在：$Path" }
}

# This is the x64 7-Zip 26.03 build with NSIS archive support used by the
# release audit.  The path is supplied explicitly or through
# MICONTROL_NSIS_EXTRACTOR_PATH; a missing or different tool is a hard fail.
$expectedNsisExtractorVersion = '7-Zip 26.03 (x64)'
$expectedNsisExtractorSource = 'https://github.com/myfreeer/7z-build-nsis/releases/download/26.03/7z2603.7z'
$expectedNsisExtractorExeSha256 = '562EC14D95D27EA081B0F05D703FBB438BDD5E7E9931F60F881D9C0340E18B21'
$expectedNsisExtractorDllSha256 = 'F7DD02C05C49589B1869D4D551FEC54BB97F8F3D0CA746234FF181B1A9695A12'

function Quote-ProcessArgument([string]$Value) {
    if ($Value -notmatch '[\s"]') { return $Value }
    return '"' + $Value.Replace('"', '\"') + '"'
}

function Invoke-CapturedProcess([string]$FilePath, [string[]]$Arguments, [string]$StdoutPath, [string]$StderrPath) {
    $argumentLine = [string]::Join(' ', @($Arguments | ForEach-Object { Quote-ProcessArgument $_ }))
    $process = Start-Process -FilePath $FilePath -ArgumentList $argumentLine -Wait -PassThru -WindowStyle Hidden -RedirectStandardOutput $StdoutPath -RedirectStandardError $StderrPath
    return $process.ExitCode
}

function Get-NsisExtractorInfo([string]$Path, [string]$ScratchRoot) {
    if ([string]::IsNullOrWhiteSpace($Path)) {
        throw 'payload 预检失败：未提供支持 NSIS 的 7-Zip 路径；请使用 -NsisExtractorPath 或 MICONTROL_NSIS_EXTRACTOR_PATH。'
    }
    $resolvedPath = Get-AbsolutePath $Path
    Assert-File $resolvedPath 'NSIS extractor'
    $dllPath = Join-Path (Split-Path -Parent $resolvedPath) '7z.dll'
    Assert-File $dllPath 'NSIS extractor sibling 7z.dll'
    $exeRecord = Get-HashRecord $resolvedPath
    $dllRecord = Get-HashRecord $dllPath
    if ($exeRecord.sha256 -ne $expectedNsisExtractorExeSha256 -or $dllRecord.sha256 -ne $expectedNsisExtractorDllSha256) {
        throw "payload 预检失败：NSIS extractor hash 不匹配；exe=$($exeRecord.sha256)，dll=$($dllRecord.sha256)。"
    }
    $stdout = Join-Path $ScratchRoot 'nsis-extractor-version.stdout.txt'
    $stderr = Join-Path $ScratchRoot 'nsis-extractor-version.stderr.txt'
    $exitCode = Invoke-CapturedProcess $resolvedPath @('-h') $stdout $stderr
    $versionText = ((Get-Content -LiteralPath $stdout -Raw -ErrorAction SilentlyContinue) + (Get-Content -LiteralPath $stderr -Raw -ErrorAction SilentlyContinue))
    if ($exitCode -ne 0 -or $versionText -notmatch [regex]::Escape($expectedNsisExtractorVersion)) {
        throw "payload 预检失败：NSIS extractor 版本探针失败，exit=$exitCode。"
    }
    return [ordered]@{ path = $resolvedPath; version = $expectedNsisExtractorVersion; source = $expectedNsisExtractorSource; exe = $exeRecord; dll = $dllRecord }
}

function Invoke-NsisPayloadExtraction([string]$ExtractorPath, [string]$SetupPath, [string]$OutputPath, [string[]]$Members, [string]$ScratchRoot) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    $stdout = Join-Path $ScratchRoot 'nsis-payload-extract.stdout.txt'
    $stderr = Join-Path $ScratchRoot 'nsis-payload-extract.stderr.txt'
    $arguments = @('x', $SetupPath, ('-o' + $OutputPath), '-y') + $Members
    $exitCode = Invoke-CapturedProcess $ExtractorPath $arguments $stdout $stderr
    if ($exitCode -ne 0) {
        throw "payload 预检失败：NSIS payload 提取失败，exit=$exitCode；stderr=$stderr。"
    }
}

function Find-AsciiMarker([byte[]]$Bytes, [byte[]]$Marker, [int]$StartAt = 0) {
    for ($start = $StartAt; $start -le $Bytes.Length - $Marker.Length; $start++) {
        $matched = $true
        for ($offset = 0; $offset -lt $Marker.Length; $offset++) {
            if ($Bytes[$start + $offset] -ne $Marker[$offset]) { $matched = $false; break }
        }
        if ($matched) { return $start }
    }
    return -1
}

function Test-ByteSequenceEqual([byte[]]$Left, [byte[]]$Right) {
    if ($Left.Length -ne $Right.Length) { return $false }
    for ($index = 0; $index -lt $Left.Length; $index++) {
        if ($Left[$index] -ne $Right[$index]) { return $false }
    }
    return $true
}

function Assert-MainPayload([string]$SourcePath, [string]$PayloadPath) {
    $source = [IO.File]::ReadAllBytes($SourcePath)
    $payload = [IO.File]::ReadAllBytes($PayloadPath)
    if ($source.Length -ne $payload.Length) { throw "payload 预检失败：main payload 长度不一致，source=$($source.Length)，payload=$($payload.Length)。" }
    $unknown = [Text.Encoding]::ASCII.GetBytes('__TAURI_BUNDLE_TYPE_VAR_UNK')
    $nsis = [Text.Encoding]::ASCII.GetBytes('__TAURI_BUNDLE_TYPE_VAR_NSS')
    $sourceMarker = Find-AsciiMarker $source $unknown
    $payloadMarker = Find-AsciiMarker $payload $nsis
    if ($sourceMarker -lt 0 -or $payloadMarker -ne $sourceMarker) {
        if (-not (Test-ByteSequenceEqual $source $payload)) { throw 'payload 预检失败：main payload 与构建输出不一致，且没有合法 Tauri NSIS marker 变换。' }
        return [ordered]@{ mode = 'exact'; source = Get-HashRecord $SourcePath; payload = Get-HashRecord $PayloadPath; markerOffset = $null; changedBytes = 0 }
    }
    $secondSourceMarker = Find-AsciiMarker $source $unknown ($sourceMarker + $unknown.Length)
    if ($secondSourceMarker -ge 0) { throw 'payload 预检失败：main source 存在重复 Tauri bundle marker，拒绝模糊匹配。' }
    $changed = 0
    for ($index = 0; $index -lt $source.Length; $index++) {
        $expected = if ($index -ge $sourceMarker -and $index -lt ($sourceMarker + $nsis.Length)) { $nsis[$index - $sourceMarker] } else { $source[$index] }
        if ($payload[$index] -ne $expected) { $changed++ }
    }
    if ($changed -ne 0) { throw "payload 预检失败：main payload 除合法 Tauri NSIS marker 外仍有 $changed 个字节差异。" }
    $markerChangedBytes = 0
    for ($index = 0; $index -lt $unknown.Length; $index++) { if ($unknown[$index] -ne $nsis[$index]) { $markerChangedBytes++ } }
    return [ordered]@{ mode = 'tauri-bundle-marker'; source = Get-HashRecord $SourcePath; payload = Get-HashRecord $PayloadPath; markerOffset = $sourceMarker; changedBytes = $markerChangedBytes }
}

function Assert-ExactPayload([string]$SourcePath, [string]$PayloadPath, [string]$Label) {
    $source = Get-HashRecord $SourcePath
    $payload = Get-HashRecord $PayloadPath
    if ($source.sha256 -ne $payload.sha256 -or $source.bytes -ne $payload.bytes) { throw "payload 预检失败：$Label payload 与冻结输入不一致。source=$($source.sha256)，payload=$($payload.sha256)。" }
    return [ordered]@{ mode = 'exact'; source = $source; payload = $payload; markerOffset = $null; changedBytes = 0 }
}

function Save-TraceArchive([string]$ArchivePath, [string]$HookPath, [string]$ConfigPath, [string]$OriginalHookPath, [string]$BuildScriptPath, [object[]]$SourceSnapshot, [string]$RunId, [string]$Status, [string]$Version, [string]$TargetRoot) {
    New-Item -ItemType Directory -Path $ArchivePath -Force | Out-Null
    $archiveHook = Join-Path $ArchivePath 'installer-hooks.nsh'
    $archiveOriginalHook = Join-Path $ArchivePath 'installer-hooks.original.nsh'
    $archiveBuildScript = Join-Path $ArchivePath 'build-micontrol-candidate.ps1'
    $archiveConfig = Join-Path $ArchivePath 'tauri.candidate.json'
    Copy-Item -LiteralPath $HookPath -Destination $archiveHook -Force
    Copy-Item -LiteralPath $OriginalHookPath -Destination $archiveOriginalHook -Force
    Copy-Item -LiteralPath $BuildScriptPath -Destination $archiveBuildScript -Force
    Copy-Item -LiteralPath $ConfigPath -Destination $archiveConfig -Force
    $trace = [ordered]@{
        runId = $RunId
        status = $Status
        version = $Version
        targetRoot = $TargetRoot
        hook = Get-HashRecord $archiveHook
        originalHook = Get-HashRecord $archiveOriginalHook
        buildScript = Get-HashRecord $archiveBuildScript
        config = Get-HashRecord $archiveConfig
        sourceFiles = $SourceSnapshot
    }
    Write-Utf8NoBom (Join-Path $ArchivePath 'trace.json') ($trace | ConvertTo-Json -Depth 16)
    return $trace
}

$repoRoot = Get-AbsolutePath (Join-Path $PSScriptRoot '..')
if ($Version -ne '2.0.7') { throw "安全预检失败：本脚本只生成 2.0.7 候选，收到版本 $Version。" }
if (-not $TargetDirectory) { $TargetDirectory = Join-Path $repoRoot ("target-candidate-2.0.7-{0}" -f $CandidateLabel) }
$targetRoot = Get-AbsolutePath $TargetDirectory
$canonicalTargetRoot = Get-AbsolutePath (Join-Path $repoRoot 'target')
if ($targetRoot -eq $canonicalTargetRoot) { throw '安全预检失败：候选构建不能使用现有 target 目录。' }
if ($targetRoot -notmatch ('\\target-candidate-2\.0\.7-' + [regex]::Escape($CandidateLabel) + '$')) {
    throw "安全预检失败：$CandidateLabel 候选构建必须使用隔离的 target-candidate-2.0.7-$CandidateLabel 目录。"
}
if (-not $ReportPath) { $ReportPath = Join-Path $repoRoot '..\..\ditanchengxu\.analysis-output\micontrol-rc003\candidate-build-2.0.7-report.json' }
$ReportPath = Get-AbsolutePath $ReportPath

$packageJsonPath = Join-Path $repoRoot 'package.json'
$buildScriptPath = [IO.Path]::GetFullPath($MyInvocation.MyCommand.Path)
$originalHookPath = Join-Path $repoRoot 'src-tauri\windows\installer-hooks.nsh'
$tauriConfigPath = Join-Path $repoRoot 'src-tauri\tauri.conf.json'
$tauriConfigParent = Split-Path -Parent $tauriConfigPath
$frontendDistRoot = Get-AbsolutePath (Join-Path $repoRoot 'dist')
$frontendDistRelative = '../dist'
$lockPath = Join-Path $repoRoot 'Cargo.lock'
$package = Get-Content -LiteralPath $packageJsonPath -Raw -Encoding UTF8 | ConvertFrom-Json
$tauriConfig = Get-Content -LiteralPath $tauriConfigPath -Raw -Encoding UTF8 | ConvertFrom-Json
$versions = [ordered]@{
    packageJson = [string]$package.version
    tauriConfig = [string]$tauriConfig.version
    cargoWorkspace = Get-CargoWorkspaceVersion (Join-Path $repoRoot 'Cargo.toml')
    micontrolCore = Get-CargoLockPackageVersion $lockPath 'micontrol-core'
    micontrolWindows = Get-CargoLockPackageVersion $lockPath 'micontrol-windows'
    micontrolWindowsApp = Get-CargoLockPackageVersion $lockPath 'micontrol-windows-app'
}
foreach ($entry in $versions.GetEnumerator()) { Assert-SameVersion $entry.Key $entry.Value $Version }

$nativeSources = @(
    (Join-Path $repoRoot 'crates\micontrol-windows\src\hid_tap_service.rs'),
    (Join-Path $repoRoot 'crates\micontrol-windows\src\hid_tap_windows.rs'),
    (Join-Path $repoRoot 'src-tauri\src\hid_tap_service.rs')
)
$helperSource = Join-Path $repoRoot 'crates\micontrol-windows\src\bin\micontrol-service-cleanup.rs'
$compatSource = Join-Path $repoRoot 'crates\micontrol-windows\src\installer_compat.rs'
$sourceFiles = @(
    $nativeSources
    $compatSource
    $helperSource
    (Join-Path $repoRoot 'crates\micontrol-windows\src\send_input.rs')
    (Join-Path $repoRoot 'crates\micontrol-windows\src\button_mapping.rs')
    (Join-Path $repoRoot 'src-tauri\src\settings.rs')
    (Join-Path $repoRoot 'src-tauri\src\main.rs')
    (Join-Path $repoRoot 'src\pages\ButtonsPage.vue')
    (Join-Path $repoRoot 'src\pages\ButtonsPage.test.ts')
    (Join-Path $repoRoot 'src\pages\return-volume-independent.test.ts')
    (Join-Path $repoRoot 'src\lib\bridge.ts')
    (Join-Path $repoRoot 'src\lib\bridge.test.ts')
    $originalHookPath
    $buildScriptPath
    $tauriConfigPath
    $packageJsonPath
    (Join-Path $repoRoot 'Cargo.toml')
    $lockPath
) | Select-Object -Unique
$sourceBefore = @($sourceFiles | ForEach-Object { Get-HashRecord $_ })

$gadgetSource = Join-Path $repoRoot 'src-tauri\resources\hid-tap\frida-gadget.dll'
$licenseSource = Join-Path $repoRoot 'src-tauri\resources\hid-tap\frida-COPYING.txt'
$helperOutput = Join-Path $targetRoot 'release\micontrol-service-cleanup.exe'
$mainOutput = Join-Path $targetRoot 'release\micontrol-windows-app.exe'
$nsisOutput = Join-Path $targetRoot 'release\nsis\x64\installer.nsi'
$setupBuildOutput = Join-Path $targetRoot ('release\bundle\nsis\MiControl_{0}_x64-setup.exe' -f $Version)
$setupOutput = Join-Path $targetRoot ('release\bundle\nsis\MiControl_{0}-{1}_x64-setup.exe' -f $Version, $CandidateLabel)

$tempRoot = Join-Path $env:TEMP ('MiControl-candidate-build-' + [guid]::NewGuid().ToString('N'))
$overrideConfigPath = Join-Path $tempRoot 'tauri.candidate.json'
$hookPath = Join-Path $tempRoot 'installer-hooks.candidate.nsh'
$runId = ((Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssfffZ') + '-' + ([guid]::NewGuid().ToString('N').Substring(0, 8)))
$archiveRoot = Join-Path (Split-Path -Parent $ReportPath) ('candidate-build-2.0.7-run-' + $runId)
$runStatus = 'preflight'
$temporaryCreated = $false
$oldCargoTarget = $env:CARGO_TARGET_DIR
$locationPushed = $false
$traceArchived = $false
$reportWritten = $false

try {
    New-Item -ItemType Directory -Path $tempRoot -Force | Out-Null
    $temporaryCreated = $true
    $nsisExtractorInfo = Get-NsisExtractorInfo $NsisExtractorPath $tempRoot
    $hookText = Get-Content -LiteralPath (Join-Path $repoRoot 'src-tauri\windows\installer-hooks.nsh') -Raw -Encoding UTF8
    $definePattern = '(?m)^[ \t]*!define[ \t]+MICONTROL_CLEANUP_HELPER_SOURCE[ \t]+[^\r\n]*'
    $defineMatches = [regex]::Matches($hookText, $definePattern)
    if ($defineMatches.Count -ne 1) { throw "临时 NSIS hook 预检失败：MICONTROL_CLEANUP_HELPER_SOURCE 定义数量为 $($defineMatches.Count)，拒绝按行号替换。" }
    $replacement = '!define MICONTROL_CLEANUP_HELPER_SOURCE "' + $helperOutput.Replace('"', '""') + '"'
    $hookText = [regex]::Replace($hookText, $definePattern, $replacement, 1)
    if ($hookText -notmatch '(?m)^\s*File\s+"\$\{MICONTROL_CLEANUP_HELPER_SOURCE\}"') { throw '临时 NSIS hook 预检失败：卸载器未使用专用 helper define。' }
    if ($hookText -match [regex]::Escape('..\target\release\micontrol-service-cleanup.exe')) { throw '临时 NSIS hook 预检失败：仍残留旧 target/release helper 路径。' }
    Write-Utf8NoBom $hookPath $hookText

    # Tauri --config uses RFC7396-style deep merge. Null entries remove the
    # relative keys from the canonical config; the absolute entries below are
    # then the complete effective resource map.
    $baseResources = [ordered]@{}
    foreach ($property in $tauriConfig.bundle.resources.psobject.Properties) {
        $baseResources[$property.Name] = $property.Value
    }
    $resourcePatch = [ordered]@{
        'resources/hid-tap/frida-gadget.dll' = $null
        'resources/hid-tap/frida-COPYING.txt' = $null
        '../target/release/micontrol-service-cleanup.exe' = $null
        $gadgetSource = 'hid-tap/frida-gadget.dll'
        $licenseSource = 'hid-tap/frida-COPYING.txt'
        $helperOutput = 'micontrol-service-cleanup.exe'
    }
    # `frontendDist` is an untagged serde enum (Url, Directory, Files).  A
    # Windows absolute string such as `D:\...\dist` is accepted by url::Url
    # as scheme `d`, selecting FrontendDist::Url and therefore embedding no
    # frontend assets.  Keep this value relative to the real Tauri config
    # parent (`src-tauri`), which is the parent used by generate_context! and
    # tauri-build when TAURI_CONFIG is merged by the CLI.
    $tauriConfig.build.frontendDist = $frontendDistRelative
    $resolvedFrontendDist = Get-AbsolutePath (Join-Path $tauriConfigParent $frontendDistRelative)
    if ($resolvedFrontendDist -ne $frontendDistRoot) { throw "前端资源预检失败：frontendDist=$frontendDistRelative 从 config parent $tauriConfigParent 解析为 $resolvedFrontendDist，期待 $frontendDistRoot。" }
    if (-not (Test-Path -LiteralPath (Join-Path $resolvedFrontendDist 'index.html') -PathType Leaf)) { throw "前端资源预检失败：缺少 $resolvedFrontendDist\index.html。" }
    $frontendFiles = @(Get-ChildItem -LiteralPath $resolvedFrontendDist -Recurse -File | Sort-Object FullName)
    if ($frontendFiles.Count -lt 2) { throw "前端资源预检失败：$resolvedFrontendDist 中没有足够的 dist 文件。" }
    $frontendManifest = @($frontendFiles | ForEach-Object {
        $relative = $_.FullName.Substring($resolvedFrontendDist.Length).TrimStart('\', '/').Replace('\', '/')
        [ordered]@{ path = $relative; sha256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash; bytes = $_.Length }
    })
    $tauriConfig.bundle.icon = @($tauriConfig.bundle.icon | ForEach-Object { Join-Path $repoRoot ('src-tauri\' + $_) })
    $tauriConfig.bundle.windows.nsis.installerIcon = Join-Path $repoRoot 'src-tauri\icons\icon.ico'
    $tauriConfig.bundle.windows.nsis.uninstallerIcon = Join-Path $repoRoot 'src-tauri\icons\icon.ico'
    $tauriConfig.bundle.resources = $resourcePatch
    $tauriConfig.bundle.windows.nsis.installerHooks = $hookPath
    $overrideJson = $tauriConfig | ConvertTo-Json -Depth 64
    $overrideObject = $overrideJson | ConvertFrom-Json
    $overrideResources = @($overrideObject.bundle.resources.psobject.Properties)
    $newResourceNames = @($gadgetSource, $licenseSource, $helperOutput)
    foreach ($source in $newResourceNames) {
        $matches = @($overrideResources | Where-Object { $_.Name -eq $source })
        if ($matches.Count -ne 1 -or $null -eq $matches[0].Value) { throw "临时 Tauri config 预检失败：缺少有效资源 source $source。" }
    }
    foreach ($oldSource in @('resources/hid-tap/frida-gadget.dll', 'resources/hid-tap/frida-COPYING.txt', '../target/release/micontrol-service-cleanup.exe')) {
        $matches = @($overrideResources | Where-Object { $_.Name -eq $oldSource })
        if ($matches.Count -ne 1 -or $null -ne $matches[0].Value) { throw "临时 Tauri config 预检失败：旧资源 source $oldSource 未以 null 删除。" }
    }
    $effectiveResources = [ordered]@{}
    foreach ($entry in $baseResources.GetEnumerator()) { $effectiveResources[$entry.Key] = $entry.Value }
    foreach ($entry in $resourcePatch.GetEnumerator()) {
        if ($null -eq $entry.Value) { [void]$effectiveResources.Remove($entry.Key) } else { $effectiveResources[$entry.Key] = $entry.Value }
    }
    if ($effectiveResources.Count -ne 3 -or
        -not $effectiveResources.Contains($gadgetSource) -or
        -not $effectiveResources.Contains($licenseSource) -or
        -not $effectiveResources.Contains($helperOutput) -or
        $effectiveResources.Contains('../target/release/micontrol-service-cleanup.exe')) {
        throw '临时 Tauri config 预检失败：RFC7396 合并后的 resources 不是三项候选绝对 source 映射。'
    }
    if (@($effectiveResources.Keys | Where-Object { -not [IO.Path]::IsPathRooted($_) }).Count -ne 0) {
        throw '临时 Tauri config 预检失败：RFC7396 合并后仍有相对资源 source。'
    }
    Write-Utf8NoBom $overrideConfigPath $overrideJson

    $plan = [ordered]@{ version = $Version; candidateLabel = $CandidateLabel; repository = $repoRoot; cargoTargetDirectory = $targetRoot; overrideConfig = $overrideConfigPath; temporaryInstallerHook = $hookPath; mainOutput = $mainOutput; helperOutput = $helperOutput; nsisOutput = $nsisOutput; setupBuildOutput = $setupBuildOutput; setupOutput = $setupOutput; effectiveResources = $effectiveResources; sourceFiles = $sourceBefore; sourceFileCount = $sourceBefore.Count; frontendDist = [ordered]@{ mode = 'Directory'; configParent = $tauriConfigParent; configuredValue = $frontendDistRelative; resolvedPath = $resolvedFrontendDist; files = $frontendManifest }; helperMustBeProducedByBeforeBuild = $true; oldTargetFallback = $false }
    if ($PlanOnly) {
        $runStatus = 'plan-only'
        $trace = Save-TraceArchive $archiveRoot $hookPath $overrideConfigPath $originalHookPath $buildScriptPath $sourceBefore $runId $runStatus $Version $targetRoot
        $traceArchived = $true
        $plan.traceRunId = $runId
        $plan.traceArchive = $archiveRoot
        $plan.trace = $trace
        $plan | ConvertTo-Json -Depth 16
        return
    }

    Push-Location $repoRoot
    $locationPushed = $true
    $runStatus = 'building'
    $env:CARGO_TARGET_DIR = $targetRoot
    & pnpm tauri build --config $overrideConfigPath
    if ($LASTEXITCODE -ne 0) { throw "候选构建失败：pnpm tauri build 退出码 $LASTEXITCODE。" }
    Assert-File $mainOutput 'main executable'
    Assert-File $helperOutput 'cleanup helper'
    Assert-File $nsisOutput 'generated NSIS script'
    Assert-File $setupBuildOutput 'single EXE setup package generated by Tauri'
    if ($setupOutput -ne $setupBuildOutput) {
        Copy-Item -LiteralPath $setupBuildOutput -Destination $setupOutput -Force
    }
    Assert-File $setupOutput 'single EXE setup package'
    Assert-File $gadgetSource 'frida gadget source'
    Assert-File $licenseSource 'frida license source'
    $nsisText = Get-Content -LiteralPath $nsisOutput -Raw -Encoding UTF8
    $nsisNormalized = $nsisText.Replace('\', '/')
    $helperNormalized = $helperOutput.Replace('\', '/')
    $oldHelperNormalized = (Join-Path $repoRoot 'target\release\micontrol-service-cleanup.exe').Replace('\', '/')
    if ($nsisNormalized -notmatch [regex]::Escape($helperNormalized)) { throw '静态 payload 预检失败：生成的 NSIS 没有绑定候选 target 下的 helper。' }
    if ($nsisNormalized -match [regex]::Escape($oldHelperNormalized)) { throw '静态 payload 预检失败：生成的 NSIS 仍绑定旧 target/release helper。' }
    if ($nsisText -notmatch 'micontrol-windows-app\.exe') { throw '静态 payload 预检失败：生成的 NSIS 未包含候选主程序。' }
    if ($nsisText -notmatch 'hid-tap[\\/]frida-gadget\.dll' -or $nsisText -notmatch 'hid-tap[\\/]frida-COPYING\.txt') { throw '静态 payload 预检失败：生成的 NSIS 未包含完整 hid-tap 资源。' }
    $appDependencyFile = Join-Path $targetRoot 'release\micontrol-windows-app.d'
    Assert-File $appDependencyFile 'app dependency file'
    $appDependencyText = Get-Content -LiteralPath $appDependencyFile -Raw -Encoding UTF8
    $fingerprintFiles = @(Get-ChildItem -LiteralPath (Join-Path $targetRoot 'release\.fingerprint') -Recurse -File -Filter 'run-build-script-build-script-build.json' -ErrorAction SilentlyContinue | Where-Object { $_.FullName -match 'micontrol-windows-app-' })
    if ($fingerprintFiles.Count -eq 0) { throw '前端资源预检失败：找不到 app build-script fingerprint，无法证明 config merge/rerun 依赖。' }
    $frontendFingerprintText = ($fingerprintFiles | Sort-Object LastWriteTime | Select-Object -Last 1 | Get-Content -Raw -Encoding UTF8)
    if ($frontendFingerprintText -notmatch [regex]::Escape($frontendDistRelative)) { throw "前端资源预检失败：build-script fingerprint 未记录 $frontendDistRelative。" }
    if ($frontendFingerprintText -match [regex]::Escape($frontendDistRoot)) { throw '前端资源预检失败：fingerprint 仍含绝对 frontendDist，拒绝继续。' }
    $generatedCodegenPath = [regex]::Match($appDependencyText, '(?m)(?:^|\s)([^\s\r\n]*\\release\\build\\micontrol-windows-app-[^\s\r\n]*\\out\\[^\s\r\n]+)').Groups[1].Value
    if ([string]::IsNullOrWhiteSpace($generatedCodegenPath) -or -not (Test-Path -LiteralPath $generatedCodegenPath -PathType Leaf)) { throw '前端资源预检失败：app .d 未绑定存在的 Tauri codegen 输出。' }
    $mainBytes = [IO.File]::ReadAllBytes($mainOutput)
    foreach ($frontendEntry in $frontendManifest) {
        $assetName = [Text.Encoding]::UTF8.GetBytes([string]$frontendEntry.path)
        if ((Find-AsciiMarker $mainBytes $assetName) -lt 0) { throw "前端资源预检失败：最终主程序缺少嵌入资源键 $($frontendEntry.path)。" }
    }
    $payloadExtractRoot = Join-Path $tempRoot 'nsis-payload'
    Invoke-NsisPayloadExtraction $nsisExtractorInfo.path $setupOutput $payloadExtractRoot @(
        'micontrol-windows-app.exe',
        'micontrol-service-cleanup.exe',
        'hid-tap/frida-gadget.dll',
        'hid-tap/frida-COPYING.txt'
    ) $tempRoot
    $payloadAudit = [ordered]@{
        extractor = $nsisExtractorInfo
        setup = Get-HashRecord $setupOutput
        main = Assert-MainPayload $mainOutput (Join-Path $payloadExtractRoot 'micontrol-windows-app.exe')
        helper = Assert-ExactPayload $helperOutput (Join-Path $payloadExtractRoot 'micontrol-service-cleanup.exe') 'cleanup helper'
        gadget = Assert-ExactPayload $gadgetSource (Join-Path $payloadExtractRoot 'hid-tap\frida-gadget.dll') 'frida gadget'
        license = Assert-ExactPayload $licenseSource (Join-Path $payloadExtractRoot 'hid-tap\frida-COPYING.txt') 'frida license'
    }
    $payloadBindings = [ordered]@{
        main = [ordered]@{ source = $mainOutput; nsisFilenamePresent = $true }
        helper = [ordered]@{ source = $helperOutput; nsisAbsoluteSourcePresent = $true }
        setup = [ordered]@{ path = $setupOutput; singleExe = $true }
        resources = @($gadgetSource, $licenseSource)
        payloadAudit = $payloadAudit
    }
    $sourceAfter = @($sourceFiles | ForEach-Object { Get-HashRecord $_ })
    for ($index = 0; $index -lt $sourceBefore.Count; $index++) { if ($sourceBefore[$index].sha256 -ne $sourceAfter[$index].sha256) { throw "源文件在构建期间发生变化：$($sourceBefore[$index].path)" } }
    $artifactFiles = @($mainOutput, $helperOutput, $setupOutput, $nsisOutput, $gadgetSource, $licenseSource)
    $artifacts = @($artifactFiles | ForEach-Object { Get-HashRecord $_ })
    $report = [ordered]@{
        status = 'static-build-passed'; version = $Version; candidateLabel = $CandidateLabel; builtAt = (Get-Date).ToString('o'); repository = $repoRoot; cargoTargetDirectory = $targetRoot; versions = $versions; sourceFileCount = $sourceBefore.Count; sourceBefore = $sourceBefore; sourceAfter = $sourceAfter; temporaryOverride = Get-HashRecord $overrideConfigPath; temporaryInstallerHook = Get-HashRecord $hookPath; traceRunId = $runId; traceArchive = $archiveRoot; setupBuildOutput = $setupBuildOutput; artifacts = $artifacts; nsisExtractor = $nsisExtractorInfo; payloadAudit = $payloadAudit
        payloadBindings = $payloadBindings
        frontendDist = [ordered]@{ mode = 'Directory'; configParent = $tauriConfigParent; configuredValue = $frontendDistRelative; resolvedPath = $resolvedFrontendDist; files = $frontendManifest; dependencyFile = Get-HashRecord $appDependencyFile; fingerprint = Get-HashRecord ($fingerprintFiles | Sort-Object LastWriteTime | Select-Object -Last 1).FullName; codegenOutput = Get-HashRecord $generatedCodegenPath }
        signed = [ordered]@{ main = (Get-AuthenticodeSignature -LiteralPath $mainOutput).Status.ToString(); helper = (Get-AuthenticodeSignature -LiteralPath $helperOutput).Status.ToString(); setup = (Get-AuthenticodeSignature -LiteralPath $setupOutput).Status.ToString() }
        acceptanceBoundary = '仅完成构建产物与静态 payload 绑定校验；未执行新机安装、UAC、SCM、真实服务或硬件验收。无代码签名证书时 Smart App Control/未知发布者拦截仍可能发生。'
    }
    New-Item -ItemType Directory -Path (Split-Path -Parent $ReportPath) -Force | Out-Null
    $runStatus = 'static-build-passed'
    Write-Utf8NoBom $ReportPath ($report | ConvertTo-Json -Depth 64)
    $reportWritten = $true
}
finally {
    if ($locationPushed) { Pop-Location }
    if ($null -eq $oldCargoTarget) { Remove-Item Env:CARGO_TARGET_DIR -ErrorAction SilentlyContinue } else { $env:CARGO_TARGET_DIR = $oldCargoTarget }
    if ($temporaryCreated -and (Test-Path -LiteralPath $tempRoot) -and -not $traceArchived) {
        try {
            $trace = Save-TraceArchive $archiveRoot $hookPath $overrideConfigPath $originalHookPath $buildScriptPath $sourceBefore $runId $runStatus $Version $targetRoot
            $traceArchived = $true
            if ($reportWritten -and (Test-Path -LiteralPath $ReportPath -PathType Leaf)) {
                $reportObject = Get-Content -LiteralPath $ReportPath -Raw -Encoding UTF8 | ConvertFrom-Json
                if ([string]$reportObject.traceRunId -eq $runId) {
                    $reportObject | Add-Member -NotePropertyName traceArchive -NotePropertyValue $archiveRoot -Force
                    $reportObject | Add-Member -NotePropertyName trace -NotePropertyValue $trace -Force
                    Write-Utf8NoBom $ReportPath ($reportObject | ConvertTo-Json -Depth 64)
                }
            }
        } catch {
            Write-Warning "候选构建 trace archive 写入失败：$($_.Exception.Message)"
        }
    }
    if ($temporaryCreated -and -not $KeepTemporary -and (Test-Path -LiteralPath $tempRoot)) { Remove-Item -LiteralPath $tempRoot -Recurse -Force }
}
