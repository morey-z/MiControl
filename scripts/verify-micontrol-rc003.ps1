[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$ServiceName,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$InstallRoot,

    [switch]$StartIfStopped,
    [switch]$StopAfter,
    [switch]$CheckAcl,
    [switch]$AllowProductionService
)

$ErrorActionPreference = 'Stop'
$productionServiceName = 'MiControlRC003HidTap'
if ($ServiceName -eq $productionServiceName -and -not $AllowProductionService) {
    throw '生产服务验收必须显式指定 -AllowProductionService；新机验证请先确认目标主机。'
}

$scPath = Join-Path $env:WINDIR 'System32\sc.exe'
if (-not (Test-Path -LiteralPath $scPath -PathType Leaf)) {
    throw "找不到 SCM 工具：$scPath"
}

function Invoke-Sc {
    param([Parameter(Mandatory = $true)][string[]]$Arguments)
    $output = @(& $scPath @Arguments 2>&1 | ForEach-Object { $_.ToString() })
    [pscustomobject]@{
        ExitCode = $LASTEXITCODE
        Text = ($output -join "`n")
    }
}

function Get-ScState {
    $result = Invoke-Sc @('query', $ServiceName)
    if ($result.ExitCode -ne 0) {
        throw "sc query 失败（$($result.ExitCode)）：$($result.Text)"
    }
    $match = [regex]::Match($result.Text, '(?m)STATE\s*:\s*(\d+)')
    if (-not $match.Success) {
        throw "无法从 sc query 解析服务状态：$($result.Text)"
    }
    switch ([int]$match.Groups[1].Value) {
        1 { 'STOPPED'; break }
        2 { 'START_PENDING'; break }
        3 { 'STOP_PENDING'; break }
        4 { 'RUNNING'; break }
        5 { 'CONTINUE_PENDING'; break }
        6 { 'PAUSE_PENDING'; break }
        7 { 'PAUSED'; break }
        default { "UNKNOWN_$($match.Groups[1].Value)" }
    }
}

function Wait-ScState {
    param(
        [Parameter(Mandatory = $true)][string]$Expected,
        [int]$TimeoutSeconds = 20
    )
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        $state = Get-ScState
        if ($state -eq $Expected) { return $state }
        Start-Sleep -Milliseconds 250
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "等待服务状态 $Expected 超时，当前为 $(Get-ScState)"
}

function Get-RuleSid {
    param([Parameter(Mandatory = $true)]$Rule)
    try {
        return $Rule.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value
    } catch {
        return $Rule.IdentityReference.Value
    }
}

function Read-BrokerConfig {
    $deadline = [DateTime]::UtcNow.AddSeconds(5)
    do {
        try {
            $candidate = Get-Content -LiteralPath $brokerPath -Raw | ConvertFrom-Json
            if ([int]$candidate.protocol -ne 4) { throw "broker protocol 不是 4：$($candidate.protocol)" }
            if ([int]$candidate.port -lt 1 -or [int]$candidate.port -gt 65535) { throw 'broker 端口无效' }
            if ($candidate.secret -notmatch '^[0-9a-fA-F]{64}$') { throw 'broker secret 格式无效' }
            if ($candidate.owner_sid -notmatch '^S-1-[0-9-]+$') { throw 'broker owner_sid 格式无效' }
            return $candidate
        } catch {
            if ([DateTime]::UtcNow -ge $deadline) {
                throw "读取 broker.json 失败：$($_.Exception.Message)"
            }
            Start-Sleep -Milliseconds 250
        }
    } while ($true)
}

$root = (Resolve-Path -LiteralPath $InstallRoot).Path
$binary = Join-Path $root 'MiControlHidService.exe'
$brokerPath = Join-Path $root 'broker.json'
foreach ($required in @($binary, $brokerPath)) {
    if (-not (Test-Path -LiteralPath $required -PathType Leaf)) {
        throw "缺少候选服务文件：$required"
    }
}

$service = Get-CimInstance Win32_Service -Filter "Name='$ServiceName'"
if ($null -eq $service) {
    throw "SCM 中不存在服务：$ServiceName"
}
if ($service.PathName -notmatch [regex]::Escape($binary)) {
    throw "服务 ImagePath 未指向验收目录：$($service.PathName)"
}

$broker = Read-BrokerConfig

$initialState = Get-ScState
if ($StartIfStopped -and $initialState -eq 'STOPPED') {
    $start = Invoke-Sc @('start', $ServiceName)
    if ($start.ExitCode -ne 0) {
        throw "普通 owner 启动服务失败（$($start.ExitCode)）：$($start.Text)"
    }
    [void](Wait-ScState -Expected 'RUNNING')
    # service_main 选择随机新端口并原子重写 broker.json；RUNNING 后必须重读。
    $broker = Read-BrokerConfig
}

$state = Get-ScState
$health = $false
$healthResponse = $null
if ($state -eq 'RUNNING') {
    $client = [System.Net.Sockets.TcpClient]::new()
    try {
        $client.ReceiveTimeout = 3000
        $client.SendTimeout = 3000
        $client.Connect('127.0.0.1', [int]$broker.port)
        $stream = $client.GetStream()
        $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
        $writer = [System.IO.StreamWriter]::new($stream, $utf8NoBom, 1024, $true)
        $writer.NewLine = "`n"
        $writer.AutoFlush = $true
        $writer.WriteLine((@{ kind = 'health'; secret = [string]$broker.secret } | ConvertTo-Json -Compress))
        $reader = [System.IO.StreamReader]::new($stream, $utf8NoBom, $false, 1024, $true)
        $line = $reader.ReadLine()
        if ($line) {
            $healthResponse = $line | ConvertFrom-Json
            $health = ($healthResponse.ok -eq $true -and [int]$healthResponse.protocol -eq 4)
        }
    } finally {
        if ($null -ne $client) { $client.Dispose() }
    }
}
if (-not $health) {
    throw "broker protocol4 health 失败；SCM=$state"
}

$runtimeChecked = $false
if ($CheckAcl) {
    $serviceAcl = Invoke-Sc @('sdshow', $ServiceName)
    if ($serviceAcl.ExitCode -ne 0) { throw "sc sdshow 失败：$($serviceAcl.Text)；请在管理员 PowerShell 中重试 -CheckAcl" }
    $ownerAce = [regex]::Escape("(A;;LCRP;;;$($broker.owner_sid))")
    if ($serviceAcl.Text -notmatch $ownerAce) {
        throw "服务 DACL 缺少 owner 的 LCRP（查询/启动）ACE：$($broker.owner_sid)"
    }

    $acl = Get-Acl -LiteralPath $root
    $rules = @($acl.Access)
    function Rules-ForSid([string]$sid) {
        @($rules | Where-Object { (Get-RuleSid $_) -eq $sid })
    }
    $ownerRules = Rules-ForSid $broker.owner_sid
    if ($ownerRules.Count -eq 0) { throw "服务目录缺少 owner ACL：$($broker.owner_sid)" }
    if ($ownerRules | Where-Object { $_.FileSystemRights.ToString() -match 'Write|Modify|FullControl|Delete' }) {
        throw '服务目录 owner ACL 含写入/修改/删除权限'
    }
    foreach ($sid in @('S-1-5-18', 'S-1-5-32-544')) {
        if (-not (Rules-ForSid $sid | Where-Object { $_.FileSystemRights.ToString() -match 'FullControl' })) {
            throw "服务目录缺少 SYSTEM/Administrators FullControl：$sid"
        }
    }
    $runtime = Join-Path $root 'runtime'
    if (Test-Path -LiteralPath $runtime -PathType Container) {
        $runtimeAcl = Get-Acl -LiteralPath $runtime
        $runtimeRules = @($runtimeAcl.Access)
        if ($runtimeRules | Where-Object {
                (Get-RuleSid $_) -eq $broker.owner_sid -and
                $_.FileSystemRights.ToString() -match 'Write|Modify|FullControl|Delete'
            }) {
            throw 'runtime 目录 owner ACL 含写入/修改/删除权限'
        }
        $runtimeChecked = $true
    }
}

if ($StopAfter) {
    $stop = Invoke-Sc @('stop', $ServiceName)
    if ($stop.ExitCode -ne 0) { throw "停止服务失败（$($stop.ExitCode)）：$($stop.Text)" }
    [void](Wait-ScState -Expected 'STOPPED')
    $state = 'STOPPED'
}

[pscustomobject]@{
    result = 'PASS'
    service = $ServiceName
    installRoot = $root
    initialState = $initialState
    finalState = $state
    protocol = [int]$broker.protocol
    brokerHealth = $health
    ownerSid = [string]$broker.owner_sid
    serviceOwnerAce = 'LCRP'
    aclChecked = [bool]$CheckAcl
    runtimeAclChecked = $runtimeChecked
    stoppedAfter = [bool]$StopAfter
} | ConvertTo-Json -Depth 4
