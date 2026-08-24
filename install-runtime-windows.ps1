# Rikune — Windows Runtime Install Script
# Installs and starts the Windows Host Agent + Runtime Node for sandbox-based PE analysis.
# Requires: PowerShell 7+, Windows 10/11 Pro or Enterprise, Windows Sandbox feature enabled
# Encoding: UTF-8 without BOM

param(
    [Parameter(HelpMessage="Run Host Agent in headless mode (no interactive prompts)")]
    [switch]$Headless,

    [Parameter(HelpMessage="Run Host Agent under PM2 in the current logged-on user session. Windows Service mode is not supported for Windows Sandbox launch.")]
    [switch]$Service,

    [Parameter(HelpMessage="Skip npm build step")]
    [switch]$SkipBuild,

    [Parameter(HelpMessage="Workspace root for sandbox temp dirs, inbox/outbox")]
    [string]$WorkspaceRoot,

    [Parameter(HelpMessage="Host Agent HTTP port")]
    [int]$Port = 18082,

    [Parameter(HelpMessage="Host Agent bind address. Non-loopback binding is an explicit network exposure decision.")]
    [string]$BindHost = "127.0.0.1",

    [Parameter(HelpMessage="Runtime portproxy bind address. Defaults to loopback when Host Agent is loopback.")]
    [string]$RuntimeBindHost,

    [Parameter(HelpMessage="Hostname advertised to Runtime clients. Local Docker installs use host.docker.internal while listeners stay on loopback.")]
    [string]$RuntimeAdvertisedHost,

    [Parameter(HelpMessage="Skip best-effort Hyper-V firewall rules that allow WSL/Docker analyzers to reach Host Agent/runtime ports.")]
    [switch]$SkipHyperVFirewallRules,

    [Parameter(HelpMessage="Read an optional Host Agent key from standard input so remote bootstrap does not expose it in process arguments.")]
    [switch]$ReadApiKeyFromStdin,

    [Parameter(HelpMessage="Allow plaintext HTTP/non-loopback runtime exposure only on an isolated trusted network.")]
    [switch]$AllowInsecureRuntimeHttp,

    [Parameter(HelpMessage="Runtime backend controlled by the Host Agent")]
    [ValidateSet("windows-sandbox", "hyperv-vm")]
    [string]$RuntimeBackend = "windows-sandbox",

    [Parameter(HelpMessage="Hyper-V VM name for the hyperv-vm runtime backend")]
    [string]$HyperVVmName,

    [Parameter(HelpMessage="Hyper-V checkpoint/snapshot name to restore before each runtime session")]
    [string]$HyperVSnapshotName,

    [Parameter(HelpMessage="Runtime Node endpoint inside the Hyper-V VM, for example http://192.168.1.50:18081")]
    [string]$HyperVRuntimeEndpoint,

    [Parameter(HelpMessage="Restore the configured Hyper-V checkpoint when the runtime session is released")]
    [switch]$HyperVRestoreOnRelease,

    [Parameter(HelpMessage="Stop the Hyper-V VM when the runtime session is released")]
    [switch]$HyperVStopOnRelease,

    [Parameter(HelpMessage="Project root directory")]
    [string]$ProjectRoot = $PSScriptRoot
)

$ErrorActionPreference = "Stop"

$ColorPrimary = "Cyan"
$ColorSuccess = "Green"
$ColorWarning = "Yellow"
$ColorError = "Red"
$ColorInfo = "White"

function Write-Header {
    param([string]$Text)
    Write-Host "`n==================================================" -ForegroundColor $ColorPrimary
    Write-Host "  $Text" -ForegroundColor $ColorPrimary
    Write-Host "==================================================" -ForegroundColor $ColorPrimary
    Write-Host "`n" -NoNewline
}

function Write-Success {
    param([string]$Text)
    Write-Host "[OK] " -ForegroundColor $ColorSuccess -NoNewline
    Write-Host $Text -ForegroundColor $ColorSuccess
}

function Write-Error-Message {
    param([string]$Text)
    Write-Host "[ERROR] " -ForegroundColor $ColorError -NoNewline
    Write-Host $Text -ForegroundColor $ColorError
}

function Write-Warning-Message {
    param([string]$Text)
    Write-Host "[WARN] " -ForegroundColor $ColorWarning -NoNewline
    Write-Host $Text -ForegroundColor $ColorWarning
}

function Write-Info {
    param([string]$Text)
    Write-Host "  $Text" -ForegroundColor $ColorInfo
}

function Write-Step {
    param([string]$Text)
    Write-Host "`n[STEP] $Text" -ForegroundColor $ColorPrimary
    Write-Host "-----------------------------------------" -ForegroundColor $ColorPrimary
}

function Exit-WithError {
    param([string]$Text)
    Write-Error-Message $Text
    exit 1
}

function Get-ProcessEnvironmentEntrySnapshot {
    param([string]$Name)

    $entry = Get-Item -LiteralPath "Env:$Name" -ErrorAction SilentlyContinue
    return [pscustomobject]@{
        Exists = $null -ne $entry
        Value = if ($null -eq $entry) { $null } else { [string]$entry.Value }
    }
}

function Restore-ProcessEnvironmentEntry {
    param(
        [string]$Name,
        [object]$Snapshot
    )

    if ($Snapshot.Exists) {
        [Environment]::SetEnvironmentVariable($Name, [string]$Snapshot.Value, "Process")
    } else {
        Remove-Item -LiteralPath "Env:$Name" -ErrorAction SilentlyContinue
    }
}

function Assert-SafeRuntimeEnvValue {
    param(
        [string]$Name,
        [AllowNull()][string]$Value,
        [switch]$AllowEmpty
    )

    $normalized = if ($null -eq $Value) { "" } else { [string]$Value }
    if ($normalized.Contains("`r") -or $normalized.Contains("`n") -or $normalized.Contains([char]0)) {
        throw "$Name must not contain CR, LF, or NUL characters"
    }
    if (-not $AllowEmpty -and [string]::IsNullOrWhiteSpace($normalized)) {
        throw "$Name is required"
    }
    return $normalized
}

function New-CryptographicApiKey {
    $bytes = [System.Security.Cryptography.RandomNumberGenerator]::GetBytes(32)
    return [Convert]::ToHexString($bytes).ToLowerInvariant()
}

function Resolve-RuntimeApiKey {
    param(
        [string]$Name,
        [AllowNull()][string]$EnvironmentKey
    )

    if ([string]::IsNullOrWhiteSpace($EnvironmentKey)) { return New-CryptographicApiKey }
    $candidate = Assert-SafeRuntimeEnvValue -Name $Name -Value $EnvironmentKey
    $candidate = $candidate.Trim()
    if ($candidate -notmatch '^[\x21-\x7e]{32,}$') {
        throw "$Name must contain at least 32 printable non-space ASCII characters"
    }
    return $candidate
}

function Get-SecretFingerprint {
    param([string]$Secret)

    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($Secret)
        $digest = $sha.ComputeHash($bytes)
        return [Convert]::ToHexString($digest).ToLowerInvariant().Substring(0, 12)
    } finally {
        $sha.Dispose()
    }
}

function Assert-SecureRuntimeEndpoint {
    param(
        [string]$Endpoint,
        [switch]$AllowInsecure
    )

    $uri = $null
    if (-not [Uri]::TryCreate($Endpoint, [UriKind]::Absolute, [ref]$uri)) {
        throw "Invalid runtime endpoint: $Endpoint"
    }
    if (-not [string]::IsNullOrEmpty($uri.UserInfo)) {
        throw "Runtime endpoints must not contain URL userinfo credentials"
    }
    if ($uri.Scheme -eq "https") { return }
    if ($uri.Scheme -eq "http" -and $uri.Host -in @("localhost", "127.0.0.1", "::1")) { return }
    if ($uri.Scheme -eq "http" -and $AllowInsecure) {
        Write-Warning-Message "Using plaintext remote runtime HTTP by explicit opt-in. Restrict it to a trusted VPN/isolated network."
        return
    }
    throw "Remote Runtime Node endpoints must use HTTPS. Use -AllowInsecureRuntimeHttp only for an isolated trusted network."
}

function Test-IsLoopbackRuntimeHost {
    param([string]$HostName)
    return $HostName.Trim().ToLowerInvariant() -in @("127.0.0.1", "localhost", "::1", "[::1]")
}

function Assert-RuntimeNetworkExposureContract {
    param(
        [string]$HostAgentBindHost,
        [string]$RuntimeProxyBindHost,
        [switch]$AllowInsecureRuntimeHttp
    )

    if ((-not (Test-IsLoopbackRuntimeHost -HostName $HostAgentBindHost) -or
        -not (Test-IsLoopbackRuntimeHost -HostName $RuntimeProxyBindHost)) -and
        -not $AllowInsecureRuntimeHttp) {
        throw "Non-loopback Host Agent or Runtime portproxy binding requires the explicit -AllowInsecureRuntimeHttp trusted-network opt-in."
    }
}

function Resolve-RuntimeWorkspaceRoot {
    param(
        [AllowNull()][string]$RequestedRoot,
        [string]$ProjectRoot,
        [string]$LocalAppData
    )

    if ([string]::IsNullOrWhiteSpace($RequestedRoot)) {
        if ([string]::IsNullOrWhiteSpace($LocalAppData)) {
            throw "LOCALAPPDATA is required when WorkspaceRoot is omitted"
        }
        $resolvedCandidate = Join-Path $LocalAppData "Rikune\Runtime"
    } elseif ([System.IO.Path]::IsPathRooted($RequestedRoot)) {
        $resolvedCandidate = [System.IO.Path]::GetFullPath($RequestedRoot)
    } else {
        $resolvedCandidate = [System.IO.Path]::GetFullPath((Join-Path $ProjectRoot $RequestedRoot))
    }
    [System.IO.Directory]::CreateDirectory($resolvedCandidate) | Out-Null
    return (Resolve-Path -LiteralPath $resolvedCandidate).Path
}

function Assert-RegularNonReparseRuntimeEnvPath {
    param([string]$Path)

    $attributes = [System.IO.File]::GetAttributes($Path)
    if (($attributes -band [System.IO.FileAttributes]::Directory) -ne 0) {
        throw "Runtime environment path must be a regular file: $Path"
    }
    if (($attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Runtime environment path must not be a symlink or reparse point: $Path"
    }
}

function Assert-ProtectedRuntimeEnvFile {
    param([string]$Path)

    Assert-RegularNonReparseRuntimeEnvPath -Path $Path
    $fileInfo = [System.IO.FileInfo]::new($Path)
    if ($fileInfo.Length -gt 65536) {
        throw "Runtime environment file exceeds the 64 KiB security limit"
    }

    $acl = Get-Acl -LiteralPath $Path
    if (-not $acl.AreAccessRulesProtected) {
        throw "Runtime environment file ACL inheritance must be disabled"
    }

    $currentSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $ownerSid = $acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value
    if ($ownerSid -ne $currentSid) {
        throw "Runtime environment file must be owned by the current Windows user"
    }

    $rules = @($acl.GetAccessRules(
        $true,
        $true,
        [System.Security.Principal.SecurityIdentifier]
    ))
    if ($rules.Count -ne 1) {
        throw "Runtime environment file must have exactly one ACL entry"
    }
    $rule = $rules[0]
    if ($rule.IsInherited -or
        $rule.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow -or
        $rule.IdentityReference.Value -ne $currentSid -or
        $rule.FileSystemRights -ne [System.Security.AccessControl.FileSystemRights]::FullControl -or
        $rule.InheritanceFlags -ne [System.Security.AccessControl.InheritanceFlags]::None -or
        $rule.PropagationFlags -ne [System.Security.AccessControl.PropagationFlags]::None) {
        throw "Runtime environment file ACL must grant only the current Windows user FullControl"
    }
}

function New-ExactAclRuntimeEnvStream {
    param([string]$Path)

    $currentSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
    if ($null -eq $currentSid) {
        throw "Unable to resolve the current Windows user SID"
    }

    $security = [System.Security.AccessControl.FileSecurity]::new()
    $security.SetOwner($currentSid)
    $security.SetAccessRuleProtection($true, $false)
    $rule = [System.Security.AccessControl.FileSystemAccessRule]::new(
        $currentSid,
        [System.Security.AccessControl.FileSystemRights]::FullControl,
        [System.Security.AccessControl.InheritanceFlags]::None,
        [System.Security.AccessControl.PropagationFlags]::None,
        [System.Security.AccessControl.AccessControlType]::Allow
    )
    $security.SetAccessRule($rule)

    return [System.IO.FileSystemAclExtensions]::Create(
        [System.IO.FileInfo]::new($Path),
        [System.IO.FileMode]::CreateNew,
        [System.Security.AccessControl.FileSystemRights]::FullControl,
        [System.IO.FileShare]::None,
        4096,
        [System.IO.FileOptions]::WriteThrough,
        $security
    )
}

function Write-SecureRuntimeEnvFile {
    param(
        [string]$Path,
        [string]$Content,
        [scriptblock]$SecureFileCreator,
        [switch]$RequireAbsent
    )

    $absolutePath = [System.IO.Path]::GetFullPath($Path)
    $parent = Split-Path -Parent $absolutePath
    [System.IO.Directory]::CreateDirectory($parent) | Out-Null
    if ($RequireAbsent -and (Test-Path -LiteralPath $absolutePath)) {
        throw "Runtime environment transaction target appeared before the final writer: $absolutePath"
    }
    if (Test-Path -LiteralPath $absolutePath) {
        Assert-RegularNonReparseRuntimeEnvPath -Path $absolutePath
    }

    $temporaryPath = Join-Path $parent ".$([System.IO.Path]::GetFileName($absolutePath)).$PID.$([Guid]::NewGuid().ToString('N')).tmp"
    $destinationReplaced = $false
    $stream = $null
    try {
        if ($null -eq $SecureFileCreator) {
            $SecureFileCreator = {
                param([string]$TargetPath)
                New-ExactAclRuntimeEnvStream -Path $TargetPath
            }
        }

        $stream = & $SecureFileCreator $temporaryPath
        if ($stream -isnot [System.IO.FileStream] -or -not $stream.CanWrite) {
            throw "Secure runtime environment creator must return a writable FileStream"
        }
        Assert-ProtectedRuntimeEnvFile -Path $temporaryPath

        $contentBytes = [System.Text.UTF8Encoding]::new($false).GetBytes($Content)
        $stream.Write($contentBytes, 0, $contentBytes.Length)
        $stream.Flush($true)
        $stream.Dispose()
        $stream = $null

        if ($RequireAbsent) {
            [System.IO.File]::Move($temporaryPath, $absolutePath, $false)
        } else {
            [System.IO.File]::Move($temporaryPath, $absolutePath, $true)
        }
        $destinationReplaced = $true
        Assert-ProtectedRuntimeEnvFile -Path $absolutePath
        if ([System.IO.File]::ReadAllText($absolutePath) -cne $Content) {
            throw "Runtime environment file content changed during secure replacement"
        }
    } catch {
        if ($destinationReplaced -and (Test-Path -LiteralPath $absolutePath)) {
            Remove-Item -LiteralPath $absolutePath -Force -ErrorAction SilentlyContinue
        }
        throw
    } finally {
        if ($null -ne $stream) {
            $stream.Dispose()
        }
        if (Test-Path -LiteralPath $temporaryPath) {
            Remove-Item -LiteralPath $temporaryPath -Force
        }
    }
}

function New-NativeInstallerFailure {
    param([string]$Message, [int]$ExitCode)

    $failure = [System.InvalidOperationException]::new($Message)
    $failure.Data["RIKUNE_NATIVE_EXIT_CODE"] = $ExitCode
    return $failure
}

function Get-RuntimePrivateEnvSnapshot {
    param(
        [string]$Path,
        [string]$NodePath,
        [string]$WriterPath
    )

    $previousEntry = Get-ProcessEnvironmentEntrySnapshot -Name "RIKUNE_STAGE_DOCKER_ENV_PATH"
    try {
        [Environment]::SetEnvironmentVariable("RIKUNE_STAGE_DOCKER_ENV_PATH", $Path, "Process")
        $snapshotOutput = & $NodePath $WriterPath 2>$null
        $nativeExitCode = $LASTEXITCODE
        if ($nativeExitCode -ne 0) {
            throw (New-NativeInstallerFailure `
                -Message "Secure Windows runtime env staging failed" `
                -ExitCode $nativeExitCode)
        }
        $snapshot = [string](@($snapshotOutput) -join '')
        if ([string]::IsNullOrWhiteSpace($snapshot)) {
            throw "Secure Windows runtime env staging returned an empty snapshot"
        }
        return $snapshot
    } finally {
        Restore-ProcessEnvironmentEntry -Name "RIKUNE_STAGE_DOCKER_ENV_PATH" -Snapshot $previousEntry
    }
}

function Invoke-RuntimePrivateEnvSnapshotOperation {
    param(
        [string]$EnvironmentName,
        [string]$Path,
        [string]$Snapshot,
        [string]$NodePath,
        [string]$WriterPath,
        [string]$FailureMessage
    )

    $previousEntry = Get-ProcessEnvironmentEntrySnapshot -Name $EnvironmentName
    try {
        [Environment]::SetEnvironmentVariable($EnvironmentName, $Path, "Process")
        $operationOutput = $Snapshot | & $NodePath $WriterPath 2>$null
        $nativeExitCode = $LASTEXITCODE
        if ($nativeExitCode -ne 0) {
            throw (New-NativeInstallerFailure -Message $FailureMessage -ExitCode $nativeExitCode)
        }
        if (@($operationOutput).Count -ne 0) {
            throw "Secure Windows runtime env snapshot operation produced unexpected output"
        }
    } finally {
        Restore-ProcessEnvironmentEntry -Name $EnvironmentName -Snapshot $previousEntry
    }
}

function Remove-RuntimePrivateEnvForSnapshot {
    param(
        [string]$Path,
        [string]$Snapshot,
        [string]$NodePath,
        [string]$WriterPath
    )

    Invoke-RuntimePrivateEnvSnapshotOperation `
        -EnvironmentName "RIKUNE_REMOVE_PRIVATE_ENV_SNAPSHOT_PATH" `
        -Path $Path `
        -Snapshot $Snapshot `
        -NodePath $NodePath `
        -WriterPath $WriterPath `
        -FailureMessage "Secure removal of the staged Windows runtime env failed"
}

function Restore-RuntimePrivateEnvSnapshot {
    param(
        [string]$Path,
        [string]$Snapshot,
        [string]$NodePath,
        [string]$WriterPath
    )

    Invoke-RuntimePrivateEnvSnapshotOperation `
        -EnvironmentName "RIKUNE_RESTORE_PRIVATE_ENV_PATH" `
        -Path $Path `
        -Snapshot $Snapshot `
        -NodePath $NodePath `
        -WriterPath $WriterPath `
        -FailureMessage "Secure restoration of the Windows runtime env failed"
}

function Resolve-PinnedPm2Command {
    param([string]$ProjectRoot)

    $manifest = Get-Content -LiteralPath (Join-Path $ProjectRoot "package.json") -Raw | ConvertFrom-Json
    $expectedVersion = [string]$manifest.devDependencies.pm2
    if ($expectedVersion -notmatch '^\d+\.\d+\.\d+$') {
        throw "package.json must pin devDependencies.pm2 to an exact version"
    }
    $command = Join-Path $ProjectRoot "node_modules\.bin\pm2.cmd"
    if (-not (Test-Path -LiteralPath $command)) {
        throw "Pinned PM2 executable is missing. Run npm ci --include=dev in the project root."
    }
    $installedManifestPath = Join-Path $ProjectRoot "node_modules\pm2\package.json"
    if (-not (Test-Path -LiteralPath $installedManifestPath)) {
        throw "Pinned PM2 package manifest is missing. Run npm ci --include=dev in the project root."
    }
    $installedManifest = Get-Content -LiteralPath $installedManifestPath -Raw | ConvertFrom-Json
    $actualVersion = [string]$installedManifest.version
    if ([string]$installedManifest.name -ne "pm2" -or $actualVersion -ne $expectedVersion) {
        throw "PM2 version mismatch: expected $expectedVersion, received $actualVersion"
    }
    return @{ Command = $command; Version = $expectedVersion }
}

function Test-IsAdmin {
    return ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
}

function Ensure-HyperVFirewallRule {
    param(
        [string]$Name,
        [string]$DisplayName,
        [string]$RemotePorts
    )

    if (-not (Get-Command New-NetFirewallHyperVRule -ErrorAction SilentlyContinue)) {
        Write-Warning-Message "Hyper-V firewall cmdlets are not available; skipping rule $Name"
        return
    }

    $vmCreatorId = "{40E0AC32-46A5-438A-A0B2-2B479E8F2E90}" # WSL/Docker Desktop VM creator id on Windows 11 Hyper-V firewall.
    try {
        Get-NetFirewallHyperVRule -Name $Name -ErrorAction SilentlyContinue | Remove-NetFirewallHyperVRule -ErrorAction SilentlyContinue
        New-NetFirewallHyperVRule `
            -Name $Name `
            -DisplayName $DisplayName `
            -Direction Outbound `
            -VMCreatorId $vmCreatorId `
            -Protocol TCP `
            -RemotePorts $RemotePorts `
            -Action Allow `
            -Enabled True | Out-Null
        Write-Success "Hyper-V firewall rule ensured: $DisplayName ($RemotePorts)"
    } catch {
        Write-Warning-Message "Could not create Hyper-V firewall rule $Name. Run this installer as Administrator or allow TCP $RemotePorts from WSL/Docker manually. $($_.Exception.Message)"
    }
}

function Get-OptionalFeatureByName {
    param([string[]]$Names)

    foreach ($name in $Names) {
        try {
            $feature = Get-WindowsOptionalFeature -Online -FeatureName $name -ErrorAction Stop
            if ($feature) { return $feature }
        } catch {
            Write-Info "Optional feature not available by name '$name'"
        }
    }

    return $null
}

function Invoke-Request {
    param(
        [string]$Uri,
        [string]$Method = "GET",
        [hashtable]$Headers = @{},
        [string]$Body = $null,
        [int]$TimeoutSec = 10
    )
    try {
        $params = @{
            Uri = $Uri
            Method = $Method
            TimeoutSec = $TimeoutSec
            UseBasicParsing = $true
            ErrorAction = "Stop"
        }
        if ($Headers.Count -gt 0) { $params.Headers = $Headers }
        if ($Body) { $params.Body = $Body }
        $response = Invoke-WebRequest @params
        return ($response.Content | ConvertFrom-Json)
    } catch {
        return @{ ok = $false; error = $_.Exception.Message }
    }
}

function Assert-LoopbackHostAgentListener {
    param(
        [int]$Port,
        [string]$ExpectedNodePath
    )

    if (-not (Get-Command Get-NetTCPConnection -ErrorAction SilentlyContinue)) {
        throw "Get-NetTCPConnection is required to verify the Host Agent loopback listener"
    }
    $listeners = @(Get-NetTCPConnection -State Listen -LocalPort $Port -ErrorAction Stop)
    if ($listeners.Count -eq 0) {
        throw "No Host Agent listener was found on port $Port"
    }
    foreach ($listener in $listeners) {
        if ([string]$listener.LocalAddress -notin @("127.0.0.1", "::1")) {
            throw "Host Agent listener escaped loopback on address '$($listener.LocalAddress)'"
        }
        $listenerProcess = Get-Process -Id $listener.OwningProcess -ErrorAction Stop
        if (-not [string]::Equals(
            [System.IO.Path]::GetFullPath($listenerProcess.Path),
            [System.IO.Path]::GetFullPath($ExpectedNodePath),
            [System.StringComparison]::OrdinalIgnoreCase
        )) {
            throw "Port $Port is not owned by the expected Node.js executable"
        }
    }
}

function Start-HostAgentProcess {
    param(
        [string]$NodeExecutable,
        [string]$EntryPath,
        [string]$WorkingDirectory,
        [string]$WorkspaceRoot
    )

    $logDir = Join-Path $WorkspaceRoot "workspace\logs"
    if (-not (Test-Path $logDir)) {
        New-Item -ItemType Directory -Path $logDir -Force | Out-Null
    }

    $stdoutLog = Join-Path $logDir "host-agent.log"
    $stderrLog = Join-Path $logDir "host-agent.error.log"
    New-Item -ItemType File -Path $stdoutLog -Force | Out-Null
    New-Item -ItemType File -Path $stderrLog -Force | Out-Null

    try {
        $proc = Start-Process `
            -FilePath $NodeExecutable `
            -ArgumentList @($EntryPath) `
            -WorkingDirectory $WorkingDirectory `
            -WindowStyle Hidden `
            -PassThru `
            -RedirectStandardOutput $stdoutLog `
            -RedirectStandardError $stderrLog `
            -ErrorAction Stop
    } catch {
        Exit-WithError "Failed to start Host Agent process: $($_.Exception.Message)"
    }

    if (-not $proc -or -not $proc.Id) {
        Exit-WithError "Host Agent process did not return a valid PID."
    }

    return @{
        Process = $proc
        StdoutLog = $stdoutLog
        StderrLog = $stderrLog
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# Main Script
# ─────────────────────────────────────────────────────────────────────────────
if (-not $Headless) { Clear-Host }
Write-Header "Rikune — Windows Runtime Install"

if ($PSVersionTable.PSVersion.Major -lt 7) {
    Exit-WithError "PowerShell 7 or newer is required for atomic protected environment-file replacement."
}
if ([string]::IsNullOrWhiteSpace($ProjectRoot)) { $ProjectRoot = $PSScriptRoot }
$ProjectRoot = [System.IO.Path]::GetFullPath($ProjectRoot)
if (-not (Test-Path -LiteralPath $ProjectRoot -PathType Container)) {
    Exit-WithError "Project root does not exist: $ProjectRoot"
}
$stdinApiKey = $null
if ($ReadApiKeyFromStdin) {
    $stdinApiKey = [Console]::In.ReadToEnd()
    if ([string]::IsNullOrWhiteSpace($stdinApiKey)) { $stdinApiKey = $null }
}

$capturedHostApiKey = if ($null -ne $stdinApiKey) {
    $stdinApiKey
} elseif (-not [string]::IsNullOrWhiteSpace($env:RIKUNE_HOST_AGENT_API_KEY)) {
    $env:RIKUNE_HOST_AGENT_API_KEY
} elseif (-not [string]::IsNullOrWhiteSpace($env:RUNTIME_HOST_AGENT_API_KEY)) {
    $env:RUNTIME_HOST_AGENT_API_KEY
} else {
    $env:RIKUNE_RUNTIME_API_KEY
}
$capturedRuntimeApiKey = if (-not [string]::IsNullOrWhiteSpace($env:RIKUNE_RUNTIME_NODE_API_KEY)) {
    $env:RIKUNE_RUNTIME_NODE_API_KEY
} else {
    $env:RUNTIME_API_KEY
}

$secretEnvironmentAliases = @(
    "RIKUNE_HOST_AGENT_API_KEY",
    "RIKUNE_RUNTIME_API_KEY",
    "RIKUNE_RUNTIME_NODE_API_KEY",
    "RUNTIME_HOST_AGENT_API_KEY",
    "HOST_AGENT_API_KEY",
    "HOST_AGENT_RUNTIME_API_KEY",
    "RUNTIME_API_KEY",
    "RIKUNE_API_KEY",
    "RIKUNE_ANALYZER_API_KEY"
)
$privateEnvControlNames = @(
    "RIKUNE_VERIFY_PRIVATE_ENV_PATH",
    "RIKUNE_STAGE_DOCKER_ENV_PATH",
    "RIKUNE_REMOVE_PRIVATE_ENV_SNAPSHOT_PATH",
    "RIKUNE_RESTORE_PRIVATE_ENV_PATH",
    "RIKUNE_REMOVE_PRIVATE_ENV_PATH",
    "RIKUNE_DOCKER_ENV_SNAPSHOT_STDIN",
    "RIKUNE_DOCKER_ENV_PATH",
    "RIKUNE_DOCKER_ENV_DATA_ROOT",
    "RIKUNE_DOCKER_ENV_PROFILE",
    "RIKUNE_BUILD_HTTP_PROXY",
    "RIKUNE_BUILD_HTTPS_PROXY",
    "RIKUNE_BUILD_NO_PROXY",
    "RIKUNE_ALLOW_INSECURE_RUNTIME_HTTP",
    "RIKUNE_STAGE_LOCAL_ENV_PATH",
    "RIKUNE_LOCAL_ENV_SNAPSHOT_STDIN",
    "RIKUNE_LOCAL_EXISTING_ENV_BASE64",
    "RIKUNE_LOCAL_ENV_PATH",
    "RIKUNE_LOCAL_ENV_FORCE_KEYS",
    "RIKUNE_PRIVATE_ENV_PATH",
    "RIKUNE_PRIVATE_ENV_ACL_MODE",
    "STAGED_LOCAL_ENV_BASE64"
)
foreach ($name in ($secretEnvironmentAliases + $privateEnvControlNames)) {
    Remove-Item -LiteralPath "Env:$name" -ErrorAction SilentlyContinue
}
$stdinApiKey = $null

if ([string]::IsNullOrWhiteSpace($RuntimeBindHost)) {
    $RuntimeBindHost = if (Test-IsLoopbackRuntimeHost -HostName $BindHost) { "127.0.0.1" } else { "0.0.0.0" }
}
try {
    Assert-SafeRuntimeEnvValue -Name "BindHost" -Value $BindHost | Out-Null
    Assert-SafeRuntimeEnvValue -Name "RuntimeBindHost" -Value $RuntimeBindHost | Out-Null
    Assert-SafeRuntimeEnvValue -Name "RuntimeAdvertisedHost" -Value $RuntimeAdvertisedHost -AllowEmpty | Out-Null
    Assert-RuntimeNetworkExposureContract `
        -HostAgentBindHost $BindHost `
        -RuntimeProxyBindHost $RuntimeBindHost `
        -AllowInsecureRuntimeHttp:$AllowInsecureRuntimeHttp
} catch {
    Exit-WithError $_.Exception.Message
}

Write-Host "This script will:" -ForegroundColor $ColorInfo
Write-Host "  1. Check Windows version and selected runtime backend" -ForegroundColor $ColorInfo
Write-Host "  2. Check Node.js, npm, and Python" -ForegroundColor $ColorInfo
Write-Host "  3. Build Runtime Node and Windows Host Agent" -ForegroundColor $ColorInfo
Write-Host "  4. Create workspace, inbox/outbox directories" -ForegroundColor $ColorInfo
Write-Host "  5. Generate Host Agent configuration (.env.runtime-windows)" -ForegroundColor $ColorInfo
Write-Host "  6. Start the Host Agent in the selected user-session mode" -ForegroundColor $ColorInfo
Write-Host "  7. Verify connectivity" -ForegroundColor $ColorInfo

if (-not $Headless) {
    $continue = Read-Host "`nContinue? (Y/n)"
    if ($continue -eq 'n' -or $continue -eq 'N') {
        Write-Warning-Message "Installation cancelled"
        exit 0
    }
}

# =============================================================================
# Step 1: Windows Environment Pre-check
# =============================================================================
Write-Step "Checking Windows Environment"

if ($env:OS -ne "Windows_NT") {
    Exit-WithError "This installer only supports Windows"
}

$osInfo = Get-CimInstance Win32_OperatingSystem
$osCaption = $osInfo.Caption
$osVersion = $osInfo.Version
Write-Info "Detected OS: $osCaption (Version $osVersion)"

# Reject Windows Home
if ($osCaption -match "Home") {
    Exit-WithError "Windows Sandbox is not available on Windows Home. Use Windows 10/11 Pro or Enterprise."
}

# Check Hyper-V (required for hyperv-vm, optional for Windows Sandbox)
$hypervFeature = Get-WindowsOptionalFeature -Online -FeatureName "Microsoft-Hyper-V-All" -ErrorAction SilentlyContinue
if ($hypervFeature -and $hypervFeature.State -eq "Enabled") {
    Write-Success "Hyper-V is enabled"
} else {
    if ($RuntimeBackend -eq "hyperv-vm") {
        Exit-WithError "Hyper-V is required for RuntimeBackend=hyperv-vm. Enable Hyper-V and reboot before continuing."
    }
    Write-Warning-Message "Hyper-V is not enabled. Windows Sandbox can still run on some systems without it, but performance may be reduced."
}

if ($RuntimeBackend -eq "windows-sandbox") {
    # Check Windows Sandbox feature. The documented feature name is
    # Containers-DisposableClientVM; keep the old name as a compatibility fallback.
    $sandboxFeatureCandidates = @("Containers-DisposableClientVM", "Containers-DisposableClient")
    $sandboxFeature = Get-OptionalFeatureByName -Names $sandboxFeatureCandidates
    if (-not $sandboxFeature -or $sandboxFeature.State -ne "Enabled") {
        Write-Warning-Message "Windows Sandbox feature is not enabled"
        if (-not $sandboxFeature) {
            Exit-WithError "Windows Sandbox optional feature was not found. On supported Windows Pro/Enterprise builds the DISM feature name is 'Containers-DisposableClientVM'."
        }

        if (Test-IsAdmin) {
            Write-Info "Attempting to enable Windows Sandbox feature: $($sandboxFeature.FeatureName)"
            $enableResult = Enable-WindowsOptionalFeature -Online -FeatureName $sandboxFeature.FeatureName -NoRestart -All -ErrorAction Stop
            if ($enableResult -and $enableResult.RestartNeeded -eq $true) {
                Exit-WithError "Windows Sandbox was enabled, but a system restart is required before continuing."
            }
            $sandboxFeature = Get-OptionalFeatureByName -Names $sandboxFeatureCandidates
            if (-not $sandboxFeature -or $sandboxFeature.State -ne "Enabled") {
                Exit-WithError "Failed to enable Windows Sandbox automatically. Please enable 'Windows Sandbox' manually via 'Turn Windows features on or off'."
            }
            Write-Success "Windows Sandbox enabled"
        } else {
            Exit-WithError "Windows Sandbox is not enabled. Please run as Administrator to auto-enable, or enable it manually via 'Turn Windows features on or off'."
        }
    } else {
        Write-Success "Windows Sandbox feature is enabled"
    }
} else {
    if ([string]::IsNullOrWhiteSpace($HyperVVmName)) {
        Exit-WithError "-HyperVVmName is required when -RuntimeBackend hyperv-vm is selected."
    }
    if ([string]::IsNullOrWhiteSpace($HyperVRuntimeEndpoint)) {
        Exit-WithError "-HyperVRuntimeEndpoint is required when -RuntimeBackend hyperv-vm is selected."
    }
    Assert-SecureRuntimeEndpoint -Endpoint $HyperVRuntimeEndpoint -AllowInsecure:$AllowInsecureRuntimeHttp
    if ($HyperVRestoreOnRelease -and [string]::IsNullOrWhiteSpace($HyperVSnapshotName)) {
        Exit-WithError "-HyperVSnapshotName is required when -HyperVRestoreOnRelease is selected."
    }
    Write-Success "Hyper-V backend selected: VM=$HyperVVmName endpoint=$HyperVRuntimeEndpoint"
}

$vmPlatformFeature = Get-WindowsOptionalFeature -Online -FeatureName "VirtualMachinePlatform" -ErrorAction SilentlyContinue
if ($vmPlatformFeature -and $vmPlatformFeature.State -eq "Enabled") {
    Write-Success "Virtual Machine Platform is enabled"
} else {
    Write-Warning-Message "Virtual Machine Platform is not enabled. Docker Desktop may require it depending on backend configuration."
}

if (-not $SkipHyperVFirewallRules) {
    Write-Step "Configuring WSL/Docker Hyper-V Firewall"
    Ensure-HyperVFirewallRule `
        -Name "Rikune-WSL-Docker-Out-HostAgent" `
        -DisplayName "Rikune WSL/Docker outbound to Windows Host Agent" `
        -RemotePorts "$Port"
    Ensure-HyperVFirewallRule `
        -Name "Rikune-WSL-Docker-Out-Runtime" `
        -DisplayName "Rikune WSL/Docker outbound to Windows Runtime portproxy" `
        -RemotePorts "18081-19000"
} else {
    Write-Info "Skipping Hyper-V firewall rules because -SkipHyperVFirewallRules was provided"
}

# =============================================================================
# Step 2: Check Required Tools
# =============================================================================
Write-Step "Checking Required Tools"

# Node.js
if (-not (Get-Command node -ErrorAction SilentlyContinue)) {
    Exit-WithError "Node.js not found. Install Node.js 22.9+ from https://nodejs.org/"
}
$nodeVersion = (node --version).Trim()
$nodeParts = ($nodeVersion -replace '^v','').Split('.')
$nodeMajor = [int]$nodeParts[0]
$nodeMinor = [int]$nodeParts[1]
if ($nodeMajor -lt 22 -or ($nodeMajor -eq 22 -and $nodeMinor -lt 9)) {
    Exit-WithError "Node.js $nodeVersion is too old (need 22.9+)"
}
Write-Success "Node.js: $nodeVersion"

# npm
if (-not (Get-Command npm -ErrorAction SilentlyContinue)) {
    Exit-WithError "npm not found"
}
Write-Success "npm: $((npm --version).Trim())"

# Python
$pythonCmd = $null
$pythonPrefixArgs = @()
$pythonCandidates = @(
    @{ Command = 'python3.12'; PrefixArgs = @() },
    @{ Command = 'py'; PrefixArgs = @('-3.12') },
    @{ Command = 'python'; PrefixArgs = @() },
    @{ Command = 'python3'; PrefixArgs = @() }
)
foreach ($candidate in $pythonCandidates) {
    $candidateCommand = [string]$candidate.Command
    $candidatePrefixArgs = @($candidate.PrefixArgs)
    if (Get-Command $candidateCommand -ErrorAction SilentlyContinue) {
        try {
            & $candidateCommand @candidatePrefixArgs -c "import struct, sys; raise SystemExit(0 if sys.implementation.name == 'cpython' and sys.version_info[:2] == (3, 12) and struct.calcsize('P') == 8 else 1)" *> $null
            if ($LASTEXITCODE -eq 0) {
                $pythonCmd = $candidateCommand
                $pythonPrefixArgs = $candidatePrefixArgs
                break
            }
        } catch {}
    }
}
if (-not $pythonCmd) {
    Exit-WithError "CPython 3.12 x86_64 is required. Install an exact 64-bit Python 3.12 release from https://www.python.org/downloads/."
}
$pyVersion = (& $pythonCmd @pythonPrefixArgs --version 2>&1).ToString().Trim()
$pythonDisplay = (($pythonCmd, ($pythonPrefixArgs -join ' ')) -join ' ').Trim()
Write-Success "Python: $pyVersion (command: $pythonDisplay)"

$nodePath = (Get-Command node).Source
try {
    $pythonPath = (& $pythonCmd @pythonPrefixArgs -c "import sys; print(sys.executable)" 2>$null).ToString().Trim()
} catch {
    Exit-WithError "Unable to resolve the exact CPython 3.12 x86_64 executable path."
}
if (-not $pythonPath -or -not (Test-Path -LiteralPath $pythonPath -PathType Leaf)) {
    Exit-WithError "Resolved CPython 3.12 executable path is invalid: $pythonPath"
}
Write-Info "Node path for Sandbox mapping: $nodePath"
Write-Info "Python path for Sandbox mapping: $pythonPath"

$envFile = Join-Path $ProjectRoot ".env.runtime-windows"
$privateEnvWriter = Join-Path $ProjectRoot "scripts\write-docker-runtime-env.mjs"
if (-not (Test-Path -LiteralPath $privateEnvWriter -PathType Leaf)) {
    Exit-WithError "Private runtime env transaction writer not found: $privateEnvWriter"
}

$privateEnvSnapshot = $null
$privateEnvTransactionActive = $false
$privateEnvTransactionCommitted = $false
$privateEnvFailure = $null
$privateEnvFailureExitCode = 1
$hostApiKey = $null
$runtimeApiKey = $null
$envContent = $null
try {
    $privateEnvSnapshot = Get-RuntimePrivateEnvSnapshot `
        -Path $envFile `
        -NodePath $nodePath `
        -WriterPath $privateEnvWriter
    $privateEnvTransactionActive = $true
    Remove-RuntimePrivateEnvForSnapshot `
        -Path $envFile `
        -Snapshot $privateEnvSnapshot `
        -NodePath $nodePath `
        -WriterPath $privateEnvWriter
    Write-Info "Any prior protected Windows runtime env was removed before npm lifecycle commands; credentials will be rotated after build."

    # =============================================================================
    # Step 3: Install npm Dependencies & Build
    # =============================================================================
    Write-Step "Installing npm Dependencies & Building"

    Push-Location $ProjectRoot
    try {
        Write-Info "Running npm ci --include=dev (root lockfile)..."
        & npm ci --include=dev 2>&1 | Out-Null
        if ($LASTEXITCODE -ne 0) {
            $nativeExitCode = $LASTEXITCODE
            throw (New-NativeInstallerFailure `
                -Message "npm ci --include=dev failed" `
                -ExitCode $nativeExitCode)
        }
        Write-Success "Root npm dependencies installed from package-lock.json"

        if (-not $SkipBuild) {
            Write-Info "Building Runtime Node..."
            & npm run build:runtime 2>&1 | Out-Null
            if ($LASTEXITCODE -ne 0) {
                $nativeExitCode = $LASTEXITCODE
                throw (New-NativeInstallerFailure `
                    -Message "Build of runtime-node failed" `
                    -ExitCode $nativeExitCode)
            }
            Write-Success "Runtime Node built"

            Write-Info "Building Windows Host Agent..."
            & npm run build:host-agent 2>&1 | Out-Null
            if ($LASTEXITCODE -ne 0) {
                $nativeExitCode = $LASTEXITCODE
                throw (New-NativeInstallerFailure `
                    -Message "Build of windows-host-agent failed" `
                    -ExitCode $nativeExitCode)
            }
            Write-Success "Windows Host Agent built"
        } else {
            Write-Warning-Message "Skipped npm build step"
        }
    } finally {
        Pop-Location
    }

    # =============================================================================
    # Step 4: Create Workspace Directories
    # =============================================================================
    Write-Step "Creating Workspace Directories"

    $WorkspaceRoot = Resolve-RuntimeWorkspaceRoot `
        -RequestedRoot $WorkspaceRoot `
        -ProjectRoot $ProjectRoot `
        -LocalAppData $env:LOCALAPPDATA

    $directories = @("workspace", "workspace\sandbox", "workspace\logs", "workspace\inbox", "workspace\outbox")
    foreach ($dir in $directories) {
        $fullPath = Join-Path $WorkspaceRoot $dir
        if (-not (Test-Path $fullPath)) {
            New-Item -ItemType Directory -Path $fullPath -Force | Out-Null
            Write-Success "Created: $fullPath"
        }
    }

    # =============================================================================
    # Step 5: Generate Host Agent Configuration
    # =============================================================================
    Write-Step "Generating Host Agent Configuration"

    $hostApiKey = Resolve-RuntimeApiKey `
        -Name "RIKUNE_HOST_AGENT_API_KEY" `
        -EnvironmentKey $capturedHostApiKey
    $runtimeApiKey = Resolve-RuntimeApiKey `
        -Name "RIKUNE_RUNTIME_NODE_API_KEY" `
        -EnvironmentKey $capturedRuntimeApiKey
    $capturedHostApiKey = $null
    $capturedRuntimeApiKey = $null
    if ([string]::Equals($hostApiKey, $runtimeApiKey, [System.StringComparison]::Ordinal)) {
        throw "Host Agent and Runtime Node API keys must be distinct security principals."
    }

    if (-not (Test-IsLoopbackRuntimeHost -HostName $BindHost) -or
        -not (Test-IsLoopbackRuntimeHost -HostName $RuntimeBindHost)) {
        Write-Warning-Message "A Host Agent or Runtime portproxy listener will bind non-loopback by explicit trusted-network opt-in. Protect this path with TLS/VPN and a restrictive firewall."
    }

    $runtimeEnvValues = @{
        HOST_AGENT_BIND_HOST = $BindHost
        HOST_AGENT_RUNTIME_BIND_HOST = $RuntimeBindHost
        HOST_AGENT_RUNTIME_ADVERTISED_HOST = $RuntimeAdvertisedHost
        HOST_AGENT_API_KEY = $hostApiKey
        HOST_AGENT_RUNTIME_API_KEY = $runtimeApiKey
        HOST_AGENT_WORKSPACE = $WorkspaceRoot
        HOST_AGENT_NODE_PATH = $nodePath
        HOST_AGENT_PYTHON_PATH = $pythonPath
        HOST_AGENT_BACKEND = $RuntimeBackend
        HOST_AGENT_HYPERV_VM_NAME = $HyperVVmName
        HOST_AGENT_HYPERV_SNAPSHOT_NAME = $HyperVSnapshotName
        HOST_AGENT_HYPERV_RUNTIME_ENDPOINT = $HyperVRuntimeEndpoint
    }
    foreach ($entry in $runtimeEnvValues.GetEnumerator()) {
        $allowEmpty = $entry.Key.StartsWith("HOST_AGENT_HYPERV_") -or
            $entry.Key -eq "HOST_AGENT_RUNTIME_ADVERTISED_HOST"
        Assert-SafeRuntimeEnvValue -Name $entry.Key -Value ([string]$entry.Value) -AllowEmpty:$allowEmpty | Out-Null
    }

    $envContent = @"
# Rikune Windows Runtime Environment — generated by install-runtime-windows.ps1
# This file configures the Windows Host Agent and the Runtime Node inside Windows Sandbox.

# Host Agent settings
HOST_AGENT_PORT=$Port
HOST_AGENT_BIND_HOST=$BindHost
HOST_AGENT_RUNTIME_BIND_HOST=$RuntimeBindHost
HOST_AGENT_RUNTIME_ADVERTISED_HOST=$RuntimeAdvertisedHost
HOST_AGENT_API_KEY=$hostApiKey
HOST_AGENT_RUNTIME_API_KEY=$runtimeApiKey
HOST_AGENT_WORKSPACE=$WorkspaceRoot
HOST_AGENT_NODE_PATH=$nodePath
HOST_AGENT_PYTHON_PATH=$pythonPath
HOST_AGENT_BACKEND=$RuntimeBackend

# Hyper-V backend settings. Used only when HOST_AGENT_BACKEND=hyperv-vm.
HOST_AGENT_HYPERV_VM_NAME=$HyperVVmName
HOST_AGENT_HYPERV_SNAPSHOT_NAME=$HyperVSnapshotName
HOST_AGENT_HYPERV_RUNTIME_ENDPOINT=$HyperVRuntimeEndpoint
HOST_AGENT_HYPERV_RESTORE_ON_RELEASE=$($HyperVRestoreOnRelease.IsPresent.ToString().ToLowerInvariant())
HOST_AGENT_HYPERV_STOP_ON_RELEASE=$($HyperVStopOnRelease.IsPresent.ToString().ToLowerInvariant())

# Optional: restrict CORS origin for Runtime Node (distributed mode)
# RUNTIME_CORS_ORIGIN=http://your-linux-analyzer-ip:18080

# Optional: allow unsafe runtime outside Windows Sandbox (DANGEROUS — only for dev)
# ALLOW_UNSAFE_RUNTIME=true
"@

    $envContent = "$($envContent.TrimEnd())`n"
    Write-SecureRuntimeEnvFile -Path $envFile -Content $envContent -RequireAbsent
    $privateEnvTransactionCommitted = $true
    $privateEnvSnapshot = $null
    Write-Success "Environment file: $envFile"
    Write-Info "Host Agent key fingerprint: $(Get-SecretFingerprint -Secret $hostApiKey)"
    Write-Info "Runtime Node key fingerprint: $(Get-SecretFingerprint -Secret $runtimeApiKey)"
} catch {
    $privateEnvFailure = $_
    if ($_.Exception.Data.Contains("RIKUNE_NATIVE_EXIT_CODE")) {
        $privateEnvFailureExitCode = [int]$_.Exception.Data["RIKUNE_NATIVE_EXIT_CODE"]
    }
} finally {
    if ($privateEnvTransactionActive -and -not $privateEnvTransactionCommitted) {
        try {
            Restore-RuntimePrivateEnvSnapshot `
                -Path $envFile `
                -Snapshot $privateEnvSnapshot `
                -NodePath $nodePath `
                -WriterPath $privateEnvWriter
        } catch {
            Write-Error-Message "Failed to restore the protected Windows runtime env after installer failure: $($_.Exception.Message)"
        }
    }
    $privateEnvSnapshot = $null
    $capturedHostApiKey = $null
    $capturedRuntimeApiKey = $null
    $envContent = $null
    $hostApiKey = $null
    $runtimeApiKey = $null
}
if ($null -ne $privateEnvFailure) {
    Write-Error-Message $privateEnvFailure.Exception.Message
    exit $privateEnvFailureExitCode
}

# =============================================================================
# Step 6: Start Host Agent
# =============================================================================
Write-Step "Starting Windows Host Agent"

$hostAgentBootstrapEntry = Join-Path $ProjectRoot "packages\windows-host-agent\dist\bootstrap.js"
if (-not (Test-Path $hostAgentBootstrapEntry)) {
    Exit-WithError "Host Agent secure bootstrap not found at $hostAgentBootstrapEntry. Build may have failed."
}

# The bootstrap reads the protected env file after process start. Do not export
# credentials into PM2 metadata, dump.pm2, or the child process argument vector.

if ($Service) {
    Write-Warning-Message "Windows Sandbox must be launched from a logged-on interactive user session."
    Write-Warning-Message "This mode uses PM2 in the current user session only; node-windows / Windows Service mode is intentionally disabled."
    Write-Info "Starting Host Agent under PM2..."

    try {
        $pm2Contract = Resolve-PinnedPm2Command -ProjectRoot $ProjectRoot
    } catch {
        Exit-WithError $_.Exception.Message
    }
    $pm2Command = $pm2Contract.Command
    Write-Info "Using lockfile-pinned PM2 $($pm2Contract.Version) to manage the user-session process..."

    $pm2DeleteOutput = & $pm2Command delete "rikune-host-agent" 2>&1
    if ($pm2DeleteOutput) {
        $pm2DeleteOutput | ForEach-Object { Write-Info $_.ToString() }
    }

    $pm2StartOutput = & $pm2Command start "$hostAgentBootstrapEntry" --name "rikune-host-agent" --cwd "$ProjectRoot" 2>&1
    $pm2StartExitCode = $LASTEXITCODE
    if ($pm2StartOutput) {
        $pm2StartOutput | ForEach-Object { Write-Info $_.ToString() }
    }
    if ($pm2StartExitCode -ne 0) {
        Exit-WithError "pm2 failed to start Host Agent. Check pm2 logs rikune-host-agent for details."
    }

    $pm2SaveOutput = & $pm2Command save 2>&1
    $pm2SaveExitCode = $LASTEXITCODE
    if ($pm2SaveOutput) {
        $pm2SaveOutput | ForEach-Object { Write-Info $_.ToString() }
    }
    if ($pm2SaveExitCode -ne 0) {
        Exit-WithError "pm2 failed to save process list."
    }
    Write-Success "Host Agent registered with pm2 (name: rikune-host-agent)"
    Write-Info "Manage with: $pm2Command logs rikune-host-agent"
} else {
    Write-Info "Starting Host Agent in the current user session..."
    Write-Info "Keep this Windows user logged in while using Windows Sandbox dynamic execution."
    Write-Host ""

    # Interactive user-session process: required for Windows Sandbox launch.
    # Headless mode uses the same detached process model, but skips prompts.
    $startResult = Start-HostAgentProcess `
        -NodeExecutable $nodePath `
        -EntryPath $hostAgentBootstrapEntry `
        -WorkingDirectory $ProjectRoot `
        -WorkspaceRoot $WorkspaceRoot
    Write-Success "Host Agent started as background process (PID: $($startResult.Process.Id))"
    Write-Info "Stdout log: $($startResult.StdoutLog)"
    Write-Info "Stderr log: $($startResult.StderrLog)"
    Start-Sleep -Seconds 2
}

# =============================================================================
# Step 7: Verify Connectivity
# =============================================================================
Write-Step "Verifying Host Agent Connectivity"

$healthUrl = "http://127.0.0.1:$Port/sandbox/health"
$maxAttempts = 10
$attempt = 0
$healthOk = $false

while ($attempt -lt $maxAttempts) {
    $attempt++
    $result = Invoke-Request -Uri $healthUrl -Headers @{ Authorization = "Bearer $hostApiKey" } -TimeoutSec 3
    if ($result.ok -eq $true) {
        $healthOk = $true
        break
    }
    Write-Info "Health check attempt $attempt / $maxAttempts ..."
    Start-Sleep -Seconds 1
}

if ($healthOk) {
    Write-Success "Host Agent is healthy and responding"
} else {
    Write-Info "Check stdout log: $(Join-Path $WorkspaceRoot "workspace\logs\host-agent.log")"
    Write-Info "Check stderr log: $(Join-Path $WorkspaceRoot "workspace\logs\host-agent.error.log")"
    Exit-WithError "Host Agent did not become healthy before the installation timeout."
}

if (Test-IsLoopbackRuntimeHost -HostName $BindHost) {
    try {
        Assert-LoopbackHostAgentListener -Port $Port -ExpectedNodePath $nodePath
        Write-Success "Host Agent listener is owned by the expected Node.js executable and restricted to loopback"
    } catch {
        Exit-WithError "Host Agent listener verification failed closed: $($_.Exception.Message)"
    }
}

# =============================================================================
# Summary
# =============================================================================
Write-Header "Installation Complete"

Write-Host "  Project Root:   $ProjectRoot" -ForegroundColor $ColorSuccess
Write-Host "  Workspace:      $WorkspaceRoot" -ForegroundColor $ColorSuccess
Write-Host "  Host Agent:     http://127.0.0.1:$Port (bind: $BindHost)" -ForegroundColor $ColorSuccess
Write-Host "  Backend:        $RuntimeBackend" -ForegroundColor $ColorSuccess
if ($RuntimeBackend -eq "hyperv-vm") {
    Write-Host "  Hyper-V VM:     $HyperVVmName" -ForegroundColor $ColorSuccess
    Write-Host "  Runtime Node:   $HyperVRuntimeEndpoint" -ForegroundColor $ColorSuccess
    if ($HyperVRestoreOnRelease) {
        Write-Host "  Release Policy: restore checkpoint on release" -ForegroundColor $ColorSuccess
    } elseif ($HyperVStopOnRelease) {
        Write-Host "  Release Policy: stop VM on release" -ForegroundColor $ColorSuccess
    } else {
        Write-Host "  Release Policy: preserve dirty VM state" -ForegroundColor $ColorSuccess
    }
}
Write-Host "  Host Key Fingerprint:    $(Get-SecretFingerprint -Secret $hostApiKey)" -ForegroundColor $ColorSuccess
Write-Host "  Runtime Key Fingerprint: $(Get-SecretFingerprint -Secret $runtimeApiKey)" -ForegroundColor $ColorSuccess
Write-Host "  Env File:       $envFile" -ForegroundColor $ColorSuccess

Write-Host "`n  Quick Start:" -ForegroundColor $ColorPrimary
Write-Host "    1. Keep the Host Agent on loopback, or put non-loopback access behind TLS/VPN and a restrictive firewall." -ForegroundColor $ColorInfo
Write-Host "    2. Read both distinct API keys from the protected env file and provision them through secure secret channels." -ForegroundColor $ColorInfo
Write-Host "    3. On the Linux Analyzer, set:" -ForegroundColor $ColorInfo
Write-Host "       RUNTIME_MODE=remote-sandbox" -ForegroundColor $ColorInfo
Write-Host "       RUNTIME_HOST_AGENT_ENDPOINT=https://<trusted-runtime-endpoint>" -ForegroundColor $ColorInfo
Write-Host "       RUNTIME_HOST_AGENT_API_KEY=<secret-from-protected-env-file>" -ForegroundColor $ColorInfo
Write-Host "       RUNTIME_API_KEY=<distinct-runtime-secret-from-protected-env-file>" -ForegroundColor $ColorInfo
Write-Host "`n  Managing the Host Agent:" -ForegroundColor $ColorPrimary
if ($Service) {
    Write-Host "    & '$pm2Command' logs rikune-host-agent" -ForegroundColor $ColorInfo
    Write-Host "    & '$pm2Command' stop rikune-host-agent" -ForegroundColor $ColorInfo
} else {
    Write-Host "    Stdout: $(Join-Path $WorkspaceRoot "workspace\logs\host-agent.log")" -ForegroundColor $ColorInfo
    Write-Host "    Stderr: $(Join-Path $WorkspaceRoot "workspace\logs\host-agent.error.log")" -ForegroundColor $ColorInfo
    Write-Host "    Stop: taskkill /F /IM node.exe   (or find PID in Resource Monitor)" -ForegroundColor $ColorInfo
}

$installInfo = @{
    InstallDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Mode = "windows-runtime"
    ProjectRoot = $ProjectRoot
    WorkspaceRoot = $WorkspaceRoot
    Port = $Port
    RuntimeBackend = $RuntimeBackend
    HyperVVmName = $HyperVVmName
    HyperVSnapshotName = $HyperVSnapshotName
    HyperVRuntimeEndpoint = $HyperVRuntimeEndpoint
    HyperVRestoreOnRelease = [bool]$HyperVRestoreOnRelease
    HyperVStopOnRelease = [bool]$HyperVStopOnRelease
    NodeVersion = $nodeVersion
    PythonVersion = $pyVersion
    ServiceMode = [bool]$Service
}
$installInfo | ConvertTo-Json | Set-Content (Join-Path $WorkspaceRoot "install-info.json") -Encoding UTF8

if (-not $Headless -and -not $Service) {
    Write-Host "`nPress any key to exit..." -ForegroundColor $ColorInfo
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}
