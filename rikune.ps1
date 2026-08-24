# Rikune top-level deployment and operations script for Windows.
# Requires: PowerShell 7+ for install/runtime actions, Docker Desktop for Docker profiles.

param(
    [Parameter(Position = 0)]
    [ValidateSet("menu", "install", "start", "stop", "restart", "status", "logs", "health", "doctor", "generate", "runtime-install", "runtime-status", "runtime-stop")]
    [string]$Action = "menu",

    [ValidateSet("static", "hybrid", "full")]
    [string]$Profile = "static",

    [string]$DataRoot = "D:\Docker\rikune",
    [string]$ProjectRoot = $PSScriptRoot,

    [string]$HostAgentEndpoint,
    [Parameter(HelpMessage = "Deprecated argv-based Host Agent key input. Prefer the protected RUNTIME_HOST_AGENT_API_KEY process environment.")]
    [string]$HostAgentApiKey,
    [Parameter(HelpMessage = "Deprecated argv-based Runtime Node key input. Prefer the protected, distinct RUNTIME_API_KEY process environment.")]
    [string]$RuntimeApiKey,
    [int]$HostAgentPort = 18082,
    [ValidateSet("windows-sandbox", "hyperv-vm")]
    [string]$RuntimeBackend = "windows-sandbox",
    [string]$HyperVVmName,
    [string]$HyperVSnapshotName,
    [string]$HyperVRuntimeEndpoint,
    [switch]$HyperVRestoreOnRelease,
    [switch]$HyperVStopOnRelease,

    [switch]$InstallRuntime,
    [switch]$Service,
    [switch]$SkipBuild,
    [switch]$SkipStart,
    [switch]$ResetData,
    [switch]$UseProxy,
    [switch]$NoProxyAutoDetect,
    [switch]$AllowInsecureRuntimeHttp,
    [string]$HttpProxy,
    [string]$HttpsProxy,
    [switch]$Follow,
    [int]$Tail = 100
)

$ErrorActionPreference = "Stop"

$script:Profiles = @{
    static = @{
        Generator = "static"
        Compose = "docker-compose.analyzer.yml"
        Service = "analyzer"
        Container = "rikune-analyzer"
        Description = "Static-only Docker analyzer"
    }
    hybrid = @{
        Generator = "hybrid"
        Compose = "docker-compose.hybrid.yml"
        Service = "analyzer"
        Container = "rikune-analyzer"
        Description = "Docker analyzer + Windows Host Agent / Windows Sandbox"
    }
    full = @{
        Generator = "full"
        Compose = "docker-compose.yml"
        Service = "mcp-server"
        Container = "rikune"
        Description = "Full all-in-one Linux Docker image"
    }
}

function Write-Header {
    param([string]$Text)
    Write-Host ""
    Write-Host "==================================================" -ForegroundColor Cyan
    Write-Host "  $Text" -ForegroundColor Cyan
    Write-Host "==================================================" -ForegroundColor Cyan
}

function Write-Step {
    param([string]$Text)
    Write-Host ""
    Write-Host "[STEP] $Text" -ForegroundColor Cyan
    Write-Host "-----------------------------------------" -ForegroundColor Cyan
}

function Write-Ok {
    param([string]$Text)
    Write-Host "[OK] " -ForegroundColor Green -NoNewline
    Write-Host $Text -ForegroundColor Green
}

function Write-Warn {
    param([string]$Text)
    Write-Host "[WARN] " -ForegroundColor Yellow -NoNewline
    Write-Host $Text -ForegroundColor Yellow
}

function Write-Err {
    param([string]$Text)
    Write-Host "[ERROR] " -ForegroundColor Red -NoNewline
    Write-Host $Text -ForegroundColor Red
}

function Write-Info {
    param([string]$Text)
    Write-Host "  $Text"
}

function Get-ProfileConfig {
    param([string]$ProfileName)
    return $script:Profiles[$ProfileName]
}

function Get-PowerShellExe {
    $pwsh = Get-Command pwsh -ErrorAction SilentlyContinue
    if ($pwsh) { return $pwsh.Source }
    if ($PSVersionTable.PSVersion.Major -lt 7) {
        throw "PowerShell 7 or newer is required. Install pwsh before running Rikune installers."
    }
    try {
        $path = (Get-Process -Id $PID).Path
        if ($path) { return $path }
    } catch {
    }
    throw "Unable to resolve the PowerShell 7 executable"
}

function Test-Command {
    param([string]$Name)
    return [bool](Get-Command $Name -ErrorAction SilentlyContinue)
}

function Resolve-ComposeKind {
    try {
        & docker compose version *> $null
        if ($LASTEXITCODE -eq 0) { return "docker compose" }
    } catch {
    }

    if (Test-Command "docker-compose") { return "docker-compose" }
    return $null
}

function Invoke-Compose {
    param(
        [string]$ProfileName,
        [string[]]$Arguments,
        [switch]$IgnoreFailure
    )

    $config = Get-ProfileConfig $ProfileName
    $composeFile = Join-Path $ProjectRoot $config.Compose
    $envFile = Join-Path $ProjectRoot ".docker-runtime.env"
    $composeKind = Resolve-ComposeKind

    if (-not $composeKind) {
        throw "Docker Compose was not found"
    }
    if (-not (Test-Path $composeFile)) {
        throw "Compose file not found: $composeFile. Run '.\rikune.ps1 generate -Profile $ProfileName' or install first."
    }

    $composeArgs = @()
    if (Test-Path $envFile) {
        Assert-ProtectedCredentialFile -Path $envFile | Out-Null
        $composeArgs += @("--env-file", $envFile)
    } else {
        Write-Warn ".docker-runtime.env not found. Compose defaults will be used."
    }
    $composeArgs += @("-f", $composeFile)
    $composeArgs += $Arguments

    Push-Location $ProjectRoot
    try {
        if ($composeKind -eq "docker compose") {
            & docker compose @composeArgs
        } else {
            & docker-compose @composeArgs
        }
        $code = $LASTEXITCODE
    } finally {
        Pop-Location
    }

    if ($code -ne 0 -and -not $IgnoreFailure) {
        throw "Docker Compose failed with exit code $code"
    }
    $script:LastComposeExitCode = $code
}

function Invoke-ChildPowerShell {
    param(
        [string[]]$Arguments,
        [hashtable]$Environment = @{}
    )

    $ps = Get-PowerShellExe
    $previousEnvironment = @{}
    foreach ($name in $Environment.Keys) {
        $previousEnvironment[$name] = [Environment]::GetEnvironmentVariable($name, "Process")
        [Environment]::SetEnvironmentVariable($name, [string]$Environment[$name], "Process")
    }
    $exitCode = 1
    try {
        & $ps @Arguments
        $exitCode = $LASTEXITCODE
    } finally {
        foreach ($name in $Environment.Keys) {
            [Environment]::SetEnvironmentVariable($name, $previousEnvironment[$name], "Process")
        }
    }
    if ($exitCode -ne 0) {
        throw "PowerShell child process failed with exit code $exitCode"
    }
}

function Read-SecretString {
    param([string]$Prompt)

    $secure = Read-Host $Prompt -AsSecureString
    $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
    try {
        return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer)
    } finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer)
    }
}

function Assert-SecureRuntimeEndpoint {
    param(
        [string]$Endpoint,
        [switch]$AllowInsecure
    )

    $uri = $null
    if (-not [Uri]::TryCreate($Endpoint, [UriKind]::Absolute, [ref]$uri)) {
        throw "Invalid Host Agent endpoint: $Endpoint"
    }
    if (-not [string]::IsNullOrEmpty($uri.UserInfo)) {
        throw "Host Agent endpoints must not contain URL userinfo credentials"
    }
    if ($uri.Scheme -eq "https") { return }
    if ($uri.Scheme -eq "http" -and $uri.Host -in @("localhost", "127.0.0.1", "::1", "host.docker.internal")) { return }
    if ($uri.Scheme -eq "http" -and $AllowInsecure) {
        Write-Warn "Using plaintext remote runtime HTTP by explicit opt-in. Restrict it to a trusted VPN/isolated network."
        return
    }
    throw "Remote Host Agent endpoints must use HTTPS. Use -AllowInsecureRuntimeHttp only for an isolated trusted network."
}

function ConvertFrom-RuntimeEnvContent {
    param([string]$Content)
    $values = @{}
    foreach ($line in ($Content -split "`r?`n")) {
        $trimmed = $line.Trim()
        if ([string]::IsNullOrWhiteSpace($trimmed) -or $trimmed.StartsWith("#")) { continue }

        $idx = $trimmed.IndexOf("=")
        if ($idx -lt 1) { continue }

        $key = $trimmed.Substring(0, $idx).Trim()
        $value = $trimmed.Substring($idx + 1).Trim()
        if (($value.StartsWith('"') -and $value.EndsWith('"')) -or ($value.StartsWith("'") -and $value.EndsWith("'"))) {
            $value = $value.Substring(1, $value.Length - 2)
        }
        $values[$key] = $value
    }
    return $values
}

function Assert-ProtectedCredentialFile {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [long]$MaxBytes = 65536
    )

    $absolutePath = [System.IO.Path]::GetFullPath($Path)
    if (-not (Test-Path -LiteralPath $absolutePath -PathType Leaf)) {
        throw "Protected credential file does not exist or is not a regular file: $absolutePath"
    }

    $item = Get-Item -LiteralPath $absolutePath -Force
    if ($item.PSIsContainer -or (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0)) {
        throw "Protected credential file must be a non-reparse regular file: $absolutePath"
    }
    if ($item.Length -gt $MaxBytes) {
        throw "Protected credential file exceeds the $MaxBytes byte limit: $absolutePath"
    }
    if (-not $IsWindows) {
        throw "Windows credential ACL verification is unavailable on this platform: $absolutePath"
    }

    $currentSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
    $acl = Get-Acl -LiteralPath $absolutePath
    try {
        $ownerSid = ([System.Security.Principal.NTAccount]$acl.Owner).Translate(
            [System.Security.Principal.SecurityIdentifier]
        )
    } catch {
        throw "Unable to resolve protected credential file owner: $absolutePath"
    }
    if ($ownerSid.Value -ne $currentSid.Value) {
        throw "Protected credential file must be owned by the current user: $absolutePath"
    }
    if (-not $acl.AreAccessRulesProtected) {
        throw "Protected credential file ACL inheritance must be disabled: $absolutePath"
    }

    $rules = @($acl.GetAccessRules(
        $true,
        $true,
        [System.Security.Principal.SecurityIdentifier]
    ))
    if ($rules.Count -ne 1) {
        throw "Protected credential file must have exactly one ACL entry: $absolutePath"
    }
    $rule = $rules[0]
    if (
        $rule.IdentityReference.Value -ne $currentSid.Value -or
        $rule.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow -or
        $rule.FileSystemRights -ne [System.Security.AccessControl.FileSystemRights]::FullControl -or
        $rule.InheritanceFlags -ne [System.Security.AccessControl.InheritanceFlags]::None -or
        $rule.PropagationFlags -ne [System.Security.AccessControl.PropagationFlags]::None
    ) {
        throw "Protected credential file ACL must grant only the current user FullControl: $absolutePath"
    }

    return $item
}

function Read-ProtectedEnvFile {
    param([string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) { return @{} }
    $item = Assert-ProtectedCredentialFile -Path $Path
    $stream = $null
    try {
        $stream = [System.IO.File]::Open(
            $item.FullName,
            [System.IO.FileMode]::Open,
            [System.IO.FileAccess]::Read,
            [System.IO.FileShare]::None
        )
        if ($stream.Length -ne $item.Length -or $stream.Length -gt 65536) {
            throw "Protected credential file changed during validation: $($item.FullName)"
        }
        Assert-ProtectedCredentialFile -Path $item.FullName | Out-Null
        $reader = [System.IO.StreamReader]::new(
            $stream,
            [System.Text.UTF8Encoding]::new($false, $true),
            $true,
            1024,
            $true
        )
        try {
            $content = $reader.ReadToEnd()
        } finally {
            $reader.Dispose()
        }
    } finally {
        if ($stream) { $stream.Dispose() }
    }

    Assert-ProtectedCredentialFile -Path $item.FullName | Out-Null
    return ConvertFrom-RuntimeEnvContent -Content $content
}

function Read-DefaultString {
    param(
        [string]$Prompt,
        [string]$DefaultValue
    )
    $value = Read-Host "$Prompt [$DefaultValue]"
    if ([string]::IsNullOrWhiteSpace($value)) { return $DefaultValue }
    return $value
}

function Read-YesNo {
    param(
        [string]$Prompt,
        [bool]$DefaultValue = $false
    )
    $suffix = if ($DefaultValue) { "Y/n" } else { "y/N" }
    $value = Read-Host "$Prompt ($suffix)"
    if ([string]::IsNullOrWhiteSpace($value)) { return $DefaultValue }
    return ($value -eq "y" -or $value -eq "Y")
}

function Reset-DataRoot {
    if (-not (Test-Path $DataRoot)) { return }

    $target = $DataRoot
    if (-not [System.IO.Path]::IsPathRooted($target)) {
        $target = Join-Path $ProjectRoot $target
    }
    $resolved = (Resolve-Path $target).Path
    $driveRoot = [System.IO.Path]::GetPathRoot($resolved)
    if ($resolved -eq $driveRoot -or $resolved.Length -lt 6) {
        throw "Refusing to delete unsafe data root: $resolved"
    }

    Write-Warn "Deleting data root because -ResetData was specified: $resolved"
    Remove-Item -LiteralPath $resolved -Recurse -Force
}

function Get-RuntimeCredentials {
    $runtimeEnv = Read-ProtectedEnvFile (Join-Path $ProjectRoot ".env.runtime-windows")
    $dockerEnv = Read-ProtectedEnvFile (Join-Path $ProjectRoot ".docker-runtime.env")

    $port = $HostAgentPort
    if ($runtimeEnv.ContainsKey("HOST_AGENT_PORT") -and $runtimeEnv["HOST_AGENT_PORT"]) {
        $port = [int]$runtimeEnv["HOST_AGENT_PORT"]
    }

    $endpoint = $HostAgentEndpoint
    if ([string]::IsNullOrWhiteSpace($endpoint) -and $dockerEnv.ContainsKey("RUNTIME_HOST_AGENT_ENDPOINT")) {
        $endpoint = $dockerEnv["RUNTIME_HOST_AGENT_ENDPOINT"]
    }
    if ([string]::IsNullOrWhiteSpace($endpoint)) {
        $endpoint = "http://host.docker.internal:$port"
    }

    $hostKey = $HostAgentApiKey
    if ([string]::IsNullOrWhiteSpace($hostKey)) {
        $hostKey = $env:RUNTIME_HOST_AGENT_API_KEY
    }
    if ([string]::IsNullOrWhiteSpace($hostKey) -and $runtimeEnv.ContainsKey("HOST_AGENT_API_KEY")) {
        $hostKey = $runtimeEnv["HOST_AGENT_API_KEY"]
    }
    if ([string]::IsNullOrWhiteSpace($hostKey) -and $dockerEnv.ContainsKey("RUNTIME_HOST_AGENT_API_KEY")) {
        $hostKey = $dockerEnv["RUNTIME_HOST_AGENT_API_KEY"]
    }

    $runtimeKey = $RuntimeApiKey
    if ([string]::IsNullOrWhiteSpace($runtimeKey)) {
        $runtimeKey = $env:RUNTIME_API_KEY
    }
    if ([string]::IsNullOrWhiteSpace($runtimeKey) -and $dockerEnv.ContainsKey("RUNTIME_API_KEY")) {
        $runtimeKey = $dockerEnv["RUNTIME_API_KEY"]
    }
    if ([string]::IsNullOrWhiteSpace($runtimeKey) -and $runtimeEnv.ContainsKey("HOST_AGENT_RUNTIME_API_KEY")) {
        $runtimeKey = $runtimeEnv["HOST_AGENT_RUNTIME_API_KEY"]
    }
    if (
        -not [string]::IsNullOrWhiteSpace($hostKey) -and
        -not [string]::IsNullOrWhiteSpace($runtimeKey) -and
        $hostKey -ceq $runtimeKey
    ) {
        throw "Host Agent and Runtime Node API keys must be distinct"
    }

    return [pscustomobject]@{
        Endpoint = $endpoint
        HostKey = $hostKey
        RuntimeKey = $runtimeKey
        Port = $port
    }
}

function Convert-EndpointForHostHealth {
    param(
        [string]$Endpoint,
        [int]$Port
    )
    if ([string]::IsNullOrWhiteSpace($Endpoint)) {
        return "http://127.0.0.1:$Port"
    }
    if ($Endpoint -match "host\.docker\.internal" -or $Endpoint -match "localhost") {
        return "http://127.0.0.1:$Port"
    }
    return $Endpoint.TrimEnd("/")
}

function Invoke-HttpJson {
    param(
        [string]$Uri,
        [hashtable]$Headers = @{},
        [int]$TimeoutSec = 8
    )

    $params = @{
        Uri = $Uri
        Method = "GET"
        TimeoutSec = $TimeoutSec
        UseBasicParsing = $true
        ErrorAction = "Stop"
    }
    if ($Headers.Count -gt 0) { $params.Headers = $Headers }
    if ((Get-Command Invoke-WebRequest).Parameters.ContainsKey("NoProxy")) {
        $params.NoProxy = $true
    }

    $response = Invoke-WebRequest @params
    if ([string]::IsNullOrWhiteSpace($response.Content)) {
        return [pscustomobject]@{ ok = $true; statusCode = $response.StatusCode }
    }
    try {
        return ($response.Content | ConvertFrom-Json)
    } catch {
        return [pscustomobject]@{ ok = $true; statusCode = $response.StatusCode; body = $response.Content }
    }
}

function Install-Runtime {
    $installer = Join-Path $ProjectRoot "install-runtime-windows.ps1"
    if (-not (Test-Path $installer)) { throw "install-runtime-windows.ps1 not found" }

    $workspaceRoot = Join-Path $DataRoot "windows-runtime"
    $args = @(
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-File", $installer,
        "-ProjectRoot", $ProjectRoot,
        "-WorkspaceRoot", $workspaceRoot,
        "-Port", "$HostAgentPort",
        "-BindHost", "127.0.0.1",
        "-RuntimeBindHost", "127.0.0.1",
        "-RuntimeAdvertisedHost", "host.docker.internal",
        "-RuntimeBackend", $RuntimeBackend,
        "-Headless"
    )
    if (-not [string]::IsNullOrWhiteSpace($HyperVVmName)) {
        $args += @("-HyperVVmName", $HyperVVmName)
    }
    if (-not [string]::IsNullOrWhiteSpace($HyperVSnapshotName)) {
        $args += @("-HyperVSnapshotName", $HyperVSnapshotName)
    }
    if (-not [string]::IsNullOrWhiteSpace($HyperVRuntimeEndpoint)) {
        $args += @("-HyperVRuntimeEndpoint", $HyperVRuntimeEndpoint)
    }
    if ($HyperVRestoreOnRelease) { $args += "-HyperVRestoreOnRelease" }
    if ($HyperVStopOnRelease) { $args += "-HyperVStopOnRelease" }
    if ($AllowInsecureRuntimeHttp) { $args += "-AllowInsecureRuntimeHttp" }
    if ($Service) { $args += "-Service" }
    if ($SkipBuild) { $args += "-SkipBuild" }
    $childEnvironment = @{}
    if (-not [string]::IsNullOrWhiteSpace($HostAgentApiKey)) {
        $childEnvironment.RIKUNE_HOST_AGENT_API_KEY = $HostAgentApiKey
    } elseif (-not [string]::IsNullOrWhiteSpace($env:RUNTIME_HOST_AGENT_API_KEY)) {
        $childEnvironment.RIKUNE_HOST_AGENT_API_KEY = $env:RUNTIME_HOST_AGENT_API_KEY
    }
    if (-not [string]::IsNullOrWhiteSpace($RuntimeApiKey)) {
        $childEnvironment.RIKUNE_RUNTIME_NODE_API_KEY = $RuntimeApiKey
    } elseif (-not [string]::IsNullOrWhiteSpace($env:RUNTIME_API_KEY)) {
        $childEnvironment.RIKUNE_RUNTIME_NODE_API_KEY = $env:RUNTIME_API_KEY
    }

    Write-Step "Installing Windows Host Agent runtime"
    Write-Info "Workspace root: $workspaceRoot"
    Write-Info "Host Agent and runtime proxy will bind only to 127.0.0.1; Docker Desktop reaches them through host.docker.internal."
    if ($Service) {
        Write-Warn "Sandbox launch requires a logged-on desktop session; -Service uses PM2 only, not a Windows Service."
    }
    Invoke-ChildPowerShell -Arguments $args -Environment $childEnvironment
    Write-Ok "Windows Host Agent installer completed"
}

function Install-Stack {
    param([string]$ProfileName)

    $config = Get-ProfileConfig $ProfileName
    Write-Header "Rikune Install: $ProfileName"
    Write-Info $config.Description
    Write-Info "Project root: $ProjectRoot"
    Write-Info "Data root: $DataRoot"

    $dockerEndpoint = $HostAgentEndpoint
    $hostKey = $HostAgentApiKey
    $runtimeKey = $RuntimeApiKey
    $resetHandledByWrapper = $false

    if ($ProfileName -eq "hybrid") {
        $creds = Get-RuntimeCredentials
        $localEndpoint = [string]::IsNullOrWhiteSpace($HostAgentEndpoint) -or $HostAgentEndpoint -match "host\.docker\.internal|localhost|127\.0\.0\.1"
        $shouldInstallLocalRuntime = $InstallRuntime -or (([string]::IsNullOrWhiteSpace($creds.HostKey) -or [string]::IsNullOrWhiteSpace($creds.RuntimeKey)) -and $localEndpoint) -or ($ResetData -and $localEndpoint)

        if ($ResetData -and $localEndpoint) {
            Reset-DataRoot
            $resetHandledByWrapper = $true
        }

        if ($shouldInstallLocalRuntime) {
            Install-Runtime
            $creds = Get-RuntimeCredentials
        }

        if ([string]::IsNullOrWhiteSpace($creds.HostKey)) {
            throw "Hybrid install needs a Host Agent API key. Provide RUNTIME_HOST_AGENT_API_KEY through a protected process environment, run -InstallRuntime, or install the Windows runtime first."
        }
        if ([string]::IsNullOrWhiteSpace($creds.RuntimeKey)) {
            throw "Hybrid install needs a distinct Runtime Node API key. Provide RUNTIME_API_KEY through a protected process environment, run -InstallRuntime, or install the Windows runtime first."
        }
        if ($creds.HostKey -ceq $creds.RuntimeKey) {
            throw "Host Agent and Runtime Node API keys must be distinct"
        }

        $dockerEndpoint = if ([string]::IsNullOrWhiteSpace($HostAgentEndpoint)) { "http://host.docker.internal:$($creds.Port)" } else { $HostAgentEndpoint }
        $hostKey = $creds.HostKey
        $runtimeKey = $creds.RuntimeKey
        Assert-SecureRuntimeEndpoint -Endpoint $dockerEndpoint -AllowInsecure:$AllowInsecureRuntimeHttp

        Write-Ok "Hybrid endpoint for container: $dockerEndpoint"
    }

    $installer = Join-Path $ProjectRoot "install-docker.ps1"
    if (-not (Test-Path $installer)) { throw "install-docker.ps1 not found" }

    $args = @(
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-File", $installer,
        "-Profile", $ProfileName,
        "-DataRoot", $DataRoot,
        "-ProjectRoot", $ProjectRoot
    )
    if ($SkipBuild) { $args += "-SkipBuild" }
    if ($SkipStart) { $args += "-SkipStart" }
    if ($ResetData -and -not $resetHandledByWrapper) { $args += "-ResetData" }
    if (-not [string]::IsNullOrWhiteSpace($HttpProxy)) { $args += @("-HttpProxy", $HttpProxy) }
    if (-not [string]::IsNullOrWhiteSpace($HttpsProxy)) { $args += @("-HttpsProxy", $HttpsProxy) }
    if ($UseProxy -or (-not $NoProxyAutoDetect -and [string]::IsNullOrWhiteSpace($HttpProxy) -and [string]::IsNullOrWhiteSpace($HttpsProxy))) {
        $args += "-UseProxy"
    }
    if ($AllowInsecureRuntimeHttp) { $args += "-AllowInsecureRuntimeHttp" }
    if ($ProfileName -eq "hybrid") {
        $args += @("-HostAgentEndpoint", $dockerEndpoint)
    }

    $childEnvironment = @{}
    if ($ProfileName -eq "hybrid") {
        $childEnvironment.RUNTIME_HOST_AGENT_API_KEY = $hostKey
        $childEnvironment.RUNTIME_API_KEY = $runtimeKey
    }

    Write-Step "Running Docker profile installer"
    Invoke-ChildPowerShell -Arguments $args -Environment $childEnvironment
}

function Generate-Profile {
    param([string]$ProfileName)
    $config = Get-ProfileConfig $ProfileName

    Write-Header "Generate Docker Profile: $ProfileName"
    Push-Location $ProjectRoot
    try {
        & node scripts/generate-docker.mjs "--profile=$($config.Generator)"
        if ($LASTEXITCODE -ne 0) { throw "Docker generator failed" }
    } finally {
        Pop-Location
    }
    Write-Ok "Generated $($config.Compose)"
}

function Start-Stack {
    param([string]$ProfileName)
    $config = Get-ProfileConfig $ProfileName
    Write-Header "Start Rikune: $ProfileName"
    Invoke-Compose -ProfileName $ProfileName -Arguments @("up", "-d", $config.Service) | Out-Null
    Write-Ok "Service started: $($config.Service)"
}

function Stop-Stack {
    param([string]$ProfileName)
    Write-Header "Stop Rikune: $ProfileName"
    Invoke-Compose -ProfileName $ProfileName -Arguments @("down") | Out-Null
    Write-Ok "Compose stack stopped"
}

function Restart-Stack {
    param([string]$ProfileName)
    Stop-Stack -ProfileName $ProfileName
    Start-Stack -ProfileName $ProfileName
}

function Show-Logs {
    param([string]$ProfileName)
    $config = Get-ProfileConfig $ProfileName
    $args = @("logs", "--tail", "$Tail")
    if ($Follow) { $args += "-f" }
    $args += $config.Service
    Invoke-Compose -ProfileName $ProfileName -Arguments $args
}

function Test-AnalyzerHealth {
    try {
        $result = Invoke-HttpJson -Uri "http://127.0.0.1:18080/api/v1/health"
        Write-Ok "Analyzer API healthy: http://127.0.0.1:18080/api/v1/health"
        if ($result.status) { Write-Info "Status: $($result.status)" }
        return $true
    } catch {
        Write-Warn "Analyzer API health check failed: $($_.Exception.Message)"
        return $false
    }
}

function Test-RuntimeHealth {
    $creds = Get-RuntimeCredentials
    if ([string]::IsNullOrWhiteSpace($creds.HostKey)) {
        Write-Warn "Host Agent key not found in .env.runtime-windows or .docker-runtime.env"
        return $false
    }

    $endpoint = Convert-EndpointForHostHealth -Endpoint $creds.Endpoint -Port $creds.Port
    $uri = "$($endpoint.TrimEnd('/'))/sandbox/health"
    try {
        $result = Invoke-HttpJson -Uri $uri -Headers @{ Authorization = "Bearer $($creds.HostKey)" }
        Write-Ok "Windows Host Agent healthy: $uri"
        if ($result.sandbox) { Write-Info "Sandbox: $($result.sandbox)" }
        return $true
    } catch {
        Write-Warn "Windows Host Agent health check failed: $($_.Exception.Message)"
        return $false
    }
}

function Show-Health {
    param([string]$ProfileName)
    Write-Header "Rikune Health: $ProfileName"
    [void](Test-AnalyzerHealth)
    if ($ProfileName -eq "hybrid") {
        [void](Test-RuntimeHealth)
    }
}

function Show-Status {
    param([string]$ProfileName)
    Write-Header "Rikune Status: $ProfileName"
    try {
        Invoke-Compose -ProfileName $ProfileName -Arguments @("ps") -IgnoreFailure
    } catch {
        Write-Warn $_.Exception.Message
    }
    Show-Health -ProfileName $ProfileName
}

function Show-Doctor {
    param([string]$ProfileName)
    Write-Header "Rikune Doctor"

    if ($env:OS -eq "Windows_NT") { Write-Ok "OS: Windows" } else { Write-Warn "OS is not Windows_NT" }

    if (Test-Command "node") {
        $nodeVersion = (node --version).Trim()
        $nodeMajor = [int]($nodeVersion -replace "^v", "").Split(".")[0]
        if ($nodeMajor -ge 22) { Write-Ok "Node.js: $nodeVersion" } else { Write-Warn "Node.js $nodeVersion found, but 22+ is recommended" }
    } else {
        Write-Err "Node.js not found"
    }

    if (Test-Command "npm") { Write-Ok "npm: $((npm --version).Trim())" } else { Write-Err "npm not found" }

    if (Test-Command "docker") {
        Write-Ok "Docker CLI: $((docker --version).Trim())"
        try {
            & docker info *> $null
            if ($LASTEXITCODE -eq 0) { Write-Ok "Docker daemon is running" } else { Write-Warn "docker info failed" }
        } catch {
            Write-Warn "Docker daemon is not reachable"
        }
    } else {
        Write-Err "Docker CLI not found"
    }

    $composeKind = Resolve-ComposeKind
    if ($composeKind) { Write-Ok "Docker Compose: $composeKind" } else { Write-Err "Docker Compose not found" }

    foreach ($scriptName in @("install-docker.ps1", "install-runtime-windows.ps1", "scripts/generate-docker.mjs")) {
        $path = Join-Path $ProjectRoot $scriptName
        if (Test-Path $path) { Write-Ok "Found $scriptName" } else { Write-Err "Missing $scriptName" }
    }

    if ($ProfileName -eq "hybrid") {
        if ($RuntimeBackend -eq "hyperv-vm") {
            if (Get-Command Get-VM -ErrorAction SilentlyContinue) {
                Write-Ok "Hyper-V PowerShell module found"
            } else {
                Write-Warn "Hyper-V PowerShell module not found"
            }
            if (-not [string]::IsNullOrWhiteSpace($HyperVVmName)) {
                Write-Info "Hyper-V VM: $HyperVVmName"
            }
            if (-not [string]::IsNullOrWhiteSpace($HyperVRuntimeEndpoint)) {
                Write-Info "Hyper-V Runtime Node: $HyperVRuntimeEndpoint"
            }
            if ($HyperVRestoreOnRelease) {
                Write-Info "Hyper-V release policy: restore checkpoint on release"
            } elseif ($HyperVStopOnRelease) {
                Write-Info "Hyper-V release policy: stop VM on release"
            } else {
                Write-Info "Hyper-V release policy: preserve dirty VM state"
            }
        } else {
            if (Get-Command WindowsSandbox.exe -ErrorAction SilentlyContinue) {
                Write-Ok "WindowsSandbox.exe found"
            } else {
                Write-Warn "WindowsSandbox.exe not found in PATH"
            }
        }

        foreach ($svc in @("hns", "vmcompute")) {
            try {
                $service = Get-Service -Name $svc -ErrorAction Stop
                Write-Ok "Service ${svc}: $($service.Status)"
            } catch {
                Write-Warn "Service $svc not found"
            }
        }

        [void](Test-RuntimeHealth)
    }

    try {
        Invoke-Compose -ProfileName $ProfileName -Arguments @("config", "--quiet") -IgnoreFailure *> $null
        if ($script:LastComposeExitCode -eq 0) {
            Write-Ok "Compose config is valid for profile '$ProfileName'"
        } else {
            Write-Warn "Compose config check failed for profile '$ProfileName'"
        }
    } catch {
        Write-Warn "Compose config check skipped or failed: $($_.Exception.Message)"
    }
}

function Stop-Runtime {
    Write-Header "Stop Windows Host Agent"

    if (Test-Command "pm2") {
        & pm2 stop rikune-host-agent 2>$null
        & pm2 delete rikune-host-agent 2>$null
        Write-Ok "pm2 process stop/delete attempted"
    }

    try {
        $svc = Get-Service | Where-Object { $_.Name -eq "Rikune Windows Host Agent" -or $_.DisplayName -eq "Rikune Windows Host Agent" } | Select-Object -First 1
        if ($svc) {
            Stop-Service -Name $svc.Name -ErrorAction SilentlyContinue
            Write-Ok "Windows service stop attempted: $($svc.DisplayName)"
        }
    } catch {
        Write-Warn "Windows service stop failed: $($_.Exception.Message)"
    }

    $processes = Get-CimInstance Win32_Process -Filter "Name = 'node.exe'" -ErrorAction SilentlyContinue |
        Where-Object { $_.CommandLine -match "windows-host-agent" -or $_.CommandLine -match "packages\\windows-host-agent\\dist\\index\.js" }

    foreach ($proc in $processes) {
        try {
            Stop-Process -Id $proc.ProcessId -Force -ErrorAction Stop
            Write-Ok "Stopped Host Agent node process PID $($proc.ProcessId)"
        } catch {
            Write-Warn "Failed to stop PID $($proc.ProcessId): $($_.Exception.Message)"
        }
    }
}

function Show-Menu {
    try { Clear-Host } catch {
    }
    Write-Header "Rikune Control"
    Write-Host "  [1] Install static Docker analyzer"
    Write-Host "  [2] Install hybrid on this Windows host (Docker + Host Agent + Sandbox)"
    Write-Host "  [3] Install full Docker image"
    Write-Host "  [4] Start current profile"
    Write-Host "  [5] Status and health"
    Write-Host "  [6] Logs"
    Write-Host "  [7] Stop current profile"
    Write-Host "  [8] Doctor"
    Write-Host "  [9] Runtime status"
    Write-Host "  [0] Exit"
    $choice = Read-Host "Select"

    switch ($choice) {
        "1" {
            $script:DataRoot = Read-DefaultString "Data root" $DataRoot
            Install-Stack -ProfileName "static"
        }
        "2" {
            $script:DataRoot = Read-DefaultString "Data root" $DataRoot
            $script:RuntimeBackend = Read-DefaultString "Runtime backend (windows-sandbox/hyperv-vm)" $RuntimeBackend
            if ($script:RuntimeBackend -ne "windows-sandbox" -and $script:RuntimeBackend -ne "hyperv-vm") {
                Write-Warn "Unknown runtime backend; using windows-sandbox"
                $script:RuntimeBackend = "windows-sandbox"
            }
            if ($script:RuntimeBackend -eq "hyperv-vm") {
                $script:HyperVVmName = Read-DefaultString "Hyper-V VM name" $HyperVVmName
                $script:HyperVSnapshotName = Read-DefaultString "Hyper-V checkpoint name (optional)" $HyperVSnapshotName
                $script:HyperVRuntimeEndpoint = Read-DefaultString "Hyper-V Runtime Node endpoint" $HyperVRuntimeEndpoint
                $script:HyperVRestoreOnRelease = Read-YesNo "Restore checkpoint when runtime session is released" $false
                if (-not $script:HyperVRestoreOnRelease) {
                    $script:HyperVStopOnRelease = Read-YesNo "Stop Hyper-V VM when runtime session is released" $false
                } else {
                    $script:HyperVStopOnRelease = $true
                }
            }
            $script:Service = Read-YesNo "Run Host Agent under PM2 in this logged-on user session" $false
            $script:InstallRuntime = $true
            Install-Stack -ProfileName "hybrid"
        }
        "3" {
            $script:DataRoot = Read-DefaultString "Data root" $DataRoot
            Install-Stack -ProfileName "full"
        }
        "4" {
            $script:Profile = Read-DefaultString "Profile" $Profile
            Start-Stack -ProfileName $Profile
        }
        "5" {
            $script:Profile = Read-DefaultString "Profile" $Profile
            Show-Status -ProfileName $Profile
        }
        "6" {
            $script:Profile = Read-DefaultString "Profile" $Profile
            $script:Follow = Read-YesNo "Follow logs" $true
            Show-Logs -ProfileName $Profile
        }
        "7" {
            $script:Profile = Read-DefaultString "Profile" $Profile
            Stop-Stack -ProfileName $Profile
        }
        "8" {
            $script:Profile = Read-DefaultString "Profile" $Profile
            Show-Doctor -ProfileName $Profile
        }
        "9" {
            Show-Health -ProfileName "hybrid"
        }
        "0" { return }
        default { Write-Warn "Unknown selection" }
    }
}

$ProjectRoot = (Resolve-Path $ProjectRoot).Path

try {
    switch ($Action) {
        "menu" { Show-Menu }
        "install" { Install-Stack -ProfileName $Profile }
        "start" { Start-Stack -ProfileName $Profile }
        "stop" { Stop-Stack -ProfileName $Profile }
        "restart" { Restart-Stack -ProfileName $Profile }
        "status" { Show-Status -ProfileName $Profile }
        "logs" { Show-Logs -ProfileName $Profile }
        "health" { Show-Health -ProfileName $Profile }
        "doctor" { Show-Doctor -ProfileName $Profile }
        "generate" { Generate-Profile -ProfileName $Profile }
        "runtime-install" { Install-Runtime }
        "runtime-status" { Show-Health -ProfileName "hybrid" }
        "runtime-stop" { Stop-Runtime }
    }
} catch {
    Write-Err $_.Exception.Message
    exit 1
}
