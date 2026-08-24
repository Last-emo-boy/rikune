# Rikune - Docker profile installer
# Requires: PowerShell 7+, Docker Desktop / Docker Engine, Node.js 22.9+

param(
    [ValidateSet("static", "full", "hybrid")]
    [string]$Profile = "static",

    [Parameter(HelpMessage = "Persistent data root directory")]
    [string]$DataRoot = "D:\Docker\rikune",

    [Parameter(HelpMessage = "Project root directory")]
    [string]$ProjectRoot = $PSScriptRoot,

    [Parameter(HelpMessage = "Skip Docker image build")]
    [switch]$SkipBuild,

    [Parameter(HelpMessage = "Skip starting the Compose service after build")]
    [switch]$SkipStart,

    [Parameter(HelpMessage = "Delete and recreate the data root before installing")]
    [switch]$ResetData,

    [Parameter(HelpMessage = "Enable verbose output")]
    [switch]$EnableVerbose,

    [Parameter(HelpMessage = "HTTP proxy URL for npm and Docker build")]
    [string]$HttpProxy,

    [Parameter(HelpMessage = "HTTPS proxy URL for npm and Docker build")]
    [string]$HttpsProxy,

    [Parameter(HelpMessage = "Use Windows system proxy if available")]
    [switch]$UseProxy,

    [Parameter(HelpMessage = "Windows Host Agent endpoint for hybrid profile")]
    [string]$HostAgentEndpoint,

    [Parameter(HelpMessage = "Deprecated argv-based Host Agent key input. Prefer RUNTIME_HOST_AGENT_API_KEY or the hidden guided prompt.")]
    [string]$HostAgentApiKey,

    [Parameter(HelpMessage = "Deprecated argv-based Runtime Node key input. Prefer RUNTIME_API_KEY or the hidden guided prompt.")]
    [string]$RuntimeApiKey,

    [Parameter(HelpMessage = "Allow plaintext HTTP to a non-loopback Host Agent only on an isolated trusted network")]
    [switch]$AllowInsecureRuntimeHttp,

    [ValidateSet("None", "Claude", "Copilot", "Codex", "Generic")]
    [string]$ConfigureClient = "None",

    [Parameter(HelpMessage = "Force guided prompts even when some parameters are provided")]
    [switch]$Interactive
)

$ErrorActionPreference = "Stop"

$ColorPrimary = "Cyan"
$ColorSuccess = "Green"
$ColorWarning = "Yellow"
$ColorError = "Red"
$ColorInfo = "White"

$DefaultNoProxy = "localhost,127.0.0.1,deb.debian.org,security.debian.org,mirrors.aliyun.com,archive.ubuntu.com,security.ubuntu.com,aliyuncs.com"

$Profiles = @{
    static = @{
        Generator = "static"
        Compose = "docker-compose.analyzer.yml"
        Service = "analyzer"
        Image = "rikune-analyzer:latest"
        Container = "rikune-analyzer"
        RuntimeMode = "disabled"
        Description = "Static-only Docker analyzer"
    }
    full = @{
        Generator = "full"
        Compose = "docker-compose.yml"
        Service = "mcp-server"
        Image = "rikune:latest"
        Container = "rikune"
        RuntimeMode = "disabled"
        Description = "Full Linux Docker analysis stack"
    }
    hybrid = @{
        Generator = "hybrid"
        Compose = "docker-compose.hybrid.yml"
        Service = "analyzer"
        Image = "rikune-analyzer:latest"
        Container = "rikune-analyzer"
        RuntimeMode = "remote-sandbox"
        Description = "Linux Docker analyzer with remote Windows Sandbox runtime"
    }
}

function Write-Header {
    param([string]$Text)
    Write-Host "`n==================================================" -ForegroundColor $ColorPrimary
    Write-Host "  $Text" -ForegroundColor $ColorPrimary
    Write-Host "==================================================" -ForegroundColor $ColorPrimary
}

function Write-Step {
    param([string]$Text)
    Write-Host "`n[STEP] $Text" -ForegroundColor $ColorPrimary
    Write-Host "-----------------------------------------" -ForegroundColor $ColorPrimary
}

function Write-Info {
    param([string]$Text)
    Write-Host "  $Text" -ForegroundColor $ColorInfo
}

function Write-Success {
    param([string]$Text)
    Write-Host "[OK] " -ForegroundColor $ColorSuccess -NoNewline
    Write-Host $Text -ForegroundColor $ColorSuccess
}

function Write-Warning-Message {
    param([string]$Text)
    Write-Host "[WARN] " -ForegroundColor $ColorWarning -NoNewline
    Write-Host $Text -ForegroundColor $ColorWarning
}

function Write-Error-Message {
    param([string]$Text)
    Write-Host "[ERROR] " -ForegroundColor $ColorError -NoNewline
    Write-Host $Text -ForegroundColor $ColorError
}

function Require-Command {
    param(
        [string]$Name,
        [string]$InstallHint
    )
    if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
        Write-Error-Message "$Name not found"
        if ($InstallHint) { Write-Host "  $InstallHint" -ForegroundColor $ColorError }
        exit 1
    }
}

function Resolve-ComposeCommand {
    try {
        & docker compose version *> $null
        if ($LASTEXITCODE -eq 0) {
            return "docker"
        }
    } catch {
    }

    if (Get-Command docker-compose -ErrorAction SilentlyContinue) {
        return "docker-compose"
    }

    return $null
}

function Invoke-Compose {
    param([string[]]$Arguments)

    if ($script:ComposeCommand -eq "docker") {
        $cmdArgs = @("compose") + $Arguments
        & docker @cmdArgs
    } else {
        & docker-compose @Arguments
    }
}

function Convert-ProxyForDocker {
    param([string]$Proxy)
    if ([string]::IsNullOrWhiteSpace($Proxy)) { return "" }
    return ($Proxy -replace "://127\.0\.0\.1:", "://host.docker.internal:" -replace "://localhost:", "://host.docker.internal:")
}

function Convert-EndpointForHostAgent {
    param([string]$Endpoint)
    if ([string]::IsNullOrWhiteSpace($Endpoint)) { return "" }
    return ($Endpoint -replace "://host\.docker\.internal:", "://localhost:")
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
        Write-Warning-Message "Using plaintext remote runtime HTTP by explicit opt-in. Restrict it to a trusted VPN/isolated network."
        return
    }
    throw "Remote Host Agent endpoints must use HTTPS. Use -AllowInsecureRuntimeHttp only for an isolated trusted network."
}

function Assert-StrongRuntimeApiKey {
    param(
        [string]$Name,
        [AllowNull()][string]$Value
    )

    if ($Value -notmatch '^[\x21-\x7e]{32,}$') {
        throw "$Name must contain at least 32 printable non-space ASCII characters"
    }
}

function New-SecureApiKey {
    $bytes = [System.Security.Cryptography.RandomNumberGenerator]::GetBytes(32)
    return ([System.Convert]::ToHexString($bytes)).ToLowerInvariant()
}

function Assert-NoSecretEnvironment {
    param([string[]]$Names)
    foreach ($name in $Names) {
        if (-not [string]::IsNullOrWhiteSpace([Environment]::GetEnvironmentVariable($name, "Process"))) {
            throw "Secret environment alias must be cleared before running dependency or build commands: $name"
        }
    }
}

function Get-SystemProxy {
    try {
        $registryPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
        $proxyEnable = Get-ItemProperty -Path $registryPath -Name "ProxyEnable" -ErrorAction SilentlyContinue
        if ($proxyEnable.ProxyEnable -ne 1) { return $null }

        $proxyServer = Get-ItemProperty -Path $registryPath -Name "ProxyServer" -ErrorAction SilentlyContinue
        if (-not $proxyServer.ProxyServer) { return $null }

        $value = $proxyServer.ProxyServer.ToString()
        if ($value -match "=") {
            $http = ($value -split ";") | Where-Object { $_ -like "http=*" } | Select-Object -First 1
            if ($http) { return ($http -replace "^http=", "") }
        }
        return $value
    } catch {
        return $null
    }
}

function ConvertTo-TomlString {
    param([string]$Value)
    if ($null -eq $Value) { return '""' }
    $escaped = $Value.Replace('\', '\\').Replace('"', '\"')
    return '"' + $escaped + '"'
}

function ConvertTo-TomlArray {
    param([string[]]$Values)
    return "[" + (($Values | ForEach-Object { ConvertTo-TomlString $_ }) -join ", ") + "]"
}

function Set-CodexMcpConfig {
    param(
        [string]$ConfigFile,
        [hashtable]$ProfileConfig,
        [string]$AnalyzerApiKey
    )

    $configDir = Split-Path -Parent $ConfigFile
    if (-not (Test-Path $configDir)) {
        New-Item -ItemType Directory -Path $configDir -Force | Out-Null
    }

    $mcpArgs = @("stdio")

    $block = @"
[mcp_servers.rikune]
type = "stdio"
command = "rikune-agent"
startup_timeout_sec = 180
args = $(ConvertTo-TomlArray $mcpArgs)

[mcp_servers.rikune.env]
RIKUNE_DOCKER_CONTAINER = $(ConvertTo-TomlString $ProfileConfig.Container)
RIKUNE_ANALYZER_ENDPOINT = "http://localhost:18080"
RIKUNE_ANALYZER_API_KEY = $(ConvertTo-TomlString $AnalyzerApiKey)
"@

    if ($ProfileConfig.RuntimeMode -eq "remote-sandbox") {
        $agentHostEndpoint = Convert-EndpointForHostAgent $HostAgentEndpoint
        $block += @"
RIKUNE_VM_ENDPOINT = $(ConvertTo-TomlString $agentHostEndpoint)
RUNTIME_HOST_AGENT_ENDPOINT = $(ConvertTo-TomlString $HostAgentEndpoint)
RUNTIME_HOST_AGENT_API_KEY = $(ConvertTo-TomlString $HostAgentApiKey)
RUNTIME_API_KEY = $(ConvertTo-TomlString $RuntimeApiKey)
"@
    }

    $content = ""
    if (Test-Path $ConfigFile) {
        $content = Get-Content -Path $ConfigFile -Raw
        $content = [regex]::Replace($content, '(?ms)^\[mcp_servers\.rikune(?:\.env)?\]\r?\n.*?(?=^\[|\z)', '').TrimEnd()
    }

    if ([string]::IsNullOrWhiteSpace($content)) {
        $block | Set-Content -Path $ConfigFile -Encoding UTF8
    } else {
        ($content + "`r`n`r`n" + $block) | Set-Content -Path $ConfigFile -Encoding UTF8
    }
}

function Test-HttpHealth {
    param(
        [string]$Uri,
        [int]$TimeoutSec = 90
    )

    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    $lastError = $null
    while ((Get-Date) -lt $deadline) {
        try {
            $healthParams = @{
                Uri = $Uri
                UseBasicParsing = $true
                TimeoutSec = 5
            }
            if ((Get-Command Invoke-WebRequest).Parameters.ContainsKey("NoProxy")) {
                $healthParams.NoProxy = $true
            }
            $response = Invoke-WebRequest @healthParams
            if ($response.StatusCode -eq 200) {
                return @{ Ok = $true; Error = $null }
            }
            $lastError = "HTTP status $($response.StatusCode)"
        } catch {
            $lastError = $_.Exception.Message
        }
        Start-Sleep -Seconds 2
    }

    return @{ Ok = $false; Error = $lastError }
}

function Write-EnvFile {
    param(
        [string]$Path,
        [string]$Snapshot,
        [string]$Root,
        [hashtable]$ProfileConfig,
        [string]$BuildHttpProxy,
        [string]$BuildHttpsProxy,
        [string]$AnalyzerKey,
        [string]$HybridEndpoint,
        [string]$HybridHostKey,
        [string]$HybridRuntimeKey,
        [switch]$AllowInsecureRuntimeHttp
    )

    $writer = Join-Path $ProjectRoot "scripts/write-docker-runtime-env.mjs"
    if (-not (Test-Path $writer)) { throw "Docker runtime env writer not found: $writer" }

    $managedEnvironment = @{
        RIKUNE_DOCKER_ENV_SNAPSHOT_STDIN = "1"
        RIKUNE_DOCKER_ENV_PATH = $Path
        RIKUNE_DOCKER_ENV_DATA_ROOT = ($Root -replace "\\", "/")
        RIKUNE_DOCKER_ENV_PROFILE = $ProfileConfig.Generator
        RIKUNE_BUILD_HTTP_PROXY = $BuildHttpProxy
        RIKUNE_BUILD_HTTPS_PROXY = $BuildHttpsProxy
        RIKUNE_BUILD_NO_PROXY = $DefaultNoProxy
        RIKUNE_API_KEY = $AnalyzerKey
        RUNTIME_HOST_AGENT_ENDPOINT = $HybridEndpoint
        RUNTIME_HOST_AGENT_API_KEY = $HybridHostKey
        RUNTIME_API_KEY = $HybridRuntimeKey
        RIKUNE_ALLOW_INSECURE_RUNTIME_HTTP = $AllowInsecureRuntimeHttp.IsPresent.ToString().ToLowerInvariant()
    }
    $previousEnvironment = @{}
    foreach ($name in $managedEnvironment.Keys) {
        $previousEnvironment[$name] = [Environment]::GetEnvironmentVariable($name, "Process")
        [Environment]::SetEnvironmentVariable($name, [string]$managedEnvironment[$name], "Process")
    }
    try {
        $Snapshot | & node $writer
        if ($LASTEXITCODE -ne 0) {
            $nativeExitCode = $LASTEXITCODE
            throw (New-NativeInstallerFailure -Message "Secure Docker runtime env generation failed" -ExitCode $nativeExitCode)
        }
    } finally {
        foreach ($name in $managedEnvironment.Keys) {
            [Environment]::SetEnvironmentVariable($name, $previousEnvironment[$name], "Process")
        }
    }

}

function New-NativeInstallerFailure {
    param([string]$Message, [int]$ExitCode)

    $failure = [System.InvalidOperationException]::new($Message)
    $failure.Data["RIKUNE_NATIVE_EXIT_CODE"] = $ExitCode
    return $failure
}

function Get-PrivateEnvSnapshot {
    param([string]$Path)

    $writer = Join-Path $ProjectRoot "scripts/write-docker-runtime-env.mjs"
    if (-not (Test-Path $writer)) { throw "Docker runtime env writer not found: $writer" }
    $previousValue = [Environment]::GetEnvironmentVariable("RIKUNE_STAGE_DOCKER_ENV_PATH", "Process")
    try {
        [Environment]::SetEnvironmentVariable("RIKUNE_STAGE_DOCKER_ENV_PATH", $Path, "Process")
        $snapshotOutput = & node $writer
        if ($LASTEXITCODE -ne 0) {
            $nativeExitCode = $LASTEXITCODE
            throw (New-NativeInstallerFailure -Message "Secure Docker runtime env staging failed" -ExitCode $nativeExitCode)
        }
        return [string](@($snapshotOutput) -join '')
    } finally {
        [Environment]::SetEnvironmentVariable("RIKUNE_STAGE_DOCKER_ENV_PATH", $previousValue, "Process")
    }
}

function Invoke-PrivateEnvSnapshotOperation {
    param(
        [string]$EnvironmentName,
        [string]$Path,
        [string]$Snapshot,
        [string]$FailureMessage
    )

    $writer = Join-Path $ProjectRoot "scripts/write-docker-runtime-env.mjs"
    if (-not (Test-Path $writer)) { throw "Docker runtime env writer not found: $writer" }
    $previousValue = [Environment]::GetEnvironmentVariable($EnvironmentName, "Process")
    try {
        [Environment]::SetEnvironmentVariable($EnvironmentName, $Path, "Process")
        $Snapshot | & node $writer
        if ($LASTEXITCODE -ne 0) {
            $nativeExitCode = $LASTEXITCODE
            throw (New-NativeInstallerFailure -Message $FailureMessage -ExitCode $nativeExitCode)
        }
    } finally {
        [Environment]::SetEnvironmentVariable($EnvironmentName, $previousValue, "Process")
    }
}

function Remove-ExistingEnvFile {
    param([string]$Path, [string]$Snapshot)

    Invoke-PrivateEnvSnapshotOperation `
        -EnvironmentName "RIKUNE_REMOVE_PRIVATE_ENV_SNAPSHOT_PATH" `
        -Path $Path `
        -Snapshot $Snapshot `
        -FailureMessage "Secure removal of the staged Docker runtime env failed"
    Write-Info "Any prior protected Compose env was removed before dependency lifecycle commands; credentials will be rotated after build."
}

function Restore-ExistingEnvFile {
    param([string]$Path, [string]$Snapshot)

    Invoke-PrivateEnvSnapshotOperation `
        -EnvironmentName "RIKUNE_RESTORE_PRIVATE_ENV_PATH" `
        -Path $Path `
        -Snapshot $Snapshot `
        -FailureMessage "Secure restoration of the Docker runtime env failed"
}

function Configure-McpClient {
    param(
        [string]$Client,
        [hashtable]$ProfileConfig,
        [string]$AnalyzerApiKey
    )

    if ($Client -eq "None") { return }

    $config = @{
        mcpServers = @{
            rikune = @{
                command = "rikune-agent"
                args = @("stdio")
                env = @{
                    RIKUNE_DOCKER_CONTAINER = $ProfileConfig.Container
                    RIKUNE_ANALYZER_ENDPOINT = "http://localhost:18080"
                    RIKUNE_ANALYZER_API_KEY = $AnalyzerApiKey
                }
                timeout = 300000
            }
        }
    }

    if ($ProfileConfig.RuntimeMode -eq "remote-sandbox") {
        $agentHostEndpoint = Convert-EndpointForHostAgent $HostAgentEndpoint
        $config.mcpServers.rikune.env.RIKUNE_VM_ENDPOINT = $agentHostEndpoint
        $config.mcpServers.rikune.env.RUNTIME_HOST_AGENT_ENDPOINT = $HostAgentEndpoint
        $config.mcpServers.rikune.env.RUNTIME_HOST_AGENT_API_KEY = $HostAgentApiKey
        $config.mcpServers.rikune.env.RUNTIME_API_KEY = $RuntimeApiKey
    }

    switch ($Client) {
        "Claude" {
            $configDir = Join-Path $env:APPDATA "Claude"
            $configFile = Join-Path $configDir "claude_desktop_config.json"
        }
        "Copilot" {
            $configDir = Join-Path $env:APPDATA "GitHub Copilot"
            $configFile = Join-Path $configDir "mcp.json"
        }
        "Codex" {
            $configDir = Join-Path $env:USERPROFILE ".codex"
            $configFile = Join-Path $configDir "config.toml"
        }
        "Generic" {
            $configDir = Join-Path $DataRoot "config"
            $configFile = Join-Path $configDir "mcp-client-config.json"
        }
    }

    if ($Client -eq "Codex") {
        Set-CodexMcpConfig -ConfigFile $configFile -ProfileConfig $ProfileConfig -AnalyzerApiKey $AnalyzerApiKey
    } else {
        if (-not (Test-Path $configDir)) {
            New-Item -ItemType Directory -Path $configDir -Force | Out-Null
        }
        $config | ConvertTo-Json -Depth 10 | Set-Content -Path $configFile -Encoding UTF8
    }
    Write-Success "MCP client config written: $configFile"
}

function Read-DefaultString {
    param(
        [string]$Prompt,
        [string]$DefaultValue
    )

    $value = Read-Host "$Prompt [$DefaultValue]"
    if ([string]::IsNullOrWhiteSpace($value)) {
        return $DefaultValue
    }
    return $value
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

function Read-YesNo {
    param(
        [string]$Prompt,
        [bool]$DefaultValue = $false
    )

    $suffix = if ($DefaultValue) { "Y/n" } else { "y/N" }
    $value = Read-Host "$Prompt ($suffix)"
    if ([string]::IsNullOrWhiteSpace($value)) {
        return $DefaultValue
    }
    return ($value -eq "y" -or $value -eq "Y")
}

function Read-Profile {
    Write-Host ""
    Write-Host "Select deployment profile:" -ForegroundColor $ColorPrimary
    Write-Host "  [1] static  - safe default, static/offline analyzer only" -ForegroundColor $ColorInfo
    Write-Host "  [2] hybrid  - Docker analyzer + Windows Host Agent / Sandbox" -ForegroundColor $ColorInfo
    Write-Host "  [3] full    - heavier all-in-one Linux toolchain image" -ForegroundColor $ColorInfo
    $choice = Read-Host "Select (default: 1)"
    switch ($choice) {
        "2" { return "hybrid" }
        "3" { return "full" }
        default { return "static" }
    }
}

function Read-ClientChoice {
    Write-Host ""
    Write-Host "Configure an MCP client now?" -ForegroundColor $ColorPrimary
    Write-Host "  [0] Skip" -ForegroundColor $ColorInfo
    Write-Host "  [1] Claude Desktop" -ForegroundColor $ColorInfo
    Write-Host "  [2] GitHub Copilot" -ForegroundColor $ColorInfo
    Write-Host "  [3] Codex" -ForegroundColor $ColorInfo
    Write-Host "  [4] Generic file under DataRoot/config" -ForegroundColor $ColorInfo
    $choice = Read-Host "Select (default: 0)"
    switch ($choice) {
        "1" { return "Claude" }
        "2" { return "Copilot" }
        "3" { return "Codex" }
        "4" { return "Generic" }
        default { return "None" }
    }
}

try { Clear-Host } catch { }
Write-Header "Rikune Docker Installer"

$ProjectRoot = (Resolve-Path $ProjectRoot).Path
$PromptMode = $Interactive -or ($PSBoundParameters.Count -eq 0)

if ($PromptMode) {
    Write-Host "Guided mode is active. Press Enter to accept defaults." -ForegroundColor $ColorInfo
    $Profile = Read-Profile
    $DataRoot = Read-DefaultString "Persistent data root" $DataRoot
    $ResetData = Read-YesNo "Delete and recreate the data root" $false

    if (Read-YesNo "Configure build proxy" $false) {
        $detectedProxy = Get-SystemProxy
        if ($detectedProxy) {
            if (-not ($detectedProxy -match "^\w+://")) { $detectedProxy = "http://$detectedProxy" }
            Write-Info "Detected Windows proxy: $detectedProxy"
            $HttpProxy = Read-DefaultString "HTTP proxy" $detectedProxy
        } else {
            $HttpProxy = Read-DefaultString "HTTP proxy" "http://127.0.0.1:7890"
        }
        $HttpsProxy = Read-DefaultString "HTTPS proxy" $HttpProxy
    }

    if ($Profile -eq "hybrid") {
        $HostAgentEndpoint = Read-DefaultString "Windows Host Agent endpoint" "http://host.docker.internal:18082"
        $HostAgentApiKey = Read-SecretString "Windows Host Agent API key"
        $RuntimeApiKey = Read-SecretString "Distinct Runtime Node API key"
    }

    $SkipBuild = Read-YesNo "Skip Docker image build" $false
    $SkipStart = Read-YesNo "Skip starting the service" $false
    $ConfigureClient = Read-ClientChoice
}

$secretEnvironmentAliases = @(
    "RIKUNE_API_KEY",
    "RIKUNE_ANALYZER_API_KEY",
    "RUNTIME_HOST_AGENT_API_KEY",
    "HOST_AGENT_API_KEY",
    "HOST_AGENT_RUNTIME_API_KEY",
    "RUNTIME_API_KEY",
    "RIKUNE_HOST_AGENT_API_KEY",
    "RIKUNE_RUNTIME_API_KEY",
    "RIKUNE_RUNTIME_NODE_API_KEY"
)
if ([string]::IsNullOrWhiteSpace($HostAgentEndpoint)) {
    $HostAgentEndpoint = $env:RUNTIME_HOST_AGENT_ENDPOINT
}
if ([string]::IsNullOrWhiteSpace($HostAgentApiKey)) {
    $HostAgentApiKey = $env:RUNTIME_HOST_AGENT_API_KEY
}
if ([string]::IsNullOrWhiteSpace($HostAgentApiKey)) {
    $HostAgentApiKey = $env:HOST_AGENT_API_KEY
}
if ([string]::IsNullOrWhiteSpace($RuntimeApiKey)) {
    $RuntimeApiKey = $env:RUNTIME_API_KEY
}
$AnalyzerApiKey = if (-not [string]::IsNullOrWhiteSpace($env:RIKUNE_API_KEY)) {
    $env:RIKUNE_API_KEY
} elseif (-not [string]::IsNullOrWhiteSpace($env:RIKUNE_ANALYZER_API_KEY)) {
    $env:RIKUNE_ANALYZER_API_KEY
} else {
    New-SecureApiKey
}
foreach ($name in $secretEnvironmentAliases) {
    [Environment]::SetEnvironmentVariable($name, $null, "Process")
}
[Environment]::SetEnvironmentVariable("RIKUNE_REMOVE_PRIVATE_ENV_PATH", $null, "Process")
Assert-NoSecretEnvironment -Names $secretEnvironmentAliases
Assert-StrongRuntimeApiKey -Name "Analyzer API key" -Value $AnalyzerApiKey

$profileConfig = $Profiles[$Profile]
$composePath = Join-Path $ProjectRoot $profileConfig.Compose
$envFile = Join-Path $ProjectRoot ".docker-runtime.env"

Write-Info "Profile: $Profile - $($profileConfig.Description)"
Write-Info "Project root: $ProjectRoot"
Write-Info "Data root: $DataRoot"

Write-Step "Checking prerequisites"
Require-Command "docker" "Install Docker Desktop: https://www.docker.com/products/docker-desktop/"
Require-Command "node" "Install Node.js 22.9+: https://nodejs.org/"
Require-Command "npm" "Install npm with Node.js 22.9+"
$nodeVersion = (node --version).Trim()
$nodeParts = ($nodeVersion -replace '^v','').Split('.')
$nodeMajor = [int]$nodeParts[0]
$nodeMinor = [int]$nodeParts[1]
if ($nodeMajor -lt 22 -or ($nodeMajor -eq 22 -and $nodeMinor -lt 9)) {
    throw "Node.js $nodeVersion is too old (need 22.9+)"
}

try {
    & docker info *> $null
    if ($LASTEXITCODE -ne 0) { throw "docker info failed" }
    Write-Success "Docker daemon is running"
} catch {
    Write-Error-Message "Docker is not running. Start Docker Desktop and retry."
    exit 1
}

$script:ComposeCommand = Resolve-ComposeCommand
if (-not $script:ComposeCommand) {
    Write-Error-Message "Docker Compose was not found"
    exit 1
}
Write-Success "Docker Compose available: $(if ($script:ComposeCommand -eq 'docker') { 'docker compose' } else { 'docker-compose' })"
Write-Success "Node.js: $nodeVersion"
Write-Success "npm: $((npm --version).Trim())"

$privateEnvSnapshot = $null
$privateEnvTransactionActive = $false
$privateEnvTransactionCommitted = $false
$privateEnvFailure = $null
$privateEnvFailureExitCode = 1
try {
    $privateEnvSnapshot = Get-PrivateEnvSnapshot -Path $envFile
    $privateEnvTransactionActive = $true
    Remove-ExistingEnvFile -Path $envFile -Snapshot $privateEnvSnapshot

Write-Step "Resolving proxy and runtime settings"

if ($UseProxy -and [string]::IsNullOrWhiteSpace($HttpProxy) -and [string]::IsNullOrWhiteSpace($HttpsProxy)) {
    $systemProxy = Get-SystemProxy
    if ($systemProxy) {
        if (-not ($systemProxy -match "^\w+://")) { $systemProxy = "http://$systemProxy" }
        $HttpProxy = $systemProxy
        $HttpsProxy = $systemProxy
        Write-Success "Using Windows system proxy: $systemProxy"
    } else {
        Write-Warning-Message "UseProxy was set, but no Windows system proxy was detected"
    }
}

if ([string]::IsNullOrWhiteSpace($HttpsProxy)) { $HttpsProxy = $HttpProxy }
$buildHttpProxy = Convert-ProxyForDocker $HttpProxy
$buildHttpsProxy = Convert-ProxyForDocker $HttpsProxy

if ([string]::IsNullOrWhiteSpace($buildHttpProxy) -and [string]::IsNullOrWhiteSpace($buildHttpsProxy)) {
    Write-Info "Docker build proxy args will be cleared to avoid inherited localhost proxy failures"
} else {
    Write-Info "Docker build HTTP proxy: $buildHttpProxy"
    Write-Info "Docker build HTTPS proxy: $buildHttpsProxy"
}

if (-not [string]::IsNullOrWhiteSpace($HttpProxy) -or -not [string]::IsNullOrWhiteSpace($HttpsProxy)) {
    if ([string]::IsNullOrWhiteSpace($HttpsProxy)) { $HttpsProxy = $HttpProxy }
    if ([string]::IsNullOrWhiteSpace($HttpProxy)) { $HttpProxy = $HttpsProxy }

    $env:HTTP_PROXY = $HttpProxy
    $env:http_proxy = $HttpProxy
    $env:HTTPS_PROXY = $HttpsProxy
    $env:https_proxy = $HttpsProxy
    $env:NO_PROXY = $DefaultNoProxy
    $env:no_proxy = $DefaultNoProxy
    Write-Info "Process proxy env set for npm and Docker CLI: $HttpsProxy"
}

if ($Profile -eq "hybrid") {
    if (
        [string]::IsNullOrWhiteSpace($HostAgentEndpoint) -or
        [string]::IsNullOrWhiteSpace($HostAgentApiKey) -or
        [string]::IsNullOrWhiteSpace($RuntimeApiKey)
    ) {
        Write-Error-Message "Hybrid profile requires an endpoint plus distinct Host Agent and Runtime Node API keys"
        Write-Info "Set RUNTIME_HOST_AGENT_API_KEY and RUNTIME_API_KEY through a protected process environment."
        exit 1
    }
    Assert-StrongRuntimeApiKey -Name "Host Agent API key" -Value $HostAgentApiKey
    Assert-StrongRuntimeApiKey -Name "Runtime Node API key" -Value $RuntimeApiKey
    if ($HostAgentApiKey -ceq $RuntimeApiKey) {
        throw "Host Agent and Runtime Node API keys must be distinct"
    }
    Assert-SecureRuntimeEndpoint -Endpoint $HostAgentEndpoint -AllowInsecure:$AllowInsecureRuntimeHttp

    Write-Success "Hybrid Host Agent endpoint: $HostAgentEndpoint"
}

Write-Step "Preparing persistent storage"

if (-not [System.IO.Path]::IsPathRooted($DataRoot)) {
    $DataRoot = Join-Path $ProjectRoot $DataRoot
}

if ($ResetData -and (Test-Path $DataRoot)) {
    $resolvedDataRoot = (Resolve-Path $DataRoot).Path
    $root = [System.IO.Path]::GetPathRoot($resolvedDataRoot)
    if ($resolvedDataRoot -eq $root) {
        Write-Error-Message "Refusing to delete drive root: $resolvedDataRoot"
        exit 1
    }
    Write-Warning-Message "Deleting data root because -ResetData was specified: $resolvedDataRoot"
    Remove-Item -LiteralPath $resolvedDataRoot -Recurse -Force
}

$directories = @("samples", "workspaces", "data", "cache", "logs", "storage", "ghidra-projects", "ghidra-logs", "qiling-rootfs", "config")
foreach ($dir in $directories) {
    $path = Join-Path $DataRoot $dir
    if (-not (Test-Path $path)) {
        New-Item -ItemType Directory -Path $path -Force | Out-Null
        if ($EnableVerbose) { Write-Info "Created: $path" }
    }
}
Write-Success "Persistent directories ready"

Write-Step "Building project and generating Docker profile"

Push-Location $ProjectRoot
try {
    Write-Info "Installing npm dependencies from package-lock.json..."
    & npm ci --include=dev
    if ($LASTEXITCODE -ne 0) {
        $nativeExitCode = $LASTEXITCODE
        throw (New-NativeInstallerFailure -Message "npm ci --include=dev failed" -ExitCode $nativeExitCode)
    }

    Write-Info "Building TypeScript and workspace packages..."
    & npm run build
    if ($LASTEXITCODE -ne 0) {
        $nativeExitCode = $LASTEXITCODE
        throw (New-NativeInstallerFailure -Message "npm run build failed" -ExitCode $nativeExitCode)
    }

    Write-Info "Generating Docker files for profile '$Profile'..."
    & node scripts/generate-docker.mjs "--profile=$($profileConfig.Generator)"
    if ($LASTEXITCODE -ne 0) {
        $nativeExitCode = $LASTEXITCODE
        throw (New-NativeInstallerFailure -Message "Docker profile generation failed" -ExitCode $nativeExitCode)
    }

    if (-not (Test-Path $composePath)) {
        throw "Expected Compose file not found: $composePath"
    }
    Write-Success "Generated $($profileConfig.Compose)"
} catch {
    throw
} finally {
    Pop-Location
}

Assert-NoSecretEnvironment -Names $secretEnvironmentAliases
Write-EnvFile `
    -Path $envFile `
    -Snapshot $privateEnvSnapshot `
    -Root $DataRoot `
    -ProfileConfig $profileConfig `
    -BuildHttpProxy $buildHttpProxy `
    -BuildHttpsProxy $buildHttpsProxy `
    -AnalyzerKey $AnalyzerApiKey `
    -HybridEndpoint $HostAgentEndpoint `
    -HybridHostKey $HostAgentApiKey `
    -HybridRuntimeKey $RuntimeApiKey `
    -AllowInsecureRuntimeHttp:$AllowInsecureRuntimeHttp
    $privateEnvTransactionCommitted = $true
    $privateEnvSnapshot = $null
} catch {
    $privateEnvFailure = $_
    if ($_.Exception.Data.Contains("RIKUNE_NATIVE_EXIT_CODE")) {
        $privateEnvFailureExitCode = [int]$_.Exception.Data["RIKUNE_NATIVE_EXIT_CODE"]
    }
} finally {
    if ($privateEnvTransactionActive -and -not $privateEnvTransactionCommitted) {
        try {
            Restore-ExistingEnvFile -Path $envFile -Snapshot $privateEnvSnapshot
        } catch {
            Write-Error-Message "Failed to restore the protected Compose env after installer failure: $($_.Exception.Message)"
        }
    }
    $privateEnvSnapshot = $null
}
if ($null -ne $privateEnvFailure) {
    Write-Error-Message $privateEnvFailure.Exception.Message
    exit $privateEnvFailureExitCode
}
Write-Success "Compose env file: $envFile"

Write-Step "Docker Compose"

Push-Location $ProjectRoot
try {
    $baseArgs = @("--env-file", ".docker-runtime.env", "-f", $profileConfig.Compose)

    if ($SkipBuild) {
        Write-Warning-Message "Skipping Docker build"
    } else {
        Write-Info "Building image: $($profileConfig.Image)"
        Invoke-Compose ($baseArgs + @("build", $profileConfig.Service))
        if ($LASTEXITCODE -ne 0) { throw "Docker Compose build failed" }
        Write-Success "Docker image built: $($profileConfig.Image)"
    }

    if ($SkipStart) {
        Write-Warning-Message "Skipping service start"
    } else {
        Write-Info "Starting service: $($profileConfig.Service)"
        Invoke-Compose ($baseArgs + @("up", "-d", $profileConfig.Service))
        if ($LASTEXITCODE -ne 0) { throw "Docker Compose up failed" }
        Write-Success "Service started: $($profileConfig.Container)"
    }
} catch {
    Write-Error-Message $_.Exception.Message
    exit 1
} finally {
    Pop-Location
}

Write-Step "Health check"

if ($SkipStart) {
    Write-Warning-Message "Health check skipped because -SkipStart was specified"
} else {
    Write-Info "Waiting for HTTP API to become ready..."
    $health = Test-HttpHealth -Uri "http://localhost:18080/api/v1/health" -TimeoutSec 90
    if ($health.Ok) {
        Write-Success "HTTP API health check passed"
    } else {
        Write-Info "Check logs with: docker logs $($profileConfig.Container)"
        throw "HTTP API health check failed: $($health.Error)"
    }
    if ($Profile -eq "hybrid") {
        Write-Info "Verifying container-to-HostAgent reachability and the full sandbox lifecycle..."
        & docker exec $profileConfig.Container node /app/scripts/verify-hybrid-runtime.mjs
        if ($LASTEXITCODE -ne 0) {
            throw "Hybrid container runtime lifecycle verification failed"
        }
        Write-Success "Hybrid Host Agent and Runtime Node lifecycle verified from the analyzer container"
    }
}

Configure-McpClient -Client $ConfigureClient -ProfileConfig $profileConfig -AnalyzerApiKey $AnalyzerApiKey

$installInfo = @{
    InstallDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Profile = $Profile
    DataRoot = $DataRoot
    ProjectRoot = $ProjectRoot
    ComposeFile = $profileConfig.Compose
    Service = $profileConfig.Service
    Container = $profileConfig.Container
    Image = $profileConfig.Image
    RuntimeMode = $profileConfig.RuntimeMode
    ComposeEnvFile = $envFile
}
$installInfo | ConvertTo-Json -Depth 5 | Set-Content -Path (Join-Path $DataRoot "install-info.json") -Encoding UTF8

Write-Header "Docker Install Complete"
Write-Host "Profile:      $Profile" -ForegroundColor $ColorSuccess
Write-Host "Image:        $($profileConfig.Image)" -ForegroundColor $ColorSuccess
Write-Host "Container:    $($profileConfig.Container)" -ForegroundColor $ColorSuccess
Write-Host "Compose file: $($profileConfig.Compose)" -ForegroundColor $ColorSuccess
Write-Host "Data root:    $DataRoot" -ForegroundColor $ColorSuccess
Write-Host ""
Write-Host "Useful commands:" -ForegroundColor $ColorPrimary
Write-Host "  docker compose --env-file .docker-runtime.env -f $($profileConfig.Compose) ps"
Write-Host "  docker compose --env-file .docker-runtime.env -f $($profileConfig.Compose) logs -f $($profileConfig.Service)"
Write-Host "  docker compose --env-file .docker-runtime.env -f $($profileConfig.Compose) down"
Write-Host ""
Write-Host "Dashboard: http://localhost:18080/dashboard" -ForegroundColor $ColorPrimary
