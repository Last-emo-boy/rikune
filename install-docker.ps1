# Rikune - Docker profile installer
# Requires: PowerShell 7+, Docker Desktop / Docker Engine, Node.js 22+

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

    [Parameter(HelpMessage = "Windows Host Agent API key for hybrid profile")]
    [string]$HostAgentApiKey,

    [Parameter(HelpMessage = "Windows Runtime Node API key for hybrid profile")]
    [string]$RuntimeApiKey,

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

function Write-EnvFile {
    param(
        [string]$Path,
        [string]$Root,
        [hashtable]$ProfileConfig,
        [string]$BuildHttpProxy,
        [string]$BuildHttpsProxy,
        [string]$HybridEndpoint,
        [string]$HybridHostKey,
        [string]$HybridRuntimeKey
    )

    $rootForCompose = $Root -replace "\\", "/"
    $lines = @(
        "# Rikune Docker runtime environment - generated by install-docker.ps1",
        "RIKUNE_DATA_ROOT=$rootForCompose",
        "RIKUNE_BUILD_HTTP_PROXY=$BuildHttpProxy",
        "RIKUNE_BUILD_HTTPS_PROXY=$BuildHttpsProxy",
        "RIKUNE_BUILD_NO_PROXY=$DefaultNoProxy"
    )

    if ($ProfileConfig.RuntimeMode -eq "remote-sandbox") {
        $lines += "RUNTIME_HOST_AGENT_ENDPOINT=$HybridEndpoint"
        $lines += "RUNTIME_HOST_AGENT_API_KEY=$HybridHostKey"
        $lines += "RUNTIME_API_KEY=$HybridRuntimeKey"
    }

    $lines | Set-Content -Path $Path -Encoding UTF8
}

function Configure-McpClient {
    param(
        [string]$Client,
        [hashtable]$ProfileConfig
    )

    if ($Client -eq "None") { return }

    $config = @{
        mcpServers = @{
            rikune = @{
                command = "docker"
                args = @(
                    "exec",
                    "-i",
                    $ProfileConfig.Container,
                    "node",
                    "dist/index.js"
                )
                env = @{
                    NODE_ENV = "production"
                    PYTHONUNBUFFERED = "1"
                    WORKSPACE_ROOT = "/app/workspaces"
                    DB_PATH = "/app/data/database.db"
                    CACHE_ROOT = "/app/cache"
                    GHIDRA_PROJECT_ROOT = "/ghidra-projects"
                    GHIDRA_LOG_ROOT = "/ghidra-logs"
                }
                timeout = 300000
            }
        }
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
            $configFile = Join-Path $configDir "mcp.json"
        }
        "Generic" {
            $configDir = Join-Path $DataRoot "config"
            $configFile = Join-Path $configDir "mcp-client-config.json"
        }
    }

    if (-not (Test-Path $configDir)) {
        New-Item -ItemType Directory -Path $configDir -Force | Out-Null
    }
    $config | ConvertTo-Json -Depth 10 | Set-Content -Path $configFile -Encoding UTF8
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
        $HostAgentEndpoint = Read-DefaultString "Windows Host Agent endpoint" "http://192.168.1.10:18082"
        $HostAgentApiKey = Read-Host "Windows Host Agent API key"
        $RuntimeApiKey = Read-DefaultString "Runtime Node API key" $HostAgentApiKey
    }

    $SkipBuild = Read-YesNo "Skip Docker image build" $false
    $SkipStart = Read-YesNo "Skip starting the service" $false
    $ConfigureClient = Read-ClientChoice
}

$profileConfig = $Profiles[$Profile]
$composePath = Join-Path $ProjectRoot $profileConfig.Compose
$envFile = Join-Path $ProjectRoot ".docker-runtime.env"

Write-Info "Profile: $Profile - $($profileConfig.Description)"
Write-Info "Project root: $ProjectRoot"
Write-Info "Data root: $DataRoot"

Write-Step "Checking prerequisites"
Require-Command "docker" "Install Docker Desktop: https://www.docker.com/products/docker-desktop/"
Require-Command "node" "Install Node.js 22+: https://nodejs.org/"
Require-Command "npm" "Install npm with Node.js 22+"

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
Write-Success "Node.js: $((node --version).Trim())"
Write-Success "npm: $((npm --version).Trim())"

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
    if ([string]::IsNullOrWhiteSpace($HostAgentEndpoint)) { $HostAgentEndpoint = $env:RUNTIME_HOST_AGENT_ENDPOINT }
    if ([string]::IsNullOrWhiteSpace($HostAgentApiKey)) { $HostAgentApiKey = $env:RUNTIME_HOST_AGENT_API_KEY }
    if ([string]::IsNullOrWhiteSpace($HostAgentApiKey)) { $HostAgentApiKey = $env:HOST_AGENT_API_KEY }
    if ([string]::IsNullOrWhiteSpace($RuntimeApiKey)) { $RuntimeApiKey = $env:RUNTIME_API_KEY }
    if ([string]::IsNullOrWhiteSpace($RuntimeApiKey)) { $RuntimeApiKey = $HostAgentApiKey }

    if ([string]::IsNullOrWhiteSpace($HostAgentEndpoint) -or [string]::IsNullOrWhiteSpace($HostAgentApiKey)) {
        Write-Error-Message "Hybrid profile requires -HostAgentEndpoint and -HostAgentApiKey"
        Write-Info "Example: .\install-docker.ps1 -Profile hybrid -HostAgentEndpoint http://192.168.1.10:18082 -HostAgentApiKey <key>"
        exit 1
    }

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

Write-EnvFile `
    -Path $envFile `
    -Root $DataRoot `
    -ProfileConfig $profileConfig `
    -BuildHttpProxy $buildHttpProxy `
    -BuildHttpsProxy $buildHttpsProxy `
    -HybridEndpoint $HostAgentEndpoint `
    -HybridHostKey $HostAgentApiKey `
    -HybridRuntimeKey $RuntimeApiKey
Write-Success "Compose env file: $envFile"

Write-Step "Building project and generating Docker profile"

Push-Location $ProjectRoot
try {
    Write-Info "Installing npm dependencies..."
    & npm install
    if ($LASTEXITCODE -ne 0) { throw "npm install failed" }

    Write-Info "Building TypeScript and workspace packages..."
    & npm run build
    if ($LASTEXITCODE -ne 0) { throw "npm run build failed" }

    Write-Info "Generating Docker files for profile '$Profile'..."
    & node scripts/generate-docker.mjs "--profile=$($profileConfig.Generator)"
    if ($LASTEXITCODE -ne 0) { throw "Docker profile generation failed" }

    if (-not (Test-Path $composePath)) {
        throw "Expected Compose file not found: $composePath"
    }
    Write-Success "Generated $($profileConfig.Compose)"
} catch {
    Write-Error-Message $_.Exception.Message
    exit 1
} finally {
    Pop-Location
}

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
    Start-Sleep -Seconds 3
    try {
        $healthParams = @{
            Uri = "http://localhost:18080/api/v1/health"
            UseBasicParsing = $true
            TimeoutSec = 10
        }
        if ((Get-Command Invoke-WebRequest).Parameters.ContainsKey("NoProxy")) {
            $healthParams.NoProxy = $true
        }
        $response = Invoke-WebRequest @healthParams
        if ($response.StatusCode -eq 200) {
            Write-Success "HTTP API health check passed"
        } else {
            Write-Warning-Message "HTTP API returned status $($response.StatusCode)"
        }
    } catch {
        Write-Warning-Message "HTTP API health check failed: $($_.Exception.Message)"
        Write-Info "Check logs with: docker logs $($profileConfig.Container)"
    }
}

Configure-McpClient -Client $ConfigureClient -ProfileConfig $profileConfig

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
