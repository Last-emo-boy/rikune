# Rikune — Windows Runtime Install Script
# Installs and starts the Windows Host Agent + Runtime Node for sandbox-based PE analysis.
# Requires: PowerShell 7+, Windows 10/11 Pro or Enterprise, Windows Sandbox feature enabled
# Encoding: UTF-8 without BOM

param(
    [Parameter(HelpMessage="Run Host Agent in headless mode (no interactive prompts)")]
    [switch]$Headless,

    [Parameter(HelpMessage="Register Host Agent as a Windows Service via pm2 or node-windows")]
    [switch]$Service,

    [Parameter(HelpMessage="Skip npm build step")]
    [switch]$SkipBuild,

    [Parameter(HelpMessage="Workspace root for sandbox temp dirs, inbox/outbox")]
    [string]$WorkspaceRoot,

    [Parameter(HelpMessage="Host Agent HTTP port")]
    [int]$Port = 18082,

    [Parameter(HelpMessage="Project root directory")]
    [string]$ProjectRoot = $PSScriptRoot
)

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

function Test-IsAdmin {
    return ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
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

# ─────────────────────────────────────────────────────────────────────────────
# Main Script
# ─────────────────────────────────────────────────────────────────────────────
if (-not $Headless) { Clear-Host }
Write-Header "Rikune — Windows Runtime Install"

Write-Host "This script will:" -ForegroundColor $ColorInfo
Write-Host "  1. Check Windows version & Windows Sandbox feature" -ForegroundColor $ColorInfo
Write-Host "  2. Check Node.js, npm, and Python" -ForegroundColor $ColorInfo
Write-Host "  3. Build Runtime Node and Windows Host Agent" -ForegroundColor $ColorInfo
Write-Host "  4. Create workspace, inbox/outbox directories" -ForegroundColor $ColorInfo
Write-Host "  5. Generate Host Agent configuration (.env.runtime-windows)" -ForegroundColor $ColorInfo
Write-Host "  6. Start the Host Agent (foreground or service)" -ForegroundColor $ColorInfo
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

# Check Windows Sandbox feature
$sandboxFeature = Get-WindowsOptionalFeature -Online -FeatureName "Containers-DisposableClient" -ErrorAction SilentlyContinue
if (-not $sandboxFeature -or $sandboxFeature.State -ne "Enabled") {
    Write-Warning-Message "Windows Sandbox feature is not enabled"
    if (Test-IsAdmin) {
        Write-Info "Attempting to enable Windows Sandbox..."
        $enableResult = Enable-WindowsOptionalFeature -Online -FeatureName "Containers-DisposableClient" -NoRestart -All -ErrorAction SilentlyContinue
        if ($enableResult -and $enableResult.RestartNeeded -eq $true) {
            Exit-WithError "Windows Sandbox was enabled, but a system restart is required before continuing."
        }
        $sandboxFeature = Get-WindowsOptionalFeature -Online -FeatureName "Containers-DisposableClient" -ErrorAction SilentlyContinue
        if (-not $sandboxFeature -or $sandboxFeature.State -ne "Enabled") {
            Exit-WithError "Failed to enable Windows Sandbox automatically. Please enable it manually via 'Turn Windows features on or off'."
        }
        Write-Success "Windows Sandbox enabled"
    } else {
        Exit-WithError "Windows Sandbox is not enabled. Please run as Administrator to auto-enable, or enable it manually via 'Turn Windows features on or off'."
    }
} else {
    Write-Success "Windows Sandbox feature is enabled"
}

# Check Hyper-V (optional but recommended)
$hypervFeature = Get-WindowsOptionalFeature -Online -FeatureName "Microsoft-Hyper-V-All" -ErrorAction SilentlyContinue
if ($hypervFeature -and $hypervFeature.State -eq "Enabled") {
    Write-Success "Hyper-V is enabled"
} else {
    Write-Warning-Message "Hyper-V is not enabled. Windows Sandbox can still run on some systems without it, but performance may be reduced."
}

# =============================================================================
# Step 2: Check Required Tools
# =============================================================================
Write-Step "Checking Required Tools"

# Node.js
if (-not (Get-Command node -ErrorAction SilentlyContinue)) {
    Exit-WithError "Node.js not found. Install Node.js 22+ from https://nodejs.org/"
}
$nodeVersion = (node --version).Trim()
$nodeMajor = [int]($nodeVersion -replace '^v','').Split('.')[0]
if ($nodeMajor -lt 22) {
    Exit-WithError "Node.js $nodeVersion is too old (need 22+)"
}
Write-Success "Node.js: $nodeVersion"

# npm
if (-not (Get-Command npm -ErrorAction SilentlyContinue)) {
    Exit-WithError "npm not found"
}
Write-Success "npm: $((npm --version).Trim())"

# Python
$pythonCmd = $null
foreach ($cmd in @('python', 'python3', 'py')) {
    if (Get-Command $cmd -ErrorAction SilentlyContinue) {
        try {
            $ver = & $cmd --version 2>&1
            if ($ver -match '3\.(1[1-9]|[2-9][0-9])') {
                $pythonCmd = $cmd
                break
            }
        } catch {}
    }
}
if (-not $pythonCmd) {
    Write-Warning-Message "Python 3.11+ not found in PATH"
    if (-not $Headless) {
        $installPy = Read-Host "Attempt to install Python 3.11 from Microsoft Store? (y/N)"
        if ($installPy -eq 'y' -or $installPy -eq 'Y') {
            Start-Process "ms-windows-store://pdp/?productid=9NRWMJP3717K" -Wait
            Exit-WithError "Please complete Python installation in the Microsoft Store, then re-run this script."
        }
    }
    Exit-WithError "Python 3.11+ is required. Install from https://www.python.org/downloads/ or Microsoft Store."
}
$pyVersion = (& $pythonCmd --version 2>&1).ToString().Trim()
Write-Success "Python: $pyVersion (command: $pythonCmd)"

# =============================================================================
# Step 3: Install npm Dependencies & Build
# =============================================================================
Write-Step "Installing npm Dependencies & Building"

Push-Location $ProjectRoot
try {
    Write-Info "Running npm install (root)..."
    npm install 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Exit-WithError "npm install failed"
    }
    Write-Success "Root npm dependencies installed"

    if (-not $SkipBuild) {
        Write-Info "Building Runtime Node..."
        npm run build:runtime 2>&1 | Out-Null
        if ($LASTEXITCODE -ne 0) { Exit-WithError "Build of runtime-node failed" }
        Write-Success "Runtime Node built"

        Write-Info "Building Windows Host Agent..."
        npm run build:host-agent 2>&1 | Out-Null
        if ($LASTEXITCODE -ne 0) { Exit-WithError "Build of windows-host-agent failed" }
        Write-Success "Windows Host Agent built"
    } else {
        Write-Warning-Message "Skipped npm build step"
    }
} catch {
    Exit-WithError "Build error: $($_.Exception.Message)"
} finally {
    Pop-Location
}

# =============================================================================
# Step 4: Create Workspace Directories
# =============================================================================
Write-Step "Creating Workspace Directories"

if (-not $WorkspaceRoot) {
    $WorkspaceRoot = "$env:LOCALAPPDATA\Rikune\Runtime"
}
$WorkspaceRoot = (Resolve-Path -Path $WorkspaceRoot -ErrorAction SilentlyContinue).Path
if (-not $WorkspaceRoot) {
    New-Item -ItemType Directory -Path "$env:LOCALAPPDATA\Rikune\Runtime" -Force | Out-Null
    $WorkspaceRoot = "$env:LOCALAPPDATA\Rikune\Runtime"
}

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

$apiKey = -join ((48..57) + (65..90) + (97..122) | Get-Random -Count 32 | ForEach-Object { [char]$_ })
$envFile = Join-Path $ProjectRoot ".env.runtime-windows"

$envContent = @"
# Rikune Windows Runtime Environment — generated by install-runtime-windows.ps1
# This file configures the Windows Host Agent and the Runtime Node inside Windows Sandbox.

# Host Agent settings
HOST_AGENT_PORT=$Port
HOST_AGENT_API_KEY=$apiKey
HOST_AGENT_RUNTIME_API_KEY=$apiKey
HOST_AGENT_WORKSPACE=$WorkspaceRoot

# Optional: restrict CORS origin for Runtime Node (distributed mode)
# RUNTIME_CORS_ORIGIN=http://your-linux-analyzer-ip:18080

# Optional: allow unsafe runtime outside Windows Sandbox (DANGEROUS — only for dev)
# ALLOW_UNSAFE_RUNTIME=true
"@

$envContent | Set-Content $envFile -Encoding UTF8
Write-Success "Environment file: $envFile"
Write-Info "API Key: $apiKey"

# =============================================================================
# Step 6: Start Host Agent
# =============================================================================
Write-Step "Starting Windows Host Agent"

$hostAgentEntry = Join-Path $ProjectRoot "packages\windows-host-agent\dist\index.js"
if (-not (Test-Path $hostAgentEntry)) {
    Exit-WithError "Host Agent entry not found at $hostAgentEntry. Build may have failed."
}

# Load env for current process
$env:HOST_AGENT_PORT = "$Port"
$env:HOST_AGENT_API_KEY = "$apiKey"
$env:HOST_AGENT_RUNTIME_API_KEY = "$apiKey"
$env:HOST_AGENT_WORKSPACE = "$WorkspaceRoot"

if ($Service) {
    Write-Info "Installing Host Agent as a background service..."

    # Prefer pm2
    $pm2 = Get-Command pm2 -ErrorAction SilentlyContinue
    if ($pm2) {
        Write-Info "Using pm2 to manage service..."
        & pm2 delete "rikune-host-agent" 2>&1 | Out-Null
        & pm2 start "node" --name "rikune-host-agent" -- "$hostAgentEntry" --cwd "$ProjectRoot" 2>&1 | Out-Null
        & pm2 save 2>&1 | Out-Null
        if ($LASTEXITCODE -ne 0) {
            Exit-WithError "pm2 failed to start Host Agent. Check pm2 logs for details."
        }
        Write-Success "Host Agent registered with pm2 (name: rikune-host-agent)"
        Write-Info "Manage with: pm2 logs rikune-host-agent"
    } else {
        # Fallback: node-windows (nsm)
        $nodeWindowsModule = Join-Path $ProjectRoot "node_modules\node-windows"
        if (-not (Test-Path $nodeWindowsModule)) {
            Write-Info "Installing node-windows..."
            Push-Location $ProjectRoot
            npm install node-windows 2>&1 | Out-Null
            Pop-Location
        }
        if (-not (Test-Path $nodeWindowsModule)) {
            Exit-WithError "node-windows installation failed"
        }

        $serviceScript = Join-Path $WorkspaceRoot "install-service.js"
        @"
const Service = require('node-windows').Service;
const svc = new Service({
  name: 'Rikune Windows Host Agent',
  description: 'Manages Windows Sandbox lifecycle for Rikune dynamic analysis.',
  script: '$($hostAgentEntry -replace '\\', '\\\\')',
  cwd: '$($ProjectRoot -replace '\\', '\\\\')',
  env: [
    { name: 'HOST_AGENT_PORT', value: '$Port' },
    { name: 'HOST_AGENT_API_KEY', value: '$apiKey' },
    { name: 'HOST_AGENT_RUNTIME_API_KEY', value: '$apiKey' },
    { name: 'HOST_AGENT_WORKSPACE', value: '$($WorkspaceRoot -replace '\\', '\\\\')' }
  ]
});
svc.on('install', () => { svc.start(); });
svc.install();
"@ | Set-Content $serviceScript -Encoding UTF8

        Write-Info "Creating Windows Service (requires Administrator)..."
        if (-not (Test-IsAdmin)) {
            Exit-WithError "Installing a Windows Service requires Administrator privileges."
        }
        node "$serviceScript" 2>&1 | Out-Null
        if ($LASTEXITCODE -ne 0) {
            Exit-WithError "Failed to install Windows Service via node-windows"
        }
        Write-Success "Windows Service installed and started"
    }
} else {
    Write-Info "Starting Host Agent in foreground..."
    Write-Info "Press Ctrl+C to stop"
    Write-Host ""

    # If headless, start detached process and return
    if ($Headless) {
        $logFile = Join-Path $WorkspaceRoot "workspace\logs\host-agent.log"
        $proc = Start-Process -FilePath "node" -ArgumentList "`"$hostAgentEntry`"" -WorkingDirectory $ProjectRoot -WindowStyle Hidden -PassThru -RedirectStandardOutput $logFile -RedirectStandardError $logFile
        Write-Success "Host Agent started as background process (PID: $($proc.Id))"
        Write-Info "Logs: $logFile"
        Start-Sleep -Seconds 2
    } else {
        # Foreground interactive: we start it, then verify, then tell user how to restart
        $logFile = Join-Path $WorkspaceRoot "workspace\logs\host-agent.log"
        $proc = Start-Process -FilePath "node" -ArgumentList "`"$hostAgentEntry`"" -WorkingDirectory $ProjectRoot -WindowStyle Hidden -PassThru -RedirectStandardOutput $logFile -RedirectStandardError $logFile
        Write-Success "Host Agent started as background process (PID: $($proc.Id))"
        Write-Info "Logs: $logFile"
        Start-Sleep -Seconds 2
    }
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
    $result = Invoke-Request -Uri $healthUrl -Headers @{ Authorization = "Bearer $apiKey" } -TimeoutSec 3
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
    Write-Warning-Message "Host Agent did not respond to health check. It may still be starting up."
    Write-Info "Check logs: $(Join-Path $WorkspaceRoot "workspace\logs\host-agent.log")"
}

# =============================================================================
# Summary
# =============================================================================
Write-Header "Installation Complete"

Write-Host "  Project Root:   $ProjectRoot" -ForegroundColor $ColorSuccess
Write-Host "  Workspace:      $WorkspaceRoot" -ForegroundColor $ColorSuccess
Write-Host "  Host Agent:     http://127.0.0.1:$Port" -ForegroundColor $ColorSuccess
Write-Host "  API Key:        $apiKey" -ForegroundColor $ColorSuccess
Write-Host "  Env File:       $envFile" -ForegroundColor $ColorSuccess

Write-Host "`n  Quick Start:" -ForegroundColor $ColorPrimary
Write-Host "    1. Ensure this Windows machine is reachable from your Linux Analyzer" -ForegroundColor $ColorInfo
Write-Host "    2. On the Linux Analyzer, set:" -ForegroundColor $ColorInfo
Write-Host "       RUNTIME_MODE=remote-sandbox" -ForegroundColor $ColorInfo
Write-Host "       RUNTIME_HOST_AGENT_ENDPOINT=http://<this-windows-ip>:$Port" -ForegroundColor $ColorInfo
Write-Host "       RUNTIME_HOST_AGENT_API_KEY=$apiKey" -ForegroundColor $ColorInfo
Write-Host "       # Optional if Runtime Node auth should be separate:" -ForegroundColor $ColorInfo
Write-Host "       # RUNTIME_API_KEY=$apiKey" -ForegroundColor $ColorInfo
Write-Host "`n  Managing the Host Agent:" -ForegroundColor $ColorPrimary
if ($Service) {
    if ($pm2) {
        Write-Host "    pm2 logs rikune-host-agent" -ForegroundColor $ColorInfo
        Write-Host "    pm2 stop rikune-host-agent" -ForegroundColor $ColorInfo
    } else {
        Write-Host "    services.msc -> 'Rikune Windows Host Agent'" -ForegroundColor $ColorInfo
    }
} else {
    Write-Host "    Logs: $(Join-Path $WorkspaceRoot "workspace\logs\host-agent.log")" -ForegroundColor $ColorInfo
    Write-Host "    Stop: taskkill /F /IM node.exe   (or find PID in Resource Monitor)" -ForegroundColor $ColorInfo
}

$installInfo = @{
    InstallDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Mode = "windows-runtime"
    ProjectRoot = $ProjectRoot
    WorkspaceRoot = $WorkspaceRoot
    Port = $Port
    NodeVersion = $nodeVersion
    PythonVersion = $pyVersion
    ServiceMode = [bool]$Service
}
$installInfo | ConvertTo-Json | Set-Content (Join-Path $WorkspaceRoot "install-info.json") -Encoding UTF8

if (-not $Headless -and -not $Service) {
    Write-Host "`nPress any key to exit..." -ForegroundColor $ColorInfo
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}
