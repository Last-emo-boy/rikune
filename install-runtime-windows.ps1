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

    [Parameter(HelpMessage="Host Agent and Runtime API key. If omitted, a random key is generated.")]
    [string]$ApiKey,

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

# ─────────────────────────────────────────────────────────────────────────────
# Main Script
# ─────────────────────────────────────────────────────────────────────────────
if (-not $Headless) { Clear-Host }
Write-Header "Rikune — Windows Runtime Install"

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

$nodePath = (Get-Command node).Source
try {
    $pythonPath = (& $pythonCmd -c "import sys; print(sys.executable)" 2>$null).ToString().Trim()
} catch {
    $pythonPath = (Get-Command $pythonCmd).Source
}
if (-not $pythonPath -or -not (Test-Path $pythonPath)) {
    $pythonPath = (Get-Command $pythonCmd).Source
}
Write-Info "Node path for Sandbox mapping: $nodePath"
Write-Info "Python path for Sandbox mapping: $pythonPath"

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

$apiKey = if ($ApiKey) { $ApiKey } else { -join ((48..57) + (65..90) + (97..122) | Get-Random -Count 32 | ForEach-Object { [char]$_ }) }
$envFile = Join-Path $ProjectRoot ".env.runtime-windows"

$envContent = @"
# Rikune Windows Runtime Environment — generated by install-runtime-windows.ps1
# This file configures the Windows Host Agent and the Runtime Node inside Windows Sandbox.

# Host Agent settings
HOST_AGENT_PORT=$Port
HOST_AGENT_API_KEY=$apiKey
HOST_AGENT_RUNTIME_API_KEY=$apiKey
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
$env:HOST_AGENT_NODE_PATH = "$nodePath"
$env:HOST_AGENT_PYTHON_PATH = "$pythonPath"
$env:HOST_AGENT_BACKEND = "$RuntimeBackend"
$env:HOST_AGENT_HYPERV_VM_NAME = "$HyperVVmName"
$env:HOST_AGENT_HYPERV_SNAPSHOT_NAME = "$HyperVSnapshotName"
$env:HOST_AGENT_HYPERV_RUNTIME_ENDPOINT = "$HyperVRuntimeEndpoint"
$env:HOST_AGENT_HYPERV_RESTORE_ON_RELEASE = "$($HyperVRestoreOnRelease.IsPresent.ToString().ToLowerInvariant())"
$env:HOST_AGENT_HYPERV_STOP_ON_RELEASE = "$($HyperVStopOnRelease.IsPresent.ToString().ToLowerInvariant())"

if ($Service) {
    Write-Warning-Message "Windows Sandbox must be launched from a logged-on interactive user session."
    Write-Warning-Message "This mode uses PM2 in the current user session only; node-windows / Windows Service mode is intentionally disabled."
    Write-Info "Starting Host Agent under PM2..."

    # Prefer pm2
    $pm2 = Get-Command pm2 -ErrorAction SilentlyContinue
    if (-not $pm2) {
        Write-Info "pm2 not found; attempting to install pm2 globally..."
        $pm2InstallOutput = & npm install -g pm2 2>&1
        $pm2InstallExitCode = $LASTEXITCODE
        if ($pm2InstallOutput) {
            $pm2InstallOutput | ForEach-Object { Write-Info $_.ToString() }
        }
        if ($pm2InstallExitCode -eq 0) {
            $pm2 = Get-Command pm2 -ErrorAction SilentlyContinue
            if (-not $pm2) {
                $npmPrefix = (& npm prefix -g 2>$null).ToString().Trim()
                if ($npmPrefix -and (Test-Path $npmPrefix)) {
                    $env:PATH = "$npmPrefix;$env:PATH"
                    $pm2 = Get-Command pm2 -ErrorAction SilentlyContinue
                }
            }
        }
    }

    if ($pm2) {
        Write-Info "Using pm2 to manage service..."
        $pm2DeleteOutput = & pm2 delete "rikune-host-agent" 2>&1
        if ($pm2DeleteOutput) {
            $pm2DeleteOutput | ForEach-Object { Write-Info $_.ToString() }
        }

        $pm2StartOutput = & pm2 start "$hostAgentEntry" --name "rikune-host-agent" --cwd "$ProjectRoot" 2>&1
        $pm2StartExitCode = $LASTEXITCODE
        if ($pm2StartOutput) {
            $pm2StartOutput | ForEach-Object { Write-Info $_.ToString() }
        }
        if ($pm2StartExitCode -ne 0) {
            Exit-WithError "pm2 failed to start Host Agent. Check pm2 logs rikune-host-agent for details."
        }

        $pm2SaveOutput = & pm2 save 2>&1
        $pm2SaveExitCode = $LASTEXITCODE
        if ($pm2SaveOutput) {
            $pm2SaveOutput | ForEach-Object { Write-Info $_.ToString() }
        }
        if ($pm2SaveExitCode -ne 0) {
            Exit-WithError "pm2 failed to save process list."
        }
        Write-Success "Host Agent registered with pm2 (name: rikune-host-agent)"
        Write-Info "Manage with: pm2 logs rikune-host-agent"
    } else {
        Exit-WithError "PM2 is unavailable. Rerun without -Service to start Host Agent as a background process in this user session. Windows Service mode cannot launch Windows Sandbox."
    }
} else {
    Write-Info "Starting Host Agent in the current user session..."
    Write-Info "Keep this Windows user logged in while using Windows Sandbox dynamic execution."
    Write-Host ""

    # If headless, start detached process and return
    if ($Headless) {
        $logFile = Join-Path $WorkspaceRoot "workspace\logs\host-agent.log"
        $proc = Start-Process -FilePath "node" -ArgumentList "`"$hostAgentEntry`"" -WorkingDirectory $ProjectRoot -WindowStyle Hidden -PassThru -RedirectStandardOutput $logFile -RedirectStandardError $logFile
        Write-Success "Host Agent started as background process (PID: $($proc.Id))"
        Write-Info "Logs: $logFile"
        Start-Sleep -Seconds 2
    } else {
        # Interactive user-session process: required for Windows Sandbox launch.
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
    Write-Host "    pm2 logs rikune-host-agent" -ForegroundColor $ColorInfo
    Write-Host "    pm2 stop rikune-host-agent" -ForegroundColor $ColorInfo
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
