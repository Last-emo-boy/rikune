# Rikune — Legacy Windows Native Analyzer Installer
# v1.4.0 retains this entry point only to fail closed before any environment or file mutation.
# Encoding: UTF-8 without BOM

param(
    [Parameter(HelpMessage="Data root directory")]
    [string]$DataRoot,

    [Parameter(HelpMessage="Project root directory")]
    [string]$ProjectRoot = $PSScriptRoot,

    [Parameter(HelpMessage="Skip optional tools check")]
    [switch]$SkipOptional,

    [Parameter(HelpMessage="Runtime execution mode")]
    # Legacy compatibility only; every invocation exits below before mutation in v1.4.0.
    [ValidateSet("disabled", "manual", "remote-sandbox")]
    [string]$RuntimeMode = "disabled",

    [Parameter(HelpMessage="Enable verbose output")]
    [switch]$EnableVerbose
)

$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $false

Write-Host "[ERROR] Rikune v1.4.0 requires a Linux kernel for the Analyzer and sample-custody data plane." -ForegroundColor Red
Write-Host "Native Windows/macOS Node Analyzer and auto-sandbox topologies are not supported." -ForegroundColor Red
Write-Host ""
Write-Host "Supported Windows-host paths:" -ForegroundColor Yellow
Write-Host "  Static Linux container:  .\rikune.ps1 install -Profile static"
Write-Host "  Hybrid Linux container:  .\rikune.ps1 install -Profile hybrid -InstallRuntime"
Write-Host "  Windows runtime only:     .\install-runtime-windows.ps1"
Write-Host "WSL2 users may run ./install-local.sh inside WSL2 and must keep sample data on the WSL Linux filesystem (for example ~/.rikune), never /mnt/<drive> DrvFS."
exit 1

$explicitAnalyzerApiKey = $env:RIKUNE_API_KEY
if ([string]::IsNullOrWhiteSpace($explicitAnalyzerApiKey)) {
    $explicitAnalyzerApiKey = $env:RIKUNE_ANALYZER_API_KEY
}
@(
    "RIKUNE_API_KEY",
    "RIKUNE_ANALYZER_API_KEY",
    "RIKUNE_STAGE_LOCAL_ENV_PATH",
    "RIKUNE_LOCAL_EXISTING_ENV_BASE64",
    "RIKUNE_LOCAL_ENV_SNAPSHOT_STDIN",
    "RIKUNE_REMOVE_PRIVATE_ENV_SNAPSHOT_PATH",
    "RIKUNE_RESTORE_PRIVATE_ENV_PATH",
    "RIKUNE_LOCAL_ENV_PATH",
    "RIKUNE_LOCAL_ENV_FORCE_KEYS",
    "RIKUNE_VERIFY_PRIVATE_ENV_PATH",
    "RIKUNE_STAGE_DOCKER_ENV_PATH",
    "RIKUNE_REMOVE_PRIVATE_ENV_PATH",
    "RIKUNE_DOCKER_ENV_SNAPSHOT_STDIN",
    "RIKUNE_DOCKER_ENV_PATH",
    "RIKUNE_DOCKER_ENV_DATA_ROOT",
    "RIKUNE_DOCKER_ENV_PROFILE",
    "RIKUNE_BUILD_HTTP_PROXY",
    "RIKUNE_BUILD_HTTPS_PROXY",
    "RIKUNE_BUILD_NO_PROXY",
    "RIKUNE_ALLOW_INSECURE_RUNTIME_HTTP",
    "RIKUNE_PRIVATE_ENV_PATH",
    "RIKUNE_PRIVATE_ENV_ACL_MODE",
    "STAGED_LOCAL_ENV_BASE64",
    "RUNTIME_HOST_AGENT_ENDPOINT",
    "ANALYZER_API_KEY",
    "RUNTIME_HOST_AGENT_API_KEY",
    "HOST_AGENT_API_KEY",
    "HOST_AGENT_RUNTIME_API_KEY",
    "RUNTIME_API_KEY",
    "RIKUNE_HOST_AGENT_API_KEY",
    "RIKUNE_RUNTIME_API_KEY",
    "RIKUNE_RUNTIME_NODE_API_KEY"
) | ForEach-Object { Remove-Item "Env:$_" -ErrorAction SilentlyContinue }
if (
    -not [string]::IsNullOrWhiteSpace($explicitAnalyzerApiKey) -and
    $explicitAnalyzerApiKey -notmatch '^[\x21-\x7e]{32,}$'
) {
    throw "RIKUNE_API_KEY must contain at least 32 printable non-space ASCII characters"
}

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

function Get-LocalPrivateEnvSnapshot {
    param([string]$Path, [string]$Writer)

    $previousEntry = Get-ProcessEnvironmentEntrySnapshot -Name "RIKUNE_STAGE_LOCAL_ENV_PATH"
    try {
        [Environment]::SetEnvironmentVariable("RIKUNE_STAGE_LOCAL_ENV_PATH", $Path, "Process")
        $snapshotOutput = & node $Writer
        if ($LASTEXITCODE -ne 0) { throw "Secure local environment staging failed" }
        return [string](@($snapshotOutput) -join '')
    } finally {
        Restore-ProcessEnvironmentEntry -Name "RIKUNE_STAGE_LOCAL_ENV_PATH" -Snapshot $previousEntry
    }
}

function Invoke-LocalPrivateEnvSnapshotOperation {
    param(
        [string]$EnvironmentName,
        [string]$Path,
        [string]$Snapshot,
        [string]$Writer,
        [string]$FailureMessage
    )

    $previousEntry = Get-ProcessEnvironmentEntrySnapshot -Name $EnvironmentName
    try {
        [Environment]::SetEnvironmentVariable($EnvironmentName, $Path, "Process")
        $Snapshot | & node $Writer
        if ($LASTEXITCODE -ne 0) { throw $FailureMessage }
    } finally {
        Restore-ProcessEnvironmentEntry -Name $EnvironmentName -Snapshot $previousEntry
    }
}

function Get-OptionalFeatureByName {
    param([string[]]$Names)

    foreach ($name in $Names) {
        try {
            $feature = Get-WindowsOptionalFeature -Online -FeatureName $name -ErrorAction Stop
            if ($feature) { return $feature }
        } catch {
            if ($EnableVerbose) { Write-Info "Optional feature not available by name '$name'" }
        }
    }

    return $null
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
        [string]$NodeCommand,
        [string[]]$McpArgs,
        [hashtable]$Env
    )

    $configDir = Split-Path -Parent $ConfigFile
    if (-not (Test-Path $configDir)) {
        New-Item -ItemType Directory -Path $configDir -Force | Out-Null
    }

    $envLines = @()
    foreach ($key in ($Env.Keys | Sort-Object)) {
        $envLines += "$key = $(ConvertTo-TomlString $Env[$key])"
    }

    $block = @"
[mcp_servers.rikune]
type = "stdio"
command = $(ConvertTo-TomlString $NodeCommand)
startup_timeout_sec = 180
args = $(ConvertTo-TomlArray $McpArgs)

[mcp_servers.rikune.env]
$($envLines -join "`r`n")
"@

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

# ─────────────────────────────────────────────────────────────────────────────
# Main Script
# ─────────────────────────────────────────────────────────────────────────────
try { Clear-Host } catch { }
Write-Header "Rikune — Local Install (No Docker)"

if ($PSVersionTable.PSVersion.Major -lt 7) {
    Write-Error-Message "PowerShell 7 or newer is required for protected atomic environment-file writes."
    exit 1
}

Write-Host "This script will:" -ForegroundColor $ColorInfo
Write-Host "  1. Check Node.js & Python" -ForegroundColor $ColorInfo
Write-Host "  2. Install npm dependencies & build" -ForegroundColor $ColorInfo
Write-Host "  3. Set up Python virtual environment" -ForegroundColor $ColorInfo
Write-Host "  4. Create data directories" -ForegroundColor $ColorInfo
Write-Host "  5. Check optional analysis tools" -ForegroundColor $ColorInfo
Write-Host "  6. Configure MCP clients" -ForegroundColor $ColorInfo
Write-Host "  7. Run health check" -ForegroundColor $ColorInfo
Write-Host "" -ForegroundColor $ColorInfo
Write-Host "Runtime mode: $RuntimeMode" -ForegroundColor $ColorInfo

$continue = Read-Host "`nContinue? (Y/n)"
if ($continue -eq 'n' -or $continue -eq 'N') {
    Write-Warning-Message "Installation cancelled"
    exit 0
}

# =============================================================================
# Step 1: Check Required Tools
# =============================================================================
Write-Step "Checking Required Tools"

$isWindowsPlatform = [System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform(
    [System.Runtime.InteropServices.OSPlatform]::Windows
)
$isX64Platform = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture -eq [System.Runtime.InteropServices.Architecture]::X64
if (-not $isWindowsPlatform -or -not $isX64Platform) {
    Write-Error-Message "This installer requires Windows x86_64; the repository Python locks target Windows x86_64."
    exit 1
}

# Node.js
if (-not (Get-Command node -ErrorAction SilentlyContinue)) {
    Write-Error-Message "Node.js not found"
    Write-Host "  Install Node.js 22.9+: https://nodejs.org/" -ForegroundColor $ColorError
    exit 1
}
$nodeVersion = (node --version).Trim()
$nodeParts = ($nodeVersion -replace '^v','').Split('.')
$nodeMajor = [int]$nodeParts[0]
$nodeMinor = [int]$nodeParts[1]
if ($nodeMajor -lt 22 -or ($nodeMajor -eq 22 -and $nodeMinor -lt 9)) {
    Write-Error-Message "Node.js $nodeVersion is too old (need 22.9+)"
    exit 1
}
Write-Success "Node.js: $nodeVersion"

# npm
if (-not (Get-Command npm -ErrorAction SilentlyContinue)) {
    Write-Error-Message "npm not found"
    exit 1
}
Write-Success "npm: $((npm --version).Trim())"

$envFile = Join-Path $ProjectRoot ".env"
$localEnvWriter = Join-Path $ProjectRoot "scripts/write-local-runtime-env.mjs"
$privateEnvWriter = Join-Path $ProjectRoot "scripts/write-docker-runtime-env.mjs"
if (-not (Test-Path -LiteralPath $localEnvWriter -PathType Leaf)) {
    throw "Secure local environment writer not found: $localEnvWriter"
}
if (-not (Test-Path -LiteralPath $privateEnvWriter -PathType Leaf)) {
    throw "Secure private environment writer not found: $privateEnvWriter"
}
$privateEnvSnapshot = $null
$privateEnvTransactionActive = $false
$privateEnvTransactionCommitted = $false
try {
    $privateEnvSnapshot = Get-LocalPrivateEnvSnapshot -Path $envFile -Writer $localEnvWriter
    $privateEnvTransactionActive = $true
    Invoke-LocalPrivateEnvSnapshotOperation `
        -EnvironmentName "RIKUNE_REMOVE_PRIVATE_ENV_SNAPSHOT_PATH" `
        -Path $envFile `
        -Snapshot $privateEnvSnapshot `
        -Writer $privateEnvWriter `
        -FailureMessage "Secure removal of the staged local environment failed"

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
    Write-Error-Message "CPython 3.12 x86_64 not found"
    Write-Host "  Install Python: https://www.python.org/downloads/" -ForegroundColor $ColorError
    exit 1
}
$pyVersion = (& $pythonCmd @pythonPrefixArgs --version 2>&1).ToString().Trim()
$pythonDisplay = (($pythonCmd, ($pythonPrefixArgs -join ' ')) -join ' ').Trim()
Write-Success "Python: $pyVersion (command: $pythonDisplay)"

# =============================================================================
# Step 2: Install npm Dependencies & Build
# =============================================================================
Write-Step "Installing npm Dependencies & Building"

Push-Location $ProjectRoot
try {
    Write-Info "Running npm ci --include=dev..."
    npm ci --include=dev 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Error-Message "npm ci --include=dev failed"
        exit 1
    }
    Write-Success "npm dependencies installed from package-lock.json"

    Write-Info "Building TypeScript..."
    npm run build 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Error-Message "Build failed"
        exit 1
    }
    Write-Success "Project built (dist/ ready)"
} catch {
    Write-Error-Message "Build error: $($_.Exception.Message)"
    exit 1
} finally {
    Pop-Location
}

# =============================================================================
# Step 3: Python Virtual Environment
# =============================================================================
Write-Step "Setting Up Python Virtual Environment"

$workersDir = Join-Path $ProjectRoot "workers"
$venvDir = Join-Path $workersDir "venv"
$venvPython = Join-Path $venvDir "Scripts\python.exe"
$baseRequirementsLock = Join-Path $ProjectRoot "requirements.windows.lock.txt"
$dynamicRequirementsLock = Join-Path $workersDir "requirements-dynamic.windows.lock.txt"
if (-not (Test-Path -LiteralPath $baseRequirementsLock -PathType Leaf)) {
    Write-Error-Message "Windows base Python lock not found: $baseRequirementsLock"
    exit 1
}

if (-not (Test-Path $venvDir)) {
    Write-Info "Creating virtual environment..."
    & $pythonCmd @pythonPrefixArgs -m venv $venvDir
    if ($LASTEXITCODE -ne 0) {
        Write-Error-Message "Failed to create venv"
        exit 1
    }
    Write-Success "Virtual environment created: $venvDir"
} else {
    Write-Success "Virtual environment exists: $venvDir"
}

if (-not (Test-Path -LiteralPath $venvPython -PathType Leaf)) {
    Write-Error-Message "Python venv executable not found: $venvPython"
    exit 1
}
& $venvPython -c "import struct, sys; raise SystemExit(0 if sys.implementation.name == 'cpython' and sys.version_info[:2] == (3, 12) and struct.calcsize('P') == 8 else 1)" *> $null
if ($LASTEXITCODE -ne 0) {
    Write-Error-Message "Existing Python venv must use CPython 3.12 x86_64. Remove $venvDir and rerun."
    exit 1
}
& $venvPython -m pip --version *> $null
if ($LASTEXITCODE -ne 0) {
    Write-Error-Message "pip is unavailable in the CPython 3.12 virtual environment. Recreate $venvDir."
    exit 1
}

# Install base requirements
Write-Info "Installing base Python requirements..."
& $venvPython -m pip install --disable-pip-version-check --require-hashes --requirement $baseRequirementsLock 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) {
    Write-Error-Message "Base Python requirements failed to install from the Windows hash lock"
    exit 1
}
Write-Success "Base Python requirements installed"

# Ask about dynamic tools
Write-Host "`nInstall dynamic analysis Python packages?" -ForegroundColor $ColorPrimary
Write-Host "  Includes: frida, speakeasy-emulator, pandare, psutil" -ForegroundColor $ColorInfo
Write-Host "  (Recommended for malware analysis workflows)" -ForegroundColor $ColorInfo
$installDynamic = Read-Host "Install? (Y/n)"
if ($installDynamic -ne 'n' -and $installDynamic -ne 'N') {
    Write-Info "Installing dynamic analysis packages..."
    if (-not (Test-Path -LiteralPath $dynamicRequirementsLock -PathType Leaf)) {
        Write-Error-Message "Windows dynamic Python lock not found: $dynamicRequirementsLock"
        exit 1
    }
    & $venvPython -m pip install --disable-pip-version-check --require-hashes --requirement $dynamicRequirementsLock 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Error-Message "Dynamic Python requirements failed to install from the Windows hash lock"
        exit 1
    }
    Write-Success "Dynamic analysis packages installed"
}

Write-Warning-Message "Qiling installation is disabled: no hashed Windows production lock is available."
Write-Warning-Message "angr installation is disabled on Windows: no hashed Windows production lock is available."

# =============================================================================
# Step 4: Data Directories
# =============================================================================
Write-Step "Creating Data Directories"

if (-not $DataRoot) {
    Write-Host "`nSelect data storage location:" -ForegroundColor $ColorPrimary
    $defaultPath = "$env:USERPROFILE\.rikune"
    Write-Host "  [0] $defaultPath (default)" -ForegroundColor $ColorInfo

    $disks = Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Free -gt 5GB -and $_.Name -ne 'C' } | Sort-Object -Property Name
    $idx = 1
    foreach ($disk in $disks) {
        $freeGB = [math]::Round($disk.Free / 1GB, 1)
        Write-Host "  [$idx] $($disk.Name):\Rikune (${freeGB}GB free)" -ForegroundColor $ColorSuccess
        $idx++
    }

    $sel = Read-Host "`nSelect (default: 0)"
    if ([string]::IsNullOrWhiteSpace($sel) -or $sel -eq '0') {
        $DataRoot = $defaultPath
    } else {
        $diskIndex = [int]$sel - 1
        if ($diskIndex -ge 0 -and $diskIndex -lt $disks.Count) {
            $DataRoot = "$($disks[$diskIndex].Name):\Rikune"
        } else {
            $DataRoot = $defaultPath
        }
    }
}
Write-Success "Data root: $DataRoot"

$directories = @("workspaces", "data", "cache", "ghidra-projects", "ghidra-logs", "logs", "storage", "samples")
foreach ($dir in $directories) {
    $fullPath = Join-Path $DataRoot $dir
    if (-not (Test-Path $fullPath)) {
        New-Item -ItemType Directory -Path $fullPath -Force | Out-Null
        Write-Success "Created: $fullPath"
    }
}

# =============================================================================
# Step 5: Check Optional Analysis Tools
# =============================================================================
if (-not $SkipOptional) {
    Write-Step "Checking Optional Analysis Tools"

    Write-Host "`nThe following tools enhance Rikune's capabilities." -ForegroundColor $ColorInfo
    Write-Host "They are optional — Rikune works without them (those tools will be unavailable)." -ForegroundColor $ColorInfo
    Write-Host ""

    $optionalTools = @(
        @{ Name = "Ghidra";   Env = "GHIDRA_INSTALL_DIR"; Test = "analyzeHeadless"; TestType = "env-dir";
           Url = "https://ghidra-sre.org/"; Desc = "Decompilation, CFG, cross-references" }
        @{ Name = "Java 21+"; Env = "JAVA_HOME";          Test = "java";            TestType = "binary";
           Url = "https://adoptium.net/";   Desc = "Required by Ghidra" }
        @{ Name = "Rizin";    Env = "RIZIN_PATH";         Test = "rizin";           TestType = "binary";
           Url = "https://rizin.re/";       Desc = "Binary disassembly, diffing" }
        @{ Name = "capa";     Env = "CAPA_PATH";          Test = "capa";            TestType = "binary";
           Url = "https://github.com/mandiant/capa"; Desc = "Malware capability detection" }
        @{ Name = "UPX";      Env = "UPX_PATH";           Test = "upx";             TestType = "binary";
           Url = "https://upx.github.io/";  Desc = "Unpacking compressed executables" }
        @{ Name = "JADX";     Env = "JADX_PATH";          Test = "jadx";            TestType = "binary";
           Url = "https://github.com/skylot/jadx"; Desc = "Android APK/DEX decompilation" }
        @{ Name = "Graphviz"; Env = "GRAPHVIZ_DOT_PATH";  Test = "dot";             TestType = "binary";
           Url = "https://graphviz.org/";   Desc = "CFG / call-graph visualization" }
        @{ Name = "Wine";     Env = "WINE_PATH";          Test = "wine";            TestType = "binary";
           Url = "https://www.winehq.org/"; Desc = "Windows PE execution on Linux" }
        @{ Name = "RetDec";   Env = "RETDEC_PATH";        Test = "retdec-decompiler"; TestType = "binary";
           Url = "https://github.com/avast/retdec"; Desc = "Retargetable decompiler" }
        @{ Name = "Frida";    Env = "FRIDA_PATH";         Test = "frida";           TestType = "binary";
           Url = "https://frida.re/";       Desc = "Dynamic instrumentation" }
        @{ Name = "GDB";      Env = $null;                Test = "gdb";             TestType = "binary";
           Url = "https://www.sourceware.org/gdb/"; Desc = "Debug sessions (Linux)" }
        @{ Name = "Volatility3"; Env = "VOLATILITY3_PATH"; Test = "vol";            TestType = "binary";
           Url = "https://github.com/volatilityfoundation/volatility3"; Desc = "Memory forensics" }
    )

    $found = 0
    $missing = 0
    foreach ($tool in $optionalTools) {
        $available = $false
        $resolvedPath = $null

        # Check env var first
        if ($tool.Env -and (Test-Path "env:\$($tool.Env)")) {
            $envVal = [Environment]::GetEnvironmentVariable($tool.Env)
            if ($envVal -and (Test-Path $envVal -ErrorAction SilentlyContinue)) {
                $available = $true
                $resolvedPath = $envVal
            }
        }

        # Check binary on PATH
        if (-not $available -and $tool.TestType -eq 'binary') {
            $cmd = Get-Command $tool.Test -ErrorAction SilentlyContinue
            if ($cmd) {
                $available = $true
                $resolvedPath = $cmd.Source
            }
        }

        if ($available) {
            $pathInfo = if ($resolvedPath) { " ($resolvedPath)" } else { "" }
            Write-Host "  [" -NoNewline
            Write-Host "OK" -ForegroundColor $ColorSuccess -NoNewline
            Write-Host "]  $($tool.Name)$pathInfo"
            $found++
        } else {
            Write-Host "  [" -NoNewline
            Write-Host "--" -ForegroundColor $ColorWarning -NoNewline
            Write-Host "]  $($tool.Name) — $($tool.Desc)"
            if ($EnableVerbose) {
                Write-Host "       Install: $($tool.Url)" -ForegroundColor $ColorInfo
                if ($tool.Env) { Write-Host "       Set env: $($tool.Env)=<path>" -ForegroundColor $ColorInfo }
            }
            $missing++
        }
    }

    Write-Host ""
    Write-Success "$found tools found, $missing optional tools not installed"
    if ($missing -gt 0 -and -not $EnableVerbose) {
        Write-Info "Run with -EnableVerbose to see install URLs and env var names"
    }
}

# =============================================================================
# Step 6: Environment Variables
# =============================================================================
Write-Step "Generating Environment Configuration"

$envContent = @"
# Rikune Local Environment — generated by install-local.ps1
# Adjust paths to match your local tool installations.

# Core paths
NODE_ROLE=analyzer
RUNTIME_MODE=$RuntimeMode
WORKSPACE_ROOT=$((Join-Path $DataRoot "workspaces") -replace '\\', '/')
DB_PATH=$((Join-Path $DataRoot "data/database.db") -replace '\\', '/')
CACHE_ROOT=$((Join-Path $DataRoot "cache") -replace '\\', '/')
AUDIT_LOG_PATH=$((Join-Path $DataRoot "logs/audit.log") -replace '\\', '/')
LOG_LEVEL=info

# Python worker
SANDBOX_PYTHON_PATH=$($venvPython -replace '\\', '/')

# API File Server
API_ENABLED=true
API_PORT=18080
API_STORAGE_ROOT=$((Join-Path $DataRoot "storage") -replace '\\', '/')
API_KEY=__RIKUNE_CSPRNG_API_KEY__

# Ghidra (set if installed)
# GHIDRA_INSTALL_DIR=C:/ghidra
# GHIDRA_PROJECT_ROOT=$((Join-Path $DataRoot "ghidra-projects") -replace '\\', '/')
# GHIDRA_LOG_ROOT=$((Join-Path $DataRoot "ghidra-logs") -replace '\\', '/')

# Optional tool paths (uncomment and set if installed)
# RIZIN_PATH=C:/tools/rizin/bin/rizin.exe
# CAPA_PATH=C:/tools/capa/capa.exe
# CAPA_RULES_PATH=C:/tools/capa-rules
# UPX_PATH=C:/tools/upx.exe
# JADX_PATH=C:/tools/jadx/bin/jadx.bat
# RETDEC_PATH=C:/tools/retdec/bin/retdec-decompiler.exe
# GRAPHVIZ_DOT_PATH=C:/Program Files/Graphviz/bin/dot.exe
# FRIDA_PATH=frida
# VOLATILITY3_PATH=vol
# ANGR_PYTHON=$((Join-Path $ProjectRoot "angr-venv/Scripts/python.exe") -replace '\\', '/')
# QILING_PYTHON=$((Join-Path $ProjectRoot "qiling-venv/Scripts/python.exe") -replace '\\', '/')
"@

$managedWriterEnvironment = @{
    RIKUNE_LOCAL_ENV_PATH = $envFile
    RIKUNE_LOCAL_ENV_FORCE_KEYS = "NODE_ROLE,RUNTIME_MODE,WORKSPACE_ROOT,DB_PATH,CACHE_ROOT,AUDIT_LOG_PATH,LOG_LEVEL,SANDBOX_PYTHON_PATH,API_ENABLED,API_PORT,API_STORAGE_ROOT"
    RIKUNE_LOCAL_ENV_SNAPSHOT_STDIN = "1"
    RIKUNE_API_KEY = $explicitAnalyzerApiKey
}
$previousWriterEnvironment = @{}
foreach ($name in $managedWriterEnvironment.Keys) {
    $previousWriterEnvironment[$name] = Get-ProcessEnvironmentEntrySnapshot -Name $name
    [Environment]::SetEnvironmentVariable($name, [string]$managedWriterEnvironment[$name], "Process")
}
try {
    ($privateEnvSnapshot + "`n" + $envContent) | & node $localEnvWriter
    if ($LASTEXITCODE -ne 0) { throw "Secure local environment generation failed" }
} finally {
    foreach ($name in $managedWriterEnvironment.Keys) {
        Restore-ProcessEnvironmentEntry -Name $name -Snapshot $previousWriterEnvironment[$name]
    }
    $explicitAnalyzerApiKey = $null
}
    $privateEnvTransactionCommitted = $true
    $privateEnvSnapshot = $null
} finally {
    if ($privateEnvTransactionActive -and -not $privateEnvTransactionCommitted) {
        try {
            Invoke-LocalPrivateEnvSnapshotOperation `
                -EnvironmentName "RIKUNE_RESTORE_PRIVATE_ENV_PATH" `
                -Path $envFile `
                -Snapshot $privateEnvSnapshot `
                -Writer $privateEnvWriter `
                -FailureMessage "Secure restoration of the local environment failed"
        } catch {
            Write-Error-Message "Failed to restore the protected local env after installer failure: $($_.Exception.Message)"
        }
    }
    $privateEnvSnapshot = $null
}
Write-Success "Protected environment file: $envFile"
Write-Info "Edit .env to set paths to your locally installed tools"

# =============================================================================
# Step 7: Configure MCP Clients
# =============================================================================
Write-Step "Configuring MCP Clients"

Write-Host "`nSelect MCP client to configure:" -ForegroundColor $ColorPrimary
Write-Host "  [1] Claude Desktop" -ForegroundColor $ColorInfo
Write-Host "  [2] GitHub Copilot" -ForegroundColor $ColorInfo
Write-Host "  [3] Codex" -ForegroundColor $ColorInfo
Write-Host "  [4] Generic config" -ForegroundColor $ColorInfo
Write-Host "  [5] Skip" -ForegroundColor $ColorInfo

$mcpClient = Read-Host "`nSelect (1-5)"

$nodeExe = (Get-Command node).Source
$distIndex = (Join-Path $ProjectRoot "dist\index.js") -replace '\\', '/'

$config = @{
    mcpServers = @{
        "rikune" = @{
            command = $nodeExe
            args = @($distIndex)
            env = @{
                NODE_ENV = "production"
                NODE_ROLE = "analyzer"
                RUNTIME_MODE = $RuntimeMode
                WORKSPACE_ROOT = (Join-Path $DataRoot "workspaces") -replace '\\', '/'
                DB_PATH = (Join-Path $DataRoot "data/database.db") -replace '\\', '/'
                CACHE_ROOT = (Join-Path $DataRoot "cache") -replace '\\', '/'
                AUDIT_LOG_PATH = (Join-Path $DataRoot "logs/audit.log") -replace '\\', '/'
                SANDBOX_PYTHON_PATH = $venvPython -replace '\\', '/'
                API_ENABLED = "false"
                API_PORT = "18080"
                API_STORAGE_ROOT = (Join-Path $DataRoot "storage") -replace '\\', '/'
            }
        }
    }
}

switch ($mcpClient) {
    "1" {
        $configDir = "$env:APPDATA\Claude"
        $configFile = Join-Path $configDir "claude_desktop_config.json"
        if (-not (Test-Path $configDir)) { New-Item -ItemType Directory -Path $configDir -Force | Out-Null }
        $config | ConvertTo-Json -Depth 10 | Set-Content $configFile -Encoding UTF8
        Write-Success "Claude Desktop config: $configFile"
    }
    "2" {
        $configDir = "$env:APPDATA\GitHub Copilot"
        $configFile = Join-Path $configDir "mcp.json"
        if (-not (Test-Path $configDir)) { New-Item -ItemType Directory -Path $configDir -Force | Out-Null }
        $config | ConvertTo-Json -Depth 10 | Set-Content $configFile -Encoding UTF8
        Write-Success "GitHub Copilot config: $configFile"
    }
    "3" {
        $configDir = "$env:USERPROFILE\.codex"
        $configFile = Join-Path $configDir "config.toml"
        Set-CodexMcpConfig -ConfigFile $configFile -NodeCommand $nodeExe -McpArgs @($distIndex) -Env $config.mcpServers["rikune"].env
        Write-Success "Codex config: $configFile"
    }
    "4" {
        $configFile = Join-Path $DataRoot "mcp-client-config.json"
        $config | ConvertTo-Json -Depth 10 | Set-Content $configFile -Encoding UTF8
        Write-Success "Generic config: $configFile"
    }
    default {
        Write-Warning-Message "Skipped MCP client configuration"
    }
}

# =============================================================================
# Step 8: Health Check — run via plugin systemDeps
# =============================================================================
Write-Step "Running Health Check"

Write-Host "`nStarting Rikune in health-check mode..." -ForegroundColor $ColorPrimary

$healthEnv = @{
    NODE_ROLE = "analyzer"
    RUNTIME_MODE = $RuntimeMode
    WORKSPACE_ROOT = Join-Path $DataRoot "workspaces"
    DB_PATH = Join-Path $DataRoot "data/database.db"
    CACHE_ROOT = Join-Path $DataRoot "cache"
    SANDBOX_PYTHON_PATH = $venvPython
    LOG_LEVEL = "warn"
    RIKUNE_HEALTH_CHECK = "1"
}
$previousHealthEnvironment = @{}
foreach ($kv in $healthEnv.GetEnumerator()) {
    $previousHealthEnvironment[$kv.Key] = Get-ProcessEnvironmentEntrySnapshot -Name $kv.Key
    [Environment]::SetEnvironmentVariable($kv.Key, $kv.Value, "Process")
}

try {
    $healthResult = node (Join-Path $ProjectRoot "dist/index.js") --health-check 2>&1
    $exitCode = $LASTEXITCODE
    if ($exitCode -eq 0) {
        Write-Success "Health check passed"
    } else {
        Write-Warning-Message "Health check completed with warnings (exit $exitCode)"
    }
    if ($EnableVerbose) {
        foreach ($line in $healthResult) { Write-Info $line }
    }
} catch {
    Write-Warning-Message "Health check could not run: $($_.Exception.Message)"
    Write-Info "This is OK — the server will check deps at startup."
} finally {
    foreach ($name in $healthEnv.Keys) {
        Restore-ProcessEnvironmentEntry -Name $name -Snapshot $previousHealthEnvironment[$name]
    }
}

# =============================================================================
# Summary
# =============================================================================
Write-Header "Installation Complete"

Write-Host "  Data Root:    $DataRoot" -ForegroundColor $ColorSuccess
Write-Host "  Project Root: $ProjectRoot" -ForegroundColor $ColorSuccess
Write-Host "  Python venv:  $venvDir" -ForegroundColor $ColorSuccess
Write-Host "  Env File:     $envFile" -ForegroundColor $ColorSuccess

Write-Host "`n  Quick Start:" -ForegroundColor $ColorPrimary
Write-Host "    cd $ProjectRoot" -ForegroundColor $ColorInfo
Write-Host "    node dist/index.js" -ForegroundColor $ColorInfo
Write-Host ""
Write-Host "  Or with npm:" -ForegroundColor $ColorPrimary
Write-Host "    npm start" -ForegroundColor $ColorInfo
Write-Host ""
Write-Host "  Development:" -ForegroundColor $ColorPrimary
Write-Host "    npm run dev      # watch mode with tsx" -ForegroundColor $ColorInfo
Write-Host "    npm test         # run tests" -ForegroundColor $ColorInfo
Write-Host ""
Write-Host "  To add optional tools later:" -ForegroundColor $ColorPrimary
Write-Host "    1. Install the tool (Ghidra, Rizin, capa, etc.)" -ForegroundColor $ColorInfo
Write-Host "    2. Set the env var in .env (e.g. GHIDRA_INSTALL_DIR=C:\ghidra)" -ForegroundColor $ColorInfo
Write-Host "    3. Restart Rikune — it auto-detects via plugin systemDeps" -ForegroundColor $ColorInfo
Write-Host ""

$installInfo = @{
    InstallDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Mode = "local"
    RuntimeMode = $RuntimeMode
    DataRoot = $DataRoot
    ProjectRoot = $ProjectRoot
    PythonVenv = $venvDir
    NodeVersion = $nodeVersion
    PythonVersion = $pyVersion
}
$installInfo | ConvertTo-Json | Set-Content (Join-Path $DataRoot "install-info.json") -Encoding UTF8
Write-Info "Install info saved to $DataRoot\install-info.json"
