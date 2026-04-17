# Rikune — Local (Non-Docker) Install Script
# Requires: PowerShell 7+, Node.js 22+, Python 3.11+
# Encoding: UTF-8 without BOM

param(
    [Parameter(HelpMessage="Data root directory")]
    [string]$DataRoot,

    [Parameter(HelpMessage="Project root directory")]
    [string]$ProjectRoot = $PSScriptRoot,

    [Parameter(HelpMessage="Skip optional tools check")]
    [switch]$SkipOptional,

    [Parameter(HelpMessage="Runtime execution mode")]
    [ValidateSet("disabled", "auto-sandbox", "manual", "remote-sandbox")]
    [string]$RuntimeMode = "disabled",

    [Parameter(HelpMessage="Enable verbose output")]
    [switch]$EnableVerbose
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

# ─────────────────────────────────────────────────────────────────────────────
# Main Script
# ─────────────────────────────────────────────────────────────────────────────
try { Clear-Host } catch { }
Write-Header "Rikune — Local Install (No Docker)"

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

# Node.js
if (-not (Get-Command node -ErrorAction SilentlyContinue)) {
    Write-Error-Message "Node.js not found"
    Write-Host "  Install Node.js 22+: https://nodejs.org/" -ForegroundColor $ColorError
    exit 1
}
$nodeVersion = (node --version).Trim()
$nodeMajor = [int]($nodeVersion -replace '^v','').Split('.')[0]
if ($nodeMajor -lt 22) {
    Write-Error-Message "Node.js $nodeVersion is too old (need 22+)"
    exit 1
}
Write-Success "Node.js: $nodeVersion"

# npm
if (-not (Get-Command npm -ErrorAction SilentlyContinue)) {
    Write-Error-Message "npm not found"
    exit 1
}
Write-Success "npm: $((npm --version).Trim())"

if ($RuntimeMode -eq "auto-sandbox") {
    if (-not [System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform([System.Runtime.InteropServices.OSPlatform]::Windows)) {
        Write-Error-Message "RUNTIME_MODE=auto-sandbox requires a Windows-native analyzer"
        exit 1
    }
    try {
        $sandboxFeature = (Get-WindowsOptionalFeature -Online -FeatureName Containers-DisposableClient -ErrorAction SilentlyContinue).State
        if ($sandboxFeature -ne "Enabled") {
            Write-Warning-Message "Windows Sandbox is not enabled. Enable Containers-DisposableClient before running dynamic tools."
        } else {
            Write-Success "Windows Sandbox feature enabled"
        }
    } catch {
        Write-Warning-Message "Could not check Windows Sandbox feature: $($_.Exception.Message)"
    }
}

# Python
$pythonCmd = $null
foreach ($cmd in @('python', 'python3', 'py')) {
    if (Get-Command $cmd -ErrorAction SilentlyContinue) {
        try {
            $ver = & $cmd --version 2>&1
            if ($ver -match '3\.\d+') {
                $pythonCmd = $cmd
                break
            }
        } catch {}
    }
}
if (-not $pythonCmd) {
    Write-Error-Message "Python 3.11+ not found"
    Write-Host "  Install Python: https://www.python.org/downloads/" -ForegroundColor $ColorError
    exit 1
}
$pyVersion = (& $pythonCmd --version 2>&1).ToString().Trim()
Write-Success "Python: $pyVersion (command: $pythonCmd)"

# pip
try {
    $pipVer = & $pythonCmd -m pip --version 2>&1
    Write-Success "pip: available"
} catch {
    Write-Warning-Message "pip not available, trying to install..."
    & $pythonCmd -m ensurepip --upgrade 2>&1 | Out-Null
}

# =============================================================================
# Step 2: Install npm Dependencies & Build
# =============================================================================
Write-Step "Installing npm Dependencies & Building"

Push-Location $ProjectRoot
try {
    Write-Info "Running npm install..."
    npm install 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Error-Message "npm install failed"
        exit 1
    }
    Write-Success "npm dependencies installed"

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

if (-not (Test-Path $venvDir)) {
    Write-Info "Creating virtual environment..."
    & $pythonCmd -m venv $venvDir
    if ($LASTEXITCODE -ne 0) {
        Write-Error-Message "Failed to create venv"
        exit 1
    }
    Write-Success "Virtual environment created: $venvDir"
} else {
    Write-Success "Virtual environment exists: $venvDir"
}

# Install base requirements
Write-Info "Installing base Python requirements..."
& $venvPython -m pip install --upgrade pip 2>&1 | Out-Null
& $venvPython -m pip install -r (Join-Path $ProjectRoot "requirements.txt") 2>&1 | Out-Null
& $venvPython -m pip install -r (Join-Path $workersDir "requirements.txt") 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) {
    Write-Warning-Message "Some base Python packages failed to install"
} else {
    Write-Success "Base Python requirements installed"
}

# Ask about dynamic tools
Write-Host "`nInstall dynamic analysis Python packages?" -ForegroundColor $ColorPrimary
Write-Host "  Includes: frida, speakeasy-emulator, pandare, psutil" -ForegroundColor $ColorInfo
Write-Host "  (Recommended for malware analysis workflows)" -ForegroundColor $ColorInfo
$installDynamic = Read-Host "Install? (Y/n)"
if ($installDynamic -ne 'n' -and $installDynamic -ne 'N') {
    Write-Info "Installing dynamic analysis packages..."
    & $venvPython -m pip install -r (Join-Path $workersDir "requirements-dynamic.txt") 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Warning-Message "Some dynamic packages failed (this is OK on Windows)"
    } else {
        Write-Success "Dynamic analysis packages installed"
    }
}

# Ask about Qiling
Write-Host "`nInstall Qiling emulation framework?" -ForegroundColor $ColorPrimary
Write-Host "  Qiling uses its own venv due to unicorn version conflicts" -ForegroundColor $ColorInfo
$installQiling = Read-Host "Install? (y/N)"
if ($installQiling -eq 'y' -or $installQiling -eq 'Y') {
    $qilingVenv = Join-Path $ProjectRoot "qiling-venv"
    if (-not (Test-Path $qilingVenv)) {
        Write-Info "Creating Qiling venv..."
        & $pythonCmd -m venv $qilingVenv
    }
    $qilingPython = Join-Path $qilingVenv "Scripts\python.exe"
    & $qilingPython -m pip install --upgrade pip 2>&1 | Out-Null
    & $qilingPython -m pip install -r (Join-Path $workersDir "requirements-qiling.txt") 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Warning-Message "Qiling installation had issues"
    } else {
        Write-Success "Qiling installed in isolated venv: $qilingVenv"
    }
}

# Ask about angr
Write-Host "`nInstall angr symbolic execution engine?" -ForegroundColor $ColorPrimary
Write-Host "  angr uses its own venv (large dependency tree, ~1.5 GB)" -ForegroundColor $ColorInfo
$installAngr = Read-Host "Install? (y/N)"
if ($installAngr -eq 'y' -or $installAngr -eq 'Y') {
    $angrVenv = Join-Path $ProjectRoot "angr-venv"
    if (-not (Test-Path $angrVenv)) {
        Write-Info "Creating angr venv..."
        & $pythonCmd -m venv $angrVenv
    }
    $angrPython = Join-Path $angrVenv "Scripts\python.exe"
    & $angrPython -m pip install --upgrade pip 2>&1 | Out-Null
    & $angrPython -m pip install angr 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Warning-Message "angr installation had issues"
    } else {
        Write-Success "angr installed in isolated venv: $angrVenv"
    }
}

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

$envFile = Join-Path $ProjectRoot ".env"
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
# API_KEY=your-secret-key-here

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

$envContent | Set-Content $envFile -Encoding UTF8
Write-Success "Environment file: $envFile"
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
                API_ENABLED = "true"
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
        $configFile = Join-Path $configDir "mcp.json"
        if (-not (Test-Path $configDir)) { New-Item -ItemType Directory -Path $configDir -Force | Out-Null }
        $config | ConvertTo-Json -Depth 10 | Set-Content $configFile -Encoding UTF8
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
foreach ($kv in $healthEnv.GetEnumerator()) {
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
