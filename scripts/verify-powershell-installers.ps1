$ErrorActionPreference = "Stop"

if ($PSVersionTable.PSVersion.Major -lt 7) {
    throw "PowerShell installer verification requires PowerShell 7 or newer"
}

$projectRoot = Split-Path -Parent $PSScriptRoot
$installerPaths = @(
    (Join-Path $projectRoot "install-docker.ps1"),
    (Join-Path $projectRoot "install-local.ps1"),
    (Join-Path $projectRoot "install-runtime-windows.ps1"),
    (Join-Path $projectRoot "rikune.ps1")
)
$installerAsts = @{}

function Assert-Contract {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw $Message }
}

function Assert-Throws {
    param([scriptblock]$Action, [string]$Message)

    $threw = $false
    try {
        & $Action | Out-Null
    } catch {
        $threw = $true
    }
    if (-not $threw) { throw $Message }
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

function Assert-ProcessEnvironmentEntryMatchesSnapshot {
    param(
        [string]$Name,
        [object]$Snapshot,
        [string]$Message
    )

    $current = Get-ProcessEnvironmentEntrySnapshot -Name $Name
    Assert-Contract (
        $current.Exists -eq $Snapshot.Exists -and
        (-not $Snapshot.Exists -or $current.Value -ceq $Snapshot.Value)
    ) $Message
}

function Get-FunctionAst {
    param(
        [System.Management.Automation.Language.ScriptBlockAst]$Ast,
        [string]$Name,
        [string]$Owner
    )

    $functionAst = $Ast.Find(
        {
            param($node)
            $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
                $node.Name -eq $Name
        },
        $true
    )
    if ($null -eq $functionAst) {
        throw "$Owner must define $Name for standalone execution"
    }
    return $functionAst
}

function Assert-PathEqual {
    param([string]$Actual, [string]$Expected, [string]$Message)

    $trimCharacters = [char[]]@(
        [System.IO.Path]::DirectorySeparatorChar,
        [System.IO.Path]::AltDirectorySeparatorChar
    )
    $actualFullPath = [System.IO.Path]::GetFullPath($Actual).TrimEnd($trimCharacters)
    $expectedFullPath = [System.IO.Path]::GetFullPath($Expected).TrimEnd($trimCharacters)
    $comparison = if ($IsWindows) {
        [System.StringComparison]::OrdinalIgnoreCase
    } else {
        [System.StringComparison]::Ordinal
    }
    if (-not [string]::Equals($actualFullPath, $expectedFullPath, $comparison)) {
        throw "$Message`: expected '$expectedFullPath', received '$actualFullPath'"
    }
}

foreach ($installerPath in $installerPaths) {
    $tokens = $null
    $parseErrors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile(
        $installerPath,
        [ref]$tokens,
        [ref]$parseErrors
    )
    if (@($parseErrors).Count -gt 0) {
        $messages = ($parseErrors | ForEach-Object { $_.Message }) -join "; "
        throw "PowerShell parse failed for $installerPath`: $messages"
    }

    $name = [System.IO.Path]::GetFileName($installerPath)
    $installerAsts[$name] = $ast
}

function Assert-NoNullEnvironmentDeletion {
    param(
        [System.Management.Automation.Language.ScriptBlockAst]$Ast,
        [string]$Owner
    )

    $nullDeletionCalls = @(
        $Ast.FindAll(
            {
                param($node)
                if ($node -isnot [System.Management.Automation.Language.InvokeMemberExpressionAst]) {
                    return $false
                }
                if ($node.Member.Extent.Text -ine "SetEnvironmentVariable") {
                    return $false
                }
                $arguments = @($node.Arguments)
                return $arguments.Count -ge 2 -and $arguments[1].Extent.Text.Trim() -ceq '$null'
            },
            $true
        )
    )
    Assert-Contract (
        $nullDeletionCalls.Count -eq 0
    ) "$Owner must delete absent process environment entries through Remove-Item Env:, never SetEnvironmentVariable(..., `$null, ...)"
}

foreach ($installerName in $installerAsts.Keys) {
    Assert-NoNullEnvironmentDeletion -Ast $installerAsts[$installerName] -Owner $installerName
}
$verificationTokens = $null
$verificationParseErrors = $null
$verificationAst = [System.Management.Automation.Language.Parser]::ParseFile(
    $PSCommandPath,
    [ref]$verificationTokens,
    [ref]$verificationParseErrors
)
Assert-Contract (@($verificationParseErrors).Count -eq 0) "PowerShell verifier must parse before checking environment deletion contracts"
Assert-NoNullEnvironmentDeletion -Ast $verificationAst -Owner "scripts/verify-powershell-installers.ps1"

$dockerAst = $installerAsts["install-docker.ps1"]
$dockerSource = $dockerAst.Extent.Text
$localInstallerAst = $installerAsts["install-local.ps1"]
$localInstallerSource = $localInstallerAst.Extent.Text
$runtimeAst = $installerAsts["install-runtime-windows.ps1"]
$runtimeSource = $runtimeAst.Extent.Text
$rikuneAst = $installerAsts["rikune.ps1"]

foreach ($installerContract in @(
    @{ Name = "install-docker.ps1"; Ast = $dockerAst },
    @{ Name = "install-local.ps1"; Ast = $localInstallerAst },
    @{ Name = "install-runtime-windows.ps1"; Ast = $runtimeAst },
    @{ Name = "rikune.ps1"; Ast = $rikuneAst }
)) {
    $snapshotSource = (Get-FunctionAst `
        -Ast $installerContract.Ast `
        -Name "Get-ProcessEnvironmentEntrySnapshot" `
        -Owner $installerContract.Name).Extent.Text
    $restoreSource = (Get-FunctionAst `
        -Ast $installerContract.Ast `
        -Name "Restore-ProcessEnvironmentEntry" `
        -Owner $installerContract.Name).Extent.Text
    Assert-Contract (
        $snapshotSource.Contains('Get-Item -LiteralPath "Env:$Name"') -and
        $snapshotSource.Contains('Exists = $null -ne $entry') -and
        $restoreSource.Contains('if ($Snapshot.Exists)') -and
        $restoreSource.Contains('Remove-Item -LiteralPath "Env:$Name"')
    ) "$($installerContract.Name) must preserve both process environment entry presence and its exact value"
}

# Import only isolated helpers from installer ASTs. This avoids executing installer top-level effects.
$runtimeHelperNames = @(
    "Get-ProcessEnvironmentEntrySnapshot",
    "Restore-ProcessEnvironmentEntry",
    "Assert-SafeRuntimeEnvValue",
    "New-CryptographicApiKey",
    "Resolve-RuntimeApiKey",
    "Get-SecretFingerprint",
    "Resolve-RuntimeWorkspaceRoot",
    "Assert-RegularNonReparseRuntimeEnvPath",
    "Assert-ProtectedRuntimeEnvFile",
    "New-ExactAclRuntimeEnvStream",
    "Write-SecureRuntimeEnvFile",
    "New-NativeInstallerFailure",
    "Get-RuntimePrivateEnvSnapshot",
    "Invoke-RuntimePrivateEnvSnapshotOperation",
    "Remove-RuntimePrivateEnvForSnapshot",
    "Restore-RuntimePrivateEnvSnapshot",
    "Resolve-PinnedPm2Command"
)
$runtimeHelperAsts = @{}
foreach ($helperName in $runtimeHelperNames) {
    $helperAst = Get-FunctionAst -Ast $runtimeAst -Name $helperName -Owner "install-runtime-windows.ps1"
    $runtimeHelperAsts[$helperName] = $helperAst
    . ([scriptblock]::Create($helperAst.Extent.Text))
}

$rikuneHelperNames = @(
    "Get-PowerShellExe",
    "Get-ProcessEnvironmentEntrySnapshot",
    "Restore-ProcessEnvironmentEntry",
    "Invoke-ChildPowerShell",
    "Assert-SecureRuntimeEndpoint",
    "Install-Runtime",
    "Install-Stack"
)
$rikuneHelperAsts = @{}
foreach ($helperName in $rikuneHelperNames) {
    $helperAst = Get-FunctionAst -Ast $rikuneAst -Name $helperName -Owner "rikune.ps1"
    $rikuneHelperAsts[$helperName] = $helperAst
    if ($helperName -in @(
        "Get-PowerShellExe",
        "Get-ProcessEnvironmentEntrySnapshot",
        "Restore-ProcessEnvironmentEntry",
        "Invoke-ChildPowerShell",
        "Assert-SecureRuntimeEndpoint"
    )) {
        . ([scriptblock]::Create($helperAst.Extent.Text))
    }
}

# Verify that child installers use PowerShell 7 and receive secrets only through a restored process environment.
$resolvedPowerShell = Get-PowerShellExe
Assert-Contract (
    [System.IO.Path]::GetFileNameWithoutExtension($resolvedPowerShell) -ieq "pwsh"
) "Get-PowerShellExe must resolve pwsh rather than Windows PowerShell"

$childFixtureRoot = Join-Path ([System.IO.Path]::GetTempPath()) "rikune-child-env-$([Guid]::NewGuid().ToString('N'))"
New-Item -ItemType Directory -Path $childFixtureRoot -Force | Out-Null
$childFixturePath = Join-Path $childFixtureRoot "verify-child-env.ps1"
$childEnvironmentName = "RIKUNE_VERIFIER_CHILD_SECRET"
$previousChildEnvironment = Get-ProcessEnvironmentEntrySnapshot -Name $childEnvironmentName
try {
    @"
if (`$env:$childEnvironmentName -ne "child-only-secret") { exit 41 }
exit 0
"@ | Set-Content -LiteralPath $childFixturePath -Encoding utf8NoBOM
    [Environment]::SetEnvironmentVariable($childEnvironmentName, "parent-original", "Process")
    Invoke-ChildPowerShell `
        -Arguments @("-NoLogo", "-NoProfile", "-File", $childFixturePath) `
        -Environment @{ $childEnvironmentName = "child-only-secret" }
    Assert-Contract (
        [Environment]::GetEnvironmentVariable($childEnvironmentName, "Process") -eq "parent-original"
    ) "Invoke-ChildPowerShell must restore the parent process environment after child success"

    Remove-Item -LiteralPath "Env:$childEnvironmentName" -ErrorAction SilentlyContinue
    Assert-Contract (
        -not (Get-ProcessEnvironmentEntrySnapshot -Name $childEnvironmentName).Exists
    ) "Absent child relay fixture must start without an environment entry"
    Invoke-ChildPowerShell `
        -Arguments @("-NoLogo", "-NoProfile", "-File", $childFixturePath) `
        -Environment @{ $childEnvironmentName = "child-only-secret" }
    Assert-Contract (
        -not (Get-ProcessEnvironmentEntrySnapshot -Name $childEnvironmentName).Exists
    ) "Invoke-ChildPowerShell must restore a previously absent parent entry as absent"

    $supportsEmptyProcessEnvironmentEntries = (
        $PSVersionTable.PSVersion.Major -gt 7 -or
        ($PSVersionTable.PSVersion.Major -eq 7 -and $PSVersionTable.PSVersion.Minor -ge 5)
    )
    if ($supportsEmptyProcessEnvironmentEntries) {
        [Environment]::SetEnvironmentVariable($childEnvironmentName, "", "Process")
        $emptyEntry = Get-ProcessEnvironmentEntrySnapshot -Name $childEnvironmentName
        Assert-Contract (
            $emptyEntry.Exists -and $emptyEntry.Value -ceq ""
        ) "PowerShell 7.5+ child relay fixture must preserve an existing empty entry"
        Invoke-ChildPowerShell `
            -Arguments @("-NoLogo", "-NoProfile", "-File", $childFixturePath) `
            -Environment @{ $childEnvironmentName = "child-only-secret" }
        $restoredEmptyEntry = Get-ProcessEnvironmentEntrySnapshot -Name $childEnvironmentName
        Assert-Contract (
            $restoredEmptyEntry.Exists -and $restoredEmptyEntry.Value -ceq ""
        ) "Invoke-ChildPowerShell must distinguish an existing empty entry from an absent entry"
    }
} finally {
    try {
        Restore-ProcessEnvironmentEntry -Name $childEnvironmentName -Snapshot $previousChildEnvironment
        Assert-ProcessEnvironmentEntryMatchesSnapshot `
            -Name $childEnvironmentName `
            -Snapshot $previousChildEnvironment `
            -Message "PowerShell verifier must restore its original child relay environment entry exactly"
    } finally {
        Remove-Item -LiteralPath $childFixtureRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

function Write-Warn {
    param([string]$Text)
}
Assert-SecureRuntimeEndpoint -Endpoint "https://runtime.example.test"
Assert-SecureRuntimeEndpoint -Endpoint "http://host.docker.internal:18082"
Assert-Throws {
    Assert-SecureRuntimeEndpoint -Endpoint "http://runtime.example.test:18082"
} "Remote plaintext runtime HTTP must fail without explicit opt-in"
Assert-SecureRuntimeEndpoint -Endpoint "http://runtime.example.test:18082" -AllowInsecure
Assert-Throws {
    Assert-SecureRuntimeEndpoint -Endpoint "ftp://runtime.example.test"
} "Non-HTTP runtime endpoints must fail closed"

# CSPRNG and API-key resolution smoke.
$newKeySource = $runtimeHelperAsts["New-CryptographicApiKey"].Extent.Text
Assert-Contract (
    $newKeySource -match 'RandomNumberGenerator\]\s*::\s*GetBytes\s*\(\s*32\s*\)'
) "New-CryptographicApiKey must obtain exactly 32 bytes from RandomNumberGenerator"

$getRandomCommands = @(
    $runtimeAst.FindAll(
        {
            param($node)
            $node -is [System.Management.Automation.Language.CommandAst] -and
                $node.GetCommandName() -ieq "Get-Random"
        },
        $true
    )
)
Assert-Contract ($getRandomCommands.Count -eq 0) "install-runtime-windows.ps1 must not use Get-Random for credentials"

$generatedKeys = @(1..4 | ForEach-Object { New-CryptographicApiKey })
foreach ($generatedKey in $generatedKeys) {
    Assert-Contract ($generatedKey -match '^[a-f0-9]{64}$') "Generated runtime API keys must be 32-byte lowercase hexadecimal values"
}
Assert-Contract (
    (@($generatedKeys | Select-Object -Unique).Count -eq $generatedKeys.Count)
) "Repeated CSPRNG calls unexpectedly returned duplicate runtime API keys"

# Native snapshot-operation diagnostics must classify fixed metadata without exposing child output.
$nativeDiagnosticRoot = Join-Path ([System.IO.Path]::GetTempPath()) "rikune-native-diagnostic-$([Guid]::NewGuid().ToString('N'))"
$nativeDiagnosticWriter = Join-Path $nativeDiagnosticRoot "writer.mjs"
$nativeDiagnosticEnvironmentName = "RIKUNE_VERIFIER_NATIVE_DIAGNOSTIC_PATH"
$nativeDiagnosticEnvironment = Get-ProcessEnvironmentEntrySnapshot -Name $nativeDiagnosticEnvironmentName
$nativeDiagnosticRemoveEnvironment = Get-ProcessEnvironmentEntrySnapshot -Name "RIKUNE_REMOVE_PRIVATE_ENV_SNAPSHOT_PATH"
$nativeDiagnosticNativeErrorPreference = $PSNativeCommandUseErrorActionPreference
$nativeDiagnosticChildMarker = "child-secret-marker"
$nativeDiagnosticCases = @(
    @{ Snapshot = "snapshot-secret-eperm"; Category = "unlink-eperm"; ExitCode = 73; Phase = "verifier-rollback-remove"; UseRemoveWrapper = $true },
    @{ Snapshot = "snapshot-secret-ebusy"; Category = "unlink-ebusy"; ExitCode = 74; Phase = "verifier-commit-remove"; UseRemoveWrapper = $true },
    @{ Snapshot = "snapshot-secret-eacces"; Category = "unlink-eacces"; ExitCode = 75; Phase = "verifier-diagnostic"; UseRemoveWrapper = $false },
    @{ Snapshot = "snapshot-secret-acl"; Category = "acl-verify"; ExitCode = 76; Phase = "verifier-diagnostic"; UseRemoveWrapper = $false },
    @{ Snapshot = "snapshot-secret-acl-detail"; Category = "acl-snapshot-match-owner"; ExitCode = 77; Phase = "verifier-rollback-remove"; UseRemoveWrapper = $true },
    @{ Snapshot = "snapshot-secret-acl-pre-unlink"; Category = "acl-pre-unlink-rule"; ExitCode = 78; Phase = "verifier-commit-remove"; UseRemoveWrapper = $true }
)
New-Item -ItemType Directory -Path $nativeDiagnosticRoot -Force | Out-Null
try {
    @'
let snapshot = ''
process.stdin.setEncoding('utf8')
process.stdin.on('data', (chunk) => { snapshot += chunk })
process.stdin.on('end', () => {
  const mode = snapshot.trim()
  const cases = {
    'snapshot-secret-eperm': [73, `Error: EPERM: operation not permitted, unlink '${mode}-Unable to verify Windows ACL-child-secret-marker'\n`],
    'snapshot-secret-ebusy': [74, `Error: EBUSY: resource busy or locked, unlink '${mode}-child-secret-marker'\n`],
    'snapshot-secret-eacces': [75, `Error: EACCES: permission denied, unlink '${mode}-child-secret-marker'\n`],
    'snapshot-secret-acl': [76, `Error: Unable to verify Windows ACL on '${mode}-Error: EPERM: operation not permitted, unlink-child-secret-marker'\n`],
    'snapshot-secret-acl-detail': [77, `Error: RIKUNE_PRIVATE_ENV_FAILURE=acl-snapshot-match-owner: Unable to verify Windows ACL\nError: ignored '${mode}-EPERM-unlink-child-secret-marker'\n`],
    'snapshot-secret-acl-pre-unlink': [78, `Error: RIKUNE_PRIVATE_ENV_FAILURE=acl-pre-unlink-rule: Unable to verify Windows ACL\nError: ignored '${mode}-EACCES-unlink-child-secret-marker'\n`],
  }
  const selected = cases[mode] ?? [79, `Error: unclassified ${mode}-child-secret-marker\n`]
  process.stderr.write(selected[1])
  process.exit(selected[0])
})
'@ | Set-Content -LiteralPath $nativeDiagnosticWriter -Encoding utf8NoBOM
    Remove-Item -LiteralPath "Env:$nativeDiagnosticEnvironmentName" -ErrorAction SilentlyContinue
    $Error.Clear()
    $PSNativeCommandUseErrorActionPreference = $true
    foreach ($nativeDiagnosticCase in $nativeDiagnosticCases) {
        $nativeDiagnosticFailure = $null
        try {
            if ($nativeDiagnosticCase.UseRemoveWrapper) {
                Remove-RuntimePrivateEnvForSnapshot `
                    -Path (Join-Path $nativeDiagnosticRoot "target.env") `
                    -Snapshot $nativeDiagnosticCase.Snapshot `
                    -NodePath (Get-Command node -ErrorAction Stop).Source `
                    -WriterPath $nativeDiagnosticWriter `
                    -FailurePhase $nativeDiagnosticCase.Phase
            } else {
                Invoke-RuntimePrivateEnvSnapshotOperation `
                    -EnvironmentName $nativeDiagnosticEnvironmentName `
                    -Path (Join-Path $nativeDiagnosticRoot "target.env") `
                    -Snapshot $nativeDiagnosticCase.Snapshot `
                    -NodePath (Get-Command node -ErrorAction Stop).Source `
                    -WriterPath $nativeDiagnosticWriter `
                    -FailureMessage "Synthetic native snapshot operation failed" `
                    -FailurePhase $nativeDiagnosticCase.Phase
            }
        } catch {
            $nativeDiagnosticFailure = $_.Exception
        }
        Assert-Contract ($null -ne $nativeDiagnosticFailure) "Native diagnostic fixture must fail"
        Assert-Contract (
            [int]$nativeDiagnosticFailure.Data["RIKUNE_NATIVE_EXIT_CODE"] -eq $nativeDiagnosticCase.ExitCode
        ) "Native diagnostic fixture must preserve the exact child exit code"
        Assert-Contract (
            [string]$nativeDiagnosticFailure.Data["RIKUNE_NATIVE_FAILURE_CATEGORY"] -eq $nativeDiagnosticCase.Category
        ) "Native diagnostic fixture must classify '$($nativeDiagnosticCase.Category)'"
        Assert-Contract (
            [string]$nativeDiagnosticFailure.Data["RIKUNE_NATIVE_FAILURE_PHASE"] -eq $nativeDiagnosticCase.Phase
        ) "Native diagnostic fixture must preserve only the fixed failure phase"
        Assert-Contract (
            $nativeDiagnosticFailure.Message.Contains(
                "phase=$($nativeDiagnosticCase.Phase); category=$($nativeDiagnosticCase.Category); exit=$($nativeDiagnosticCase.ExitCode)"
            )
        ) "Native diagnostic fixture must expose only fixed metadata in its message"
        Assert-Contract (
            -not $nativeDiagnosticFailure.Message.Contains($nativeDiagnosticCase.Snapshot) -and
            -not $nativeDiagnosticFailure.Message.Contains($nativeDiagnosticChildMarker)
        ) "Native diagnostic fixture must not expose snapshot or child output"
        $nativeDiagnosticDataKeys = @(
            $nativeDiagnosticFailure.Data.Keys |
                ForEach-Object { [string]$_ } |
                Sort-Object
        )
        Assert-Contract (
            $nativeDiagnosticDataKeys.Count -eq 3 -and
            ($nativeDiagnosticDataKeys -join ',') -eq (
                'RIKUNE_NATIVE_EXIT_CODE,RIKUNE_NATIVE_FAILURE_CATEGORY,RIKUNE_NATIVE_FAILURE_PHASE'
            )
        ) "Native diagnostic fixture must expose exactly three fixed Data keys"
        $nativeDiagnosticDataText = [string](@($nativeDiagnosticFailure.Data.Values) -join "`n")
        Assert-Contract (
            -not $nativeDiagnosticDataText.Contains($nativeDiagnosticCase.Snapshot) -and
            -not $nativeDiagnosticDataText.Contains($nativeDiagnosticChildMarker)
        ) "Native diagnostic fixture Data must not expose snapshot or child output"
        Assert-Contract (
            $null -eq $nativeDiagnosticFailure.InnerException -and
            -not $nativeDiagnosticFailure.ToString().Contains($nativeDiagnosticCase.Snapshot) -and
            -not $nativeDiagnosticFailure.ToString().Contains($nativeDiagnosticChildMarker)
        ) "Native diagnostic fixture exception serialization must not expose child output"
        if ($nativeDiagnosticCase.UseRemoveWrapper) {
            Assert-ProcessEnvironmentEntryMatchesSnapshot `
                -Name "RIKUNE_REMOVE_PRIVATE_ENV_SNAPSHOT_PATH" `
                -Snapshot $nativeDiagnosticRemoveEnvironment `
                -Message "Native diagnostic remove wrapper must restore its selector exactly"
        } else {
            Assert-Contract (
                -not (Get-ProcessEnvironmentEntrySnapshot -Name $nativeDiagnosticEnvironmentName).Exists
            ) "Native diagnostic fixture must restore an absent selector as absent"
        }
        Assert-Contract (
            $PSNativeCommandUseErrorActionPreference -eq $true
        ) "Native diagnostic helper must not mutate the caller native-error preference"
    }
    $nativeDiagnosticErrorText = [string](@($Error) -join "`n")
    foreach ($nativeDiagnosticCase in $nativeDiagnosticCases) {
        Assert-Contract (
            -not $nativeDiagnosticErrorText.Contains($nativeDiagnosticCase.Snapshot)
        ) "Native diagnostic fixture must not retain snapshot output in the PowerShell error history"
    }
    Assert-Contract (
        -not $nativeDiagnosticErrorText.Contains($nativeDiagnosticChildMarker)
    ) "Native diagnostic fixture must not retain child output in the PowerShell error history"
} finally {
    try {
        Restore-ProcessEnvironmentEntry `
            -Name $nativeDiagnosticEnvironmentName `
            -Snapshot $nativeDiagnosticEnvironment
        Restore-ProcessEnvironmentEntry `
            -Name "RIKUNE_REMOVE_PRIVATE_ENV_SNAPSHOT_PATH" `
            -Snapshot $nativeDiagnosticRemoveEnvironment
    } finally {
        $PSNativeCommandUseErrorActionPreference = $nativeDiagnosticNativeErrorPreference
        $nativeDiagnosticCases = $null
        $nativeDiagnosticChildMarker = $null
        $nativeDiagnosticErrorText = $null
        $nativeDiagnosticDataKeys = $null
        $nativeDiagnosticDataText = $null
        Remove-Item -LiteralPath $nativeDiagnosticRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}
Assert-Contract (
    $PSNativeCommandUseErrorActionPreference -eq $nativeDiagnosticNativeErrorPreference
) "Native diagnostic fixture must restore the caller native-error preference exactly"

$explicitKey = [string]::new([char]0x65, 32)
$environmentKey = [string]::new([char]0x66, 32)
$resolvedKey = Resolve-RuntimeApiKey `
    -Name "RIKUNE_HOST_AGENT_API_KEY" `
    -EnvironmentKey $explicitKey
Assert-Contract ($resolvedKey -eq $explicitKey) "A protected process-environment Host Agent key must be honored"

$resolvedKey = Resolve-RuntimeApiKey `
    -Name "RIKUNE_RUNTIME_NODE_API_KEY" `
    -EnvironmentKey $environmentKey
Assert-Contract ($resolvedKey -eq $environmentKey) "A protected process-environment API key must be honored"

$resolvedKey = Resolve-RuntimeApiKey `
    -Name "RIKUNE_RUNTIME_NODE_API_KEY" `
    -EnvironmentKey $null
Assert-Contract ($resolvedKey -match '^[a-f0-9]{64}$') "An omitted runtime API key must be generated with the CSPRNG"

$resolvedKey = Resolve-RuntimeApiKey -Name "RIKUNE_RUNTIME_NODE_API_KEY" -EnvironmentKey " "
Assert-Contract ($resolvedKey -match '^[a-f0-9]{64}$') "A blank process-environment API key must be treated as omitted and regenerated"
Assert-Throws {
    Resolve-RuntimeApiKey -Name "RIKUNE_RUNTIME_NODE_API_KEY" -EnvironmentKey "too-short"
} "A short runtime API key must fail closed"
Assert-Throws {
    Resolve-RuntimeApiKey -Name "RIKUNE_RUNTIME_NODE_API_KEY" -EnvironmentKey "$explicitKey`n"
} "A runtime API key containing a line break must fail closed"

$fingerprint = Get-SecretFingerprint -Secret $explicitKey
Assert-Contract ($fingerprint -match '^[a-f0-9]{12}$') "Secret fingerprints must expose only 12 lowercase SHA-256 hexadecimal characters"
Assert-Contract (
    (Get-SecretFingerprint -Secret $explicitKey) -eq $fingerprint
) "Secret fingerprints must be deterministic"
$fingerprintSource = $runtimeHelperAsts["Get-SecretFingerprint"].Extent.Text
Assert-Contract (
    $fingerprintSource -match 'SHA256' -and $fingerprintSource -match 'Substring\s*\(\s*0\s*,\s*12\s*\)'
) "Get-SecretFingerprint must remain a truncated SHA-256 digest rather than exposing the secret"

# Exact workspace-path behavior.
$testRoot = Join-Path ([System.IO.Path]::GetTempPath()) "rikune-powershell-contract-$([Guid]::NewGuid().ToString('N'))"
New-Item -ItemType Directory -Path $testRoot -Force | Out-Null
try {
    $projectFixture = Join-Path $testRoot "project root"
    New-Item -ItemType Directory -Path $projectFixture -Force | Out-Null

    $requestedAbsolute = Join-Path $testRoot "custom workspace that does not exist"
    Assert-Contract (-not (Test-Path -LiteralPath $requestedAbsolute)) "Absolute workspace fixture must start absent"
    $resolvedAbsolute = Resolve-RuntimeWorkspaceRoot `
        -RequestedRoot $requestedAbsolute `
        -ProjectRoot $projectFixture `
        -LocalAppData (Join-Path $testRoot "local-app-data")
    Assert-PathEqual $resolvedAbsolute $requestedAbsolute "A requested absolute WorkspaceRoot must be preserved exactly"

    $requestedRelative = Join-Path "relative parent" "runtime workspace"
    $expectedRelative = Join-Path $projectFixture $requestedRelative
    $resolvedRelative = Resolve-RuntimeWorkspaceRoot `
        -RequestedRoot $requestedRelative `
        -ProjectRoot $projectFixture `
        -LocalAppData (Join-Path $testRoot "local-app-data")
    Assert-PathEqual $resolvedRelative $expectedRelative "A relative WorkspaceRoot must resolve exactly beneath ProjectRoot"

    $localAppDataFixture = Join-Path $testRoot "local app data"
    $expectedDefault = Join-Path $localAppDataFixture "Rikune\Runtime"
    $resolvedDefault = Resolve-RuntimeWorkspaceRoot `
        -RequestedRoot $null `
        -ProjectRoot $projectFixture `
        -LocalAppData $localAppDataFixture
    Assert-PathEqual $resolvedDefault $expectedDefault "An omitted WorkspaceRoot must resolve exactly beneath LOCALAPPDATA"

    Assert-Throws {
        Resolve-RuntimeWorkspaceRoot -RequestedRoot $null -ProjectRoot $projectFixture -LocalAppData ""
    } "Workspace resolution must fail closed when both WorkspaceRoot and LOCALAPPDATA are unavailable"
} finally {
    Remove-Item -LiteralPath $testRoot -Recurse -Force -ErrorAction SilentlyContinue
}

# Source contracts: loopback by default, no secret console output, and exact project-local PM2.
$bindHostParameter = @(
    $runtimeAst.ParamBlock.Parameters | Where-Object {
        $_.Name.VariablePath.UserPath -eq "BindHost"
    }
) | Select-Object -First 1
Assert-Contract ($null -ne $bindHostParameter) "install-runtime-windows.ps1 must declare BindHost"
$bindHostDefault = if ($null -eq $bindHostParameter.DefaultValue) {
    $null
} else {
    [string]$bindHostParameter.DefaultValue.SafeGetValue()
}
Assert-Contract ($bindHostDefault -eq "127.0.0.1") "Windows Host Agent must default to the loopback bind address"

foreach ($requiredFragment in @(
    '$capturedHostApiKey',
    '$capturedRuntimeApiKey',
    'foreach ($name in ($secretEnvironmentAliases + $privateEnvControlNames))',
    'Remove-Item -LiteralPath "Env:$name" -ErrorAction SilentlyContinue',
    'Host Agent and Runtime Node API keys must be distinct',
    'Resolve-RuntimeWorkspaceRoot',
    'Resolve-PinnedPm2Command'
)) {
    Assert-Contract ($runtimeSource.Contains($requiredFragment)) "Runtime installer is missing the integrated security contract fragment '$requiredFragment'"
}

# Wrapper contracts: prefer PowerShell 7, keep keys out of child argv, restore env, and relay HTTP opt-in explicitly.
$getPowerShellSource = $rikuneHelperAsts["Get-PowerShellExe"].Extent.Text
$pwshLookupIndex = $getPowerShellSource.IndexOf("Get-Command pwsh", [System.StringComparison]::OrdinalIgnoreCase)
$versionGateIndex = $getPowerShellSource.IndexOf("PSVersionTable.PSVersion.Major -lt 7", [System.StringComparison]::OrdinalIgnoreCase)
$currentProcessIndex = $getPowerShellSource.IndexOf("Get-Process -Id `$PID", [System.StringComparison]::OrdinalIgnoreCase)
Assert-Contract (
    $pwshLookupIndex -ge 0 -and $versionGateIndex -gt $pwshLookupIndex -and $currentProcessIndex -gt $versionGateIndex
) "Get-PowerShellExe must prefer pwsh, reject pre-7 hosts, and only then fall back to the current PowerShell 7 process"
Assert-Contract (
    $getPowerShellSource -notmatch '(?i)\bpowershell\.exe\b'
) "Get-PowerShellExe must not select Windows PowerShell 5.1"

$invokeChildSource = $rikuneHelperAsts["Invoke-ChildPowerShell"].Extent.Text
foreach ($requiredFragment in @(
    '[hashtable]$Environment',
    'Get-ProcessEnvironmentEntrySnapshot -Name $name',
    'SetEnvironmentVariable($name, [string]$Environment[$name], "Process")',
    'finally',
    'Restore-ProcessEnvironmentEntry -Name $name -Snapshot $previousEnvironment[$name]'
)) {
    Assert-Contract ($invokeChildSource.Contains($requiredFragment)) "Invoke-ChildPowerShell is missing the child environment restoration contract '$requiredFragment'"
}

function Assert-NoSecretArgumentAssignments {
    param(
        [System.Management.Automation.Language.FunctionDefinitionAst]$FunctionAst,
        [string]$Owner
    )

    $secretNames = @(
        "existingkey", "hostkey", "runtimekey", "hostagentapikey", "runtimeapikey",
        "childenvironment", "runtimeenv", "dockerenv"
    )
    $argumentAssignments = @(
        $FunctionAst.FindAll(
            {
                param($node)
                $node -is [System.Management.Automation.Language.AssignmentStatementAst] -and
                    $node.Left.Extent.Text -ieq '$args'
            },
            $true
        )
    )
    Assert-Contract ($argumentAssignments.Count -gt 0) "$Owner must construct an explicit child argument list"
    foreach ($assignmentAst in $argumentAssignments) {
        if ($assignmentAst.Right.Extent.Text -match '(?i)["'']-(?:HostAgentApiKey|RuntimeApiKey|ApiKey)["'']') {
            throw "$Owner must not put an API-key switch in child argv: $($assignmentAst.Extent.Text)"
        }
        $secretReferences = @(
            $assignmentAst.Right.FindAll(
                {
                    param($node)
                    $node -is [System.Management.Automation.Language.VariableExpressionAst] -and
                        $node.VariablePath.UserPath.ToLowerInvariant() -in $secretNames
                },
                $true
            )
        )
        if ($secretReferences.Count -gt 0) {
            throw "$Owner must not put secret variables in child argv: $($assignmentAst.Extent.Text)"
        }
    }
}

$installRuntimeAst = $rikuneHelperAsts["Install-Runtime"]
$installStackAst = $rikuneHelperAsts["Install-Stack"]
$installRuntimeSource = $installRuntimeAst.Extent.Text
$installStackSource = $installStackAst.Extent.Text
Assert-NoSecretArgumentAssignments -FunctionAst $installRuntimeAst -Owner "rikune.ps1 Install-Runtime"
Assert-NoSecretArgumentAssignments -FunctionAst $installStackAst -Owner "rikune.ps1 Install-Stack"

foreach ($requiredFragment in @(
    '$childEnvironment.RIKUNE_HOST_AGENT_API_KEY = $env:RUNTIME_HOST_AGENT_API_KEY',
    '$childEnvironment.RIKUNE_RUNTIME_NODE_API_KEY = $env:RUNTIME_API_KEY',
    'Invoke-ChildPowerShell -Arguments $args -Environment $childEnvironment',
    '"-BindHost", "127.0.0.1"',
    '"-RuntimeBindHost", "127.0.0.1"',
    '"-RuntimeAdvertisedHost", "host.docker.internal"',
    '$args += "-AllowInsecureRuntimeHttp"'
)) {
    Assert-Contract ($installRuntimeSource.Contains($requiredFragment)) "Install-Runtime is missing the secure child relay contract '$requiredFragment'"
}
foreach ($requiredFragment in @(
    '$childEnvironment.RUNTIME_HOST_AGENT_API_KEY = $hostKey',
    '$childEnvironment.RUNTIME_API_KEY = $runtimeKey',
    'Host Agent and Runtime Node API keys must be distinct',
    'Invoke-ChildPowerShell -Arguments $args -Environment $childEnvironment',
    'Assert-SecureRuntimeEndpoint -Endpoint $dockerEndpoint -AllowInsecure:$AllowInsecureRuntimeHttp',
    '$args += "-AllowInsecureRuntimeHttp"'
)) {
    Assert-Contract ($installStackSource.Contains($requiredFragment)) "Install-Stack is missing the secure child relay contract '$requiredFragment'"
}

foreach ($astContract in @($rikuneAst, $dockerAst, $runtimeAst)) {
    $allowInsecureParameter = @(
        $astContract.ParamBlock.Parameters | Where-Object {
            $_.Name.VariablePath.UserPath -eq "AllowInsecureRuntimeHttp"
        }
    ) | Select-Object -First 1
    Assert-Contract ($null -ne $allowInsecureParameter) "Every Windows installer layer must declare AllowInsecureRuntimeHttp"
}
Assert-Contract (
    $dockerSource.Contains('Assert-SecureRuntimeEndpoint -Endpoint $HostAgentEndpoint -AllowInsecure:$AllowInsecureRuntimeHttp')
) "install-docker.ps1 must enforce the relayed insecure-HTTP opt-in on the Host Agent endpoint"
Assert-Contract (
    $runtimeSource.Contains('Assert-SecureRuntimeEndpoint -Endpoint $HyperVRuntimeEndpoint -AllowInsecure:$AllowInsecureRuntimeHttp')
) "install-runtime-windows.ps1 must enforce the relayed insecure-HTTP opt-in on the Hyper-V Runtime endpoint"

$privateEnvInternalControls = @(
    'RIKUNE_VERIFY_PRIVATE_ENV_PATH',
    'RIKUNE_STAGE_DOCKER_ENV_PATH',
    'RIKUNE_REMOVE_PRIVATE_ENV_SNAPSHOT_PATH',
    'RIKUNE_RESTORE_PRIVATE_ENV_PATH',
    'RIKUNE_REMOVE_PRIVATE_ENV_PATH',
    'RIKUNE_DOCKER_ENV_SNAPSHOT_STDIN',
    'RIKUNE_DOCKER_ENV_PATH',
    'RIKUNE_DOCKER_ENV_DATA_ROOT',
    'RIKUNE_DOCKER_ENV_PROFILE',
    'RIKUNE_BUILD_HTTP_PROXY',
    'RIKUNE_BUILD_HTTPS_PROXY',
    'RIKUNE_BUILD_NO_PROXY',
    'RIKUNE_ALLOW_INSECURE_RUNTIME_HTTP',
    'RIKUNE_STAGE_LOCAL_ENV_PATH',
    'RIKUNE_LOCAL_ENV_SNAPSHOT_STDIN',
    'RIKUNE_LOCAL_EXISTING_ENV_BASE64',
    'RIKUNE_LOCAL_ENV_PATH',
    'RIKUNE_LOCAL_ENV_FORCE_KEYS',
    'RIKUNE_PRIVATE_ENV_PATH',
    'RIKUNE_PRIVATE_ENV_ACL_MODE',
    'STAGED_LOCAL_ENV_BASE64'
)
foreach ($controlName in $privateEnvInternalControls) {
    Assert-Contract ($dockerSource.Contains('"' + $controlName + '"')) "Docker installer must scrub inherited private env control '$controlName'"
    Assert-Contract ($localInstallerSource.Contains('"' + $controlName + '"')) "Local PowerShell installer must scrub inherited private env control '$controlName'"
    Assert-Contract ($runtimeSource.Contains('"' + $controlName + '"')) "Windows runtime installer must scrub inherited private env control '$controlName'"
}

foreach ($requiredFragment in @(
    'RIKUNE_STAGE_DOCKER_ENV_PATH',
    'RIKUNE_REMOVE_PRIVATE_ENV_SNAPSHOT_PATH',
    'RIKUNE_RESTORE_PRIVATE_ENV_PATH',
    'RIKUNE_DOCKER_ENV_SNAPSHOT_STDIN',
    '$privateEnvTransactionActive = $true',
    '$privateEnvTransactionCommitted = $true',
    'RIKUNE_NATIVE_EXIT_CODE',
    'exit $privateEnvFailureExitCode',
    '$previousEnvironment[$name] = Get-ProcessEnvironmentEntrySnapshot -Name $name',
    'Restore-ProcessEnvironmentEntry -Name $name -Snapshot $previousEnvironment[$name]',
    'Remove-Item -LiteralPath "Env:$name" -ErrorAction SilentlyContinue',
    '$nodeMinor -lt 9',
    'need 22.9+',
    'finally'
)) {
    Assert-Contract ($dockerSource.Contains($requiredFragment)) "Docker installer is missing the private env transaction fragment '$requiredFragment'"
}
$dockerStageIndex = $dockerSource.IndexOf('Get-PrivateEnvSnapshot -Path $envFile')
$dockerScrubIndex = $dockerSource.IndexOf('foreach ($name in ($secretEnvironmentAliases + $privateEnvControlNames))')
$dockerDependencyIndex = $dockerSource.IndexOf('& npm ci --include=dev')
$dockerWriterIndex = $dockerSource.LastIndexOf('Write-EnvFile `')
$dockerCommitIndex = $dockerSource.LastIndexOf('$privateEnvTransactionCommitted = $true')
$dockerComposeIndex = $dockerSource.IndexOf('Write-Step "Docker Compose"')
Assert-Contract (
    $dockerStageIndex -ge 0 -and
    $dockerScrubIndex -ge 0 -and
    $dockerStageIndex -gt $dockerScrubIndex -and
    $dockerDependencyIndex -gt $dockerStageIndex -and
    $dockerWriterIndex -gt $dockerDependencyIndex -and
    $dockerCommitIndex -gt $dockerWriterIndex -and
    $dockerComposeIndex -gt $dockerCommitIndex
) "Docker private env transaction must cover dependency/generate failures and commit immediately after the verified writer"

foreach ($requiredFragment in @(
    'RIKUNE_STAGE_DOCKER_ENV_PATH',
    'RIKUNE_REMOVE_PRIVATE_ENV_SNAPSHOT_PATH',
    'RIKUNE_RESTORE_PRIVATE_ENV_PATH',
    '$privateEnvTransactionActive = $true',
    '$privateEnvTransactionCommitted = $true',
    'RIKUNE_NATIVE_EXIT_CODE',
    'RIKUNE_NATIVE_FAILURE_CATEGORY',
    'RIKUNE_PRIVATE_ENV_FAILURE=',
    '$operationOutput = $Snapshot | & $NodePath $WriterPath 2>&1',
    '$nativeFailureCategory = "unclassified"',
    '$PSNativeCommandUseErrorActionPreference = $false',
    'category=$nativeFailureCategory; exit=$nativeExitCode',
    'exit $privateEnvFailureExitCode',
    'Write-SecureRuntimeEnvFile -Path $envFile -Content $envContent -RequireAbsent',
    '$previousEntry = Get-ProcessEnvironmentEntrySnapshot -Name $EnvironmentName',
    'Restore-ProcessEnvironmentEntry -Name $EnvironmentName -Snapshot $previousEntry',
    'Remove-Item -LiteralPath "Env:$name" -ErrorAction SilentlyContinue',
    '$nodeMinor -lt 9',
    'need 22.9+',
    'finally'
)) {
    Assert-Contract ($runtimeSource.Contains($requiredFragment)) "Windows runtime installer is missing the private env transaction fragment '$requiredFragment'"
}
$runtimeScrubIndex = $runtimeSource.IndexOf('foreach ($name in ($secretEnvironmentAliases + $privateEnvControlNames))')
$runtimeStageIndex = $runtimeSource.IndexOf('$privateEnvSnapshot = Get-RuntimePrivateEnvSnapshot')
$runtimeRemoveIndex = $runtimeSource.IndexOf('Remove-RuntimePrivateEnvForSnapshot `')
$runtimeDependencyIndex = $runtimeSource.IndexOf('& npm ci --include=dev')
$runtimeWriterIndex = $runtimeSource.LastIndexOf('Write-SecureRuntimeEnvFile -Path $envFile')
$runtimeCommitIndex = $runtimeSource.LastIndexOf('$privateEnvTransactionCommitted = $true')
$runtimeStartIndex = $runtimeSource.IndexOf('Write-Step "Starting Windows Host Agent"')
Assert-Contract (
    $runtimeScrubIndex -ge 0 -and
    $runtimeStageIndex -gt $runtimeScrubIndex -and
    $runtimeRemoveIndex -gt $runtimeStageIndex -and
    $runtimeDependencyIndex -gt $runtimeRemoveIndex -and
    $runtimeWriterIndex -gt $runtimeDependencyIndex -and
    $runtimeCommitIndex -gt $runtimeWriterIndex -and
    $runtimeStartIndex -gt $runtimeCommitIndex
) "Windows runtime private env transaction must remove the old file before npm, commit immediately after the verified writer, and exclude service startup from rollback"

foreach ($requiredFragment in @(
    'RIKUNE_STAGE_LOCAL_ENV_PATH',
    'RIKUNE_REMOVE_PRIVATE_ENV_SNAPSHOT_PATH',
    'RIKUNE_RESTORE_PRIVATE_ENV_PATH',
    'RIKUNE_LOCAL_ENV_SNAPSHOT_STDIN',
    '$privateEnvTransactionActive = $true',
    '$privateEnvTransactionCommitted = $true',
    '$previousWriterEnvironment[$name] = Get-ProcessEnvironmentEntrySnapshot -Name $name',
    'Restore-ProcessEnvironmentEntry -Name $name -Snapshot $previousWriterEnvironment[$name]',
    '$nodeMinor -lt 9',
    'need 22.9+',
    'finally'
)) {
    Assert-Contract ($localInstallerSource.Contains($requiredFragment)) "Local PowerShell installer is missing the private env transaction fragment '$requiredFragment'"
}
$localStageIndex = $localInstallerSource.IndexOf('Get-LocalPrivateEnvSnapshot -Path $envFile')
$localScrubIndex = $localInstallerSource.IndexOf(') | ForEach-Object { Remove-Item "Env:$_" -ErrorAction SilentlyContinue }')
$localDependencyIndex = $localInstallerSource.IndexOf('npm ci --include=dev')
$localWriterIndex = $localInstallerSource.IndexOf('RIKUNE_LOCAL_ENV_SNAPSHOT_STDIN = "1"')
$localCommitIndex = $localInstallerSource.LastIndexOf('$privateEnvTransactionCommitted = $true')
Assert-Contract (
    $localStageIndex -ge 0 -and
    $localScrubIndex -ge 0 -and
    $localStageIndex -gt $localScrubIndex -and
    $localDependencyIndex -gt $localStageIndex -and
    $localWriterIndex -gt $localDependencyIndex -and
    $localCommitIndex -gt $localWriterIndex
) "Local PowerShell private env transaction must cover dependency failures and commit after the verified writer"

$consoleCommands = @(
    "Write-Host", "Write-Output", "Write-Information", "Write-Verbose", "Write-Debug",
    "Write-Warning", "Write-Error", "Write-Progress", "Out-Host", "Tee-Object", "echo",
    "Write-Info", "Write-Success", "Write-Warning-Message", "Write-Error-Message"
)
$secretVariableNames = @(
    "apikey",
    "suppliedkey",
    "environmentkey",
    "existingkey",
    "stdinapikey",
    "environmentapikey",
    "envcontent",
    "runtimeenvvalues",
    "existingruntimeenv"
)
function Test-IsFingerprintProtectedReference {
    param(
        [System.Management.Automation.Language.VariableExpressionAst]$Reference,
        [System.Management.Automation.Language.CommandAst]$OutputCommand
    )

    $ancestor = $Reference.Parent
    while ($null -ne $ancestor -and $ancestor -ne $OutputCommand) {
        if (
            $ancestor -is [System.Management.Automation.Language.CommandAst] -and
            $ancestor.GetCommandName() -ieq "Get-SecretFingerprint"
        ) {
            return $true
        }
        $ancestor = $ancestor.Parent
    }
    return $false
}

$runtimeOutputCommands = @(
    $runtimeAst.FindAll(
        {
            param($node)
            $node -is [System.Management.Automation.Language.CommandAst] -and
                $node.GetCommandName() -in $consoleCommands
        },
        $true
    )
)
foreach ($commandAst in $runtimeOutputCommands) {
    $referencedSecrets = @(
        $commandAst.FindAll(
            {
                param($node)
                $node -is [System.Management.Automation.Language.VariableExpressionAst] -and
                    $node.VariablePath.UserPath.ToLowerInvariant() -in $secretVariableNames
            },
            $true
        )
    )
    if ($referencedSecrets.Count -eq 0) { continue }

    foreach ($secretReference in $referencedSecrets) {
        $isApiKey = $secretReference.VariablePath.UserPath -ieq "apiKey"
        $isFingerprintProtected = $isApiKey -and (
            Test-IsFingerprintProtectedReference -Reference $secretReference -OutputCommand $commandAst
        )
        if (-not $isFingerprintProtected) {
            throw "Runtime installer console output must not reference secret material: $($commandAst.Extent.Text)"
        }
    }
}

$runtimeOutputPipelines = @(
    $runtimeAst.FindAll(
        {
            param($node)
            if ($node -isnot [System.Management.Automation.Language.PipelineAst]) { return $false }
            foreach ($element in @($node.PipelineElements)) {
                if (
                    $element -is [System.Management.Automation.Language.CommandAst] -and
                    $element.GetCommandName() -in $consoleCommands
                ) {
                    return $true
                }
            }
            return $false
        },
        $true
    )
)
foreach ($pipelineAst in $runtimeOutputPipelines) {
    $pipelineOutputCommands = @(
        $pipelineAst.PipelineElements | Where-Object {
            $_ -is [System.Management.Automation.Language.CommandAst] -and
                $_.GetCommandName() -in $consoleCommands
        }
    )
    $pipelineSecretReferences = @(
        $pipelineAst.FindAll(
            {
                param($node)
                $node -is [System.Management.Automation.Language.VariableExpressionAst] -and
                    $node.VariablePath.UserPath.ToLowerInvariant() -in $secretVariableNames
            },
            $true
        )
    )
    foreach ($secretReference in $pipelineSecretReferences) {
        $protected = $false
        if ($secretReference.VariablePath.UserPath -ieq "apiKey") {
            foreach ($outputCommand in $pipelineOutputCommands) {
                if (Test-IsFingerprintProtectedReference -Reference $secretReference -OutputCommand $outputCommand) {
                    $protected = $true
                    break
                }
            }
        }
        if (-not $protected) {
            throw "Runtime installer output pipeline must not reference secret material: $($pipelineAst.Extent.Text)"
        }
    }
}

$runtimeCommands = @(
    $runtimeAst.FindAll(
        {
            param($node)
            $node -is [System.Management.Automation.Language.CommandAst]
        },
        $true
    )
)
foreach ($commandAst in $runtimeCommands) {
    $commandName = $commandAst.GetCommandName()
    if ($commandName -match '(?i)^pm2(?:\.cmd)?$') {
        throw "install-runtime-windows.ps1 must never invoke a global PM2 command"
    }
    if ($commandName -ieq "Get-Command" -and $commandAst.Extent.Text -match '(?i)\bpm2\b') {
        throw "install-runtime-windows.ps1 must not resolve PM2 from the global PATH"
    }
    if (
        ($commandName -ieq "npx" -and $commandAst.Extent.Text -match '(?i)\bpm2\b') -or
        ($commandName -ieq "npm" -and $commandAst.Extent.Text -match '(?i)\bexec\s+pm2\b') -or
        ($commandName -ieq "npm" -and $commandAst.Extent.Text -match '(?i)\binstall\b.*(?:\bpm2\b.*(?:-g|--global)|(?:-g|--global).*\bpm2\b)')
    ) {
        throw "install-runtime-windows.ps1 must not install or execute PM2 through a global/package-runner path"
    }
}

$pm2ResolverSource = $runtimeHelperAsts["Resolve-PinnedPm2Command"].Extent.Text
foreach ($requiredFragment in @(
    "devDependencies.pm2",
    "node_modules\.bin\pm2.cmd",
    "node_modules\pm2\package.json",
    "actualVersion -ne expectedVersion"
)) {
    Assert-Contract (
        $pm2ResolverSource.Replace('$', '') -match [regex]::Escape($requiredFragment.Replace('$', ''))
    ) "Resolve-PinnedPm2Command is missing the exact local PM2 contract fragment '$requiredFragment'"
}

$manifest = Get-Content -LiteralPath (Join-Path $projectRoot "package.json") -Raw | ConvertFrom-Json
$expectedPm2Version = [string]$manifest.devDependencies.pm2
Assert-Contract ($expectedPm2Version -match '^\d+\.\d+\.\d+$') "package.json must pin devDependencies.pm2 to an exact version"
$lock = Get-Content -LiteralPath (Join-Path $projectRoot "package-lock.json") -Raw | ConvertFrom-Json -AsHashtable
$lockRoot = $lock["packages"][""]
$lockPm2 = $lock["packages"]["node_modules/pm2"]
Assert-Contract ($null -ne $lockRoot) "package-lock.json is missing its root package entry"
Assert-Contract ($null -ne $lockPm2) "package-lock.json is missing node_modules/pm2"
Assert-Contract ([string]$lockRoot["devDependencies"]["pm2"] -eq $expectedPm2Version) "package-lock.json root PM2 pin must match package.json"
Assert-Contract ([string]$lockPm2["version"] -eq $expectedPm2Version) "package-lock.json installed PM2 version must match the exact root pin"

$secureCreatorSource = $runtimeHelperAsts["New-ExactAclRuntimeEnvStream"].Extent.Text
foreach ($requiredFragment in @(
    "FileSecurity]::new()",
    "SetOwner(`$currentSid)",
    "SetAccessRuleProtection(`$true, `$false)",
    "FileSystemAccessRule]::new(",
    "FileSystemRights]::FullControl",
    "InheritanceFlags]::None",
    "PropagationFlags]::None",
    "AccessControlType]::Allow",
    "SetAccessRule(`$rule)",
    "FileSystemAclExtensions]::Create(",
    "FileMode]::CreateNew",
    "FileShare]::None",
    "FileOptions]::WriteThrough"
)) {
    Assert-Contract ($secureCreatorSource.Contains($requiredFragment)) "New-ExactAclRuntimeEnvStream is missing '$requiredFragment'"
}
Assert-Contract (
    $secureCreatorSource -match 'FileOptions\]::WriteThrough,\s*\$security\s*\)'
) "New-ExactAclRuntimeEnvStream must pass the exact FileSecurity descriptor to Create"

$secureWriterSource = $runtimeHelperAsts["Write-SecureRuntimeEnvFile"].Extent.Text
foreach ($requiredFragment in @(
    "[switch]`$RequireAbsent",
    "Runtime environment transaction target appeared before the final writer",
    "New-ExactAclRuntimeEnvStream -Path `$TargetPath",
    "Assert-ProtectedRuntimeEnvFile -Path `$temporaryPath",
    "UTF8Encoding]::new(`$false).GetBytes(`$Content)",
    "`$stream.Write(`$contentBytes, 0, `$contentBytes.Length)",
    "`$stream.Flush(`$true)",
    "File]::Move(`$temporaryPath, `$absolutePath, `$false)",
    "File]::Move(`$temporaryPath, `$absolutePath, `$true)"
)) {
    Assert-Contract ($secureWriterSource.Contains($requiredFragment)) "Write-SecureRuntimeEnvFile is missing '$requiredFragment'"
}
$secureCreateIndex = $secureWriterSource.IndexOf("& `$SecureFileCreator `$temporaryPath", [System.StringComparison]::Ordinal)
$aclVerifyIndex = $secureWriterSource.IndexOf("Assert-ProtectedRuntimeEnvFile -Path `$temporaryPath", [System.StringComparison]::Ordinal)
$secretWriteIndex = $secureWriterSource.IndexOf("`$stream.Write(`$contentBytes", [System.StringComparison]::Ordinal)
$durableFlushIndex = $secureWriterSource.IndexOf("`$stream.Flush(`$true)", [System.StringComparison]::Ordinal)
$atomicMoveIndex = $secureWriterSource.IndexOf("File]::Move", [System.StringComparison]::Ordinal)
$targetVerifyIndex = $secureWriterSource.LastIndexOf("Assert-ProtectedRuntimeEnvFile -Path `$absolutePath", [System.StringComparison]::Ordinal)
Assert-Contract (
    $secureCreateIndex -ge 0 -and
    $aclVerifyIndex -gt $secureCreateIndex -and
    $secretWriteIndex -gt $aclVerifyIndex -and
    $durableFlushIndex -gt $secretWriteIndex -and
    $atomicMoveIndex -gt $durableFlushIndex -and
    $targetVerifyIndex -gt $atomicMoveIndex
) "Runtime env writer must atomically create with an exact ACL, verify, write, durably flush, atomically replace, and re-verify in order"

$nodeWriter = Join-Path $projectRoot "scripts/write-docker-runtime-env.mjs"
$nodeWriterSource = [System.IO.File]::ReadAllText($nodeWriter)
$windowsBranchIndex = $nodeWriterSource.IndexOf("if (platform === 'win32')", [System.StringComparison]::Ordinal)
Assert-Contract ($windowsBranchIndex -ge 0) "Node secure env writer must define an explicit Windows branch"
$exclusiveCreateIndex = $nodeWriterSource.IndexOf("fs.openSync(temporaryPath, 'wx'", $windowsBranchIndex, [System.StringComparison]::Ordinal)
$nodeTempAclIndex = $nodeWriterSource.IndexOf("restrictWindowsAcl(temporaryPath)", $windowsBranchIndex, [System.StringComparison]::Ordinal)
$nodeSecretWriteIndex = $nodeWriterSource.IndexOf("fs.writeFileSync(descriptor, normalizedContent", $windowsBranchIndex, [System.StringComparison]::Ordinal)
$nodeFsyncIndex = $nodeWriterSource.IndexOf("fs.fsyncSync(descriptor)", $windowsBranchIndex, [System.StringComparison]::Ordinal)
$nodeRenameIndex = $nodeWriterSource.IndexOf("fs.renameSync(temporaryPath, absoluteTarget)", $windowsBranchIndex, [System.StringComparison]::Ordinal)
$nodeTargetAclIndex = $nodeWriterSource.IndexOf("restrictWindowsAcl(absoluteTarget)", $windowsBranchIndex, [System.StringComparison]::Ordinal)
Assert-Contract (
    $windowsBranchIndex -ge 0 -and
    $exclusiveCreateIndex -gt $windowsBranchIndex -and
    $nodeTempAclIndex -gt $exclusiveCreateIndex -and
    $nodeSecretWriteIndex -gt $nodeTempAclIndex -and
    $nodeFsyncIndex -gt $nodeSecretWriteIndex -and
    $nodeRenameIndex -gt $nodeFsyncIndex -and
    $nodeTargetAclIndex -gt $nodeRenameIndex
) "Node Windows env writer must exclusively create, ACL-protect, write, fsync, atomically rename, and re-verify the target in order"

# Windows-only integration: exercise both secure writers against legacy broad ACLs.
if ($IsWindows) {
    function Get-AllowRulesForSid {
        param(
            [System.Security.AccessControl.FileSecurity]$Acl,
            [string]$Sid
        )

        $matchingRules = @()
        foreach ($rule in @($Acl.Access)) {
            if ($rule.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) {
                continue
            }
            try {
                $ruleSid = $rule.IdentityReference.Translate(
                    [System.Security.Principal.SecurityIdentifier]
                ).Value
            } catch {
                continue
            }
            if ($ruleSid -eq $Sid) { $matchingRules += $rule }
        }
        return @($matchingRules)
    }

    function Assert-ProtectedFileAcl {
        param(
            [string]$Path,
            [string]$Description
        )

        $acl = Get-Acl -LiteralPath $Path
        Assert-Contract $acl.AreAccessRulesProtected "$Description must have ACL inheritance disabled"
        $currentSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
        $rules = @($acl.GetAccessRules(
            $true,
            $true,
            [System.Security.Principal.SecurityIdentifier]
        ))
        Assert-Contract ($rules.Count -eq 1) "$Description must have exactly one ACL entry"
        $rule = $rules[0]
        Assert-Contract (
            -not $rule.IsInherited -and
            $rule.IdentityReference.Value -eq $currentSid -and
            $rule.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow -and
            $rule.FileSystemRights -eq [System.Security.AccessControl.FileSystemRights]::FullControl -and
            $rule.InheritanceFlags -eq [System.Security.AccessControl.InheritanceFlags]::None -and
            $rule.PropagationFlags -eq [System.Security.AccessControl.PropagationFlags]::None
        ) "$Description must grant only the current Windows identity FullControl"
    }

    function Add-LegacyEveryoneAce {
        param([string]$Path)

        & icacls.exe $Path "/inheritance:e" "/grant:r" "*S-1-1-0:(F)" *> $null
        if ($LASTEXITCODE -ne 0) {
            throw "Unable to create the legacy Everyone ACL fixture"
        }
        $legacyAcl = Get-Acl -LiteralPath $Path
        Assert-Contract (
            @(Get-AllowRulesForSid -Acl $legacyAcl -Sid "S-1-1-0").Count -gt 0
        ) "Legacy ACL fixture must grant Everyone access before replacement"
    }

    $nodeCommand = (Get-Command node -ErrorAction Stop).Source
    $aclTestRoot = Join-Path ([System.IO.Path]::GetTempPath()) "rikune-windows-acl-$([Guid]::NewGuid().ToString('N'))"
    New-Item -ItemType Directory -Path $aclTestRoot -Force | Out-Null
    $targetPath = Join-Path $aclTestRoot ".docker-runtime.env"
    $dataRoot = Join-Path $aclTestRoot "data"
    $managedEnvironment = @{
        RIKUNE_DOCKER_ENV_PATH = $targetPath
        RIKUNE_DOCKER_ENV_DATA_ROOT = $dataRoot
        RIKUNE_DOCKER_ENV_PROFILE = "static"
        RIKUNE_BUILD_HTTP_PROXY = ""
        RIKUNE_BUILD_HTTPS_PROXY = ""
        RIKUNE_BUILD_NO_PROXY = "localhost,127.0.0.1"
        RIKUNE_API_KEY = [string]::new([char]0x61, 64)
        RIKUNE_ANALYZER_API_KEY = $null
        RUNTIME_HOST_AGENT_ENDPOINT = $null
        RUNTIME_HOST_AGENT_API_KEY = $null
        RUNTIME_API_KEY = $null
    }
    $previousEnvironment = @{}

    try {
        $powerShellTarget = Join-Path $aclTestRoot ".env.runtime-windows"
        [System.IO.File]::WriteAllText(
            $powerShellTarget,
            "OLD_POWERSHELL_MARKER=true`nHOST_AGENT_API_KEY=legacy-key`n",
            [System.Text.UTF8Encoding]::new($false)
        )
        Add-LegacyEveryoneAce -Path $powerShellTarget
        $powerShellContent = "HOST_AGENT_API_KEY=$([string]::new([char]0x62, 64))`n"
        Write-SecureRuntimeEnvFile -Path $powerShellTarget -Content $powerShellContent
        Assert-Contract (
            [System.IO.File]::ReadAllText($powerShellTarget) -eq $powerShellContent
        ) "PowerShell secure env writer must atomically replace legacy content"
        Assert-ProtectedFileAcl -Path $powerShellTarget -Description "PowerShell runtime env file"
        Assert-Contract (
            @(Get-ChildItem -LiteralPath $aclTestRoot -Filter "*.tmp" -Force).Count -eq 0
        ) "PowerShell secure env writer must not leave temporary files behind"

        $runtimeTransactionOriginalBytes = [System.IO.File]::ReadAllBytes($powerShellTarget)
        $runtimeTransactionPreviousControls = @{}
        $runtimeTransactionSnapshot = $null
        foreach ($name in $privateEnvInternalControls) {
            $runtimeTransactionPreviousControls[$name] = Get-ProcessEnvironmentEntrySnapshot -Name $name
            Remove-Item -LiteralPath "Env:$name" -ErrorAction SilentlyContinue
        }
        foreach ($name in $privateEnvInternalControls) {
            Assert-Contract (
                -not (Get-ProcessEnvironmentEntrySnapshot -Name $name).Exists
            ) "Windows runtime transaction must truly remove inherited private env control '$name'"
        }
        try {
            $runtimeTransactionSnapshot = Get-RuntimePrivateEnvSnapshot `
                -Path $powerShellTarget `
                -NodePath $nodeCommand `
                -WriterPath $nodeWriter
            Remove-RuntimePrivateEnvForSnapshot `
                -Path $powerShellTarget `
                -Snapshot $runtimeTransactionSnapshot `
                -NodePath $nodeCommand `
                -WriterPath $nodeWriter `
                -FailurePhase "verifier-rollback-remove"
            Assert-Contract (
                -not (Test-Path -LiteralPath $powerShellTarget)
            ) "Windows runtime transaction must keep the protected env absent during lifecycle commands"

            Restore-RuntimePrivateEnvSnapshot `
                -Path $powerShellTarget `
                -Snapshot $runtimeTransactionSnapshot `
                -NodePath $nodeCommand `
                -WriterPath $nodeWriter
            Assert-Contract (
                [Convert]::ToBase64String([System.IO.File]::ReadAllBytes($powerShellTarget)) -eq
                    [Convert]::ToBase64String($runtimeTransactionOriginalBytes)
            ) "Windows runtime transaction rollback must restore exact bytes"
            Assert-ProtectedFileAcl -Path $powerShellTarget -Description "Rolled-back Windows runtime env file"

            Remove-RuntimePrivateEnvForSnapshot `
                -Path $powerShellTarget `
                -Snapshot $runtimeTransactionSnapshot `
                -NodePath $nodeCommand `
                -WriterPath $nodeWriter `
                -FailurePhase "verifier-commit-remove"
            $runtimeTransactionReplacement = "HOST_AGENT_API_KEY=$([string]::new([char]0x63, 64))`n"
            Write-SecureRuntimeEnvFile `
                -Path $powerShellTarget `
                -Content $runtimeTransactionReplacement `
                -RequireAbsent
            Assert-Contract (
                [System.IO.File]::ReadAllText($powerShellTarget) -eq $runtimeTransactionReplacement
            ) "Windows runtime transaction must commit only the verified replacement"
            Assert-ProtectedFileAcl -Path $powerShellTarget -Description "Committed Windows runtime env file"
        } finally {
            $runtimeTransactionSnapshot = $null
            foreach ($name in $privateEnvInternalControls) {
                Restore-ProcessEnvironmentEntry `
                    -Name $name `
                    -Snapshot $runtimeTransactionPreviousControls[$name]
            }
            foreach ($name in $privateEnvInternalControls) {
                Assert-ProcessEnvironmentEntryMatchesSnapshot `
                    -Name $name `
                    -Snapshot $runtimeTransactionPreviousControls[$name] `
                    -Message "Windows runtime transaction must restore private env control '$name' exactly"
            }
        }

        $failureTarget = Join-Path $aclTestRoot ".env.runtime-windows.failure"
        $failureOriginalContent = "ORIGINAL_TARGET_MUST_SURVIVE=true`n"
        [System.IO.File]::WriteAllText(
            $failureTarget,
            $failureOriginalContent,
            [System.Text.UTF8Encoding]::new($false)
        )
        Assert-Throws {
            Write-SecureRuntimeEnvFile `
                -Path $failureTarget `
                -Content "SECRET_MUST_NOT_REPLACE_TARGET=true`n" `
                -SecureFileCreator {
                    param([string]$TemporaryPath)

                    $currentSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
                    $security = [System.Security.AccessControl.FileSecurity]::new()
                    $security.SetOwner($currentSid)
                    $security.SetAccessRuleProtection($true, $false)
                    foreach ($sid in @(
                        $currentSid,
                        [System.Security.Principal.SecurityIdentifier]::new("S-1-1-0")
                    )) {
                        $security.AddAccessRule(
                            [System.Security.AccessControl.FileSystemAccessRule]::new(
                                $sid,
                                [System.Security.AccessControl.FileSystemRights]::FullControl,
                                [System.Security.AccessControl.InheritanceFlags]::None,
                                [System.Security.AccessControl.PropagationFlags]::None,
                                [System.Security.AccessControl.AccessControlType]::Allow
                            )
                        )
                    }
                    return [System.IO.FileSystemAclExtensions]::Create(
                        [System.IO.FileInfo]::new($TemporaryPath),
                        [System.IO.FileMode]::CreateNew,
                        [System.Security.AccessControl.FileSystemRights]::FullControl,
                        [System.IO.FileShare]::None,
                        4096,
                        [System.IO.FileOptions]::WriteThrough,
                        $security
                    )
                }
        } "PowerShell runtime env writer must reject an insecure creator before writing secret content"
        Assert-Contract (
            [System.IO.File]::ReadAllText($failureTarget) -eq $failureOriginalContent
        ) "Insecure creator rejection must leave the previous runtime env target untouched"
        Assert-Contract (
            -not [System.IO.File]::ReadAllText($failureTarget).Contains("SECRET_MUST_NOT_REPLACE_TARGET")
        ) "Insecure creator rejection must happen before secret content is written"
        Assert-Contract (
            @(Get-ChildItem -LiteralPath $aclTestRoot -Filter "*.tmp" -Force).Count -eq 0
        ) "Insecure creator rejection must clean the PowerShell runtime env temporary file"

        [System.IO.File]::WriteAllText(
            $targetPath,
            "OLD_MARKER=true`nRIKUNE_API_KEY=legacy-key`n",
            [System.Text.UTF8Encoding]::new($false)
        )
        Add-LegacyEveryoneAce -Path $targetPath

        foreach ($name in $managedEnvironment.Keys) {
            $previousEnvironment[$name] = Get-ProcessEnvironmentEntrySnapshot -Name $name
            if ($null -eq $managedEnvironment[$name]) {
                Remove-Item -LiteralPath "Env:$name" -ErrorAction SilentlyContinue
            } else {
                [Environment]::SetEnvironmentVariable($name, [string]$managedEnvironment[$name], "Process")
            }
        }
        foreach ($name in @($managedEnvironment.Keys | Where-Object { $null -eq $managedEnvironment[$_] })) {
            Assert-Contract (
                -not (Get-ProcessEnvironmentEntrySnapshot -Name $name).Exists
            ) "Node writer fixture must truly remove optional environment entry '$name'"
        }
        try {
            & $nodeCommand $nodeWriter
            Assert-Contract ($LASTEXITCODE -ne 0) "Node secure Docker env writer must reject a legacy broad ACL instead of laundering it"
            Assert-Contract (
                [System.IO.File]::ReadAllText($targetPath).Contains("OLD_MARKER=true")
            ) "Rejected legacy Docker env content must remain untouched"

            Remove-Item -LiteralPath $targetPath -Force
            & $nodeCommand $nodeWriter
            if ($LASTEXITCODE -ne 0) { throw "Node secure Docker env writer failed with exit code $LASTEXITCODE" }
        } finally {
            foreach ($name in $managedEnvironment.Keys) {
                Restore-ProcessEnvironmentEntry -Name $name -Snapshot $previousEnvironment[$name]
            }
            foreach ($name in $managedEnvironment.Keys) {
                Assert-ProcessEnvironmentEntryMatchesSnapshot `
                    -Name $name `
                    -Snapshot $previousEnvironment[$name] `
                    -Message "Node writer fixture must restore environment entry '$name' exactly"
            }
        }

        $rewrittenContent = [System.IO.File]::ReadAllText($targetPath)
        Assert-Contract (-not $rewrittenContent.Contains("OLD_MARKER")) "Node secure env writer must atomically replace legacy content"
        Assert-Contract (
            $rewrittenContent.Contains("RIKUNE_API_KEY=$($managedEnvironment.RIKUNE_API_KEY)")
        ) "Node secure env writer did not persist the requested analyzer key"

        Assert-ProtectedFileAcl -Path $targetPath -Description "Node Docker runtime env file"

        $snapshotOriginalBytes = [System.IO.File]::ReadAllBytes($targetPath)
        $snapshotEnvironmentNames = @(
            "RIKUNE_STAGE_DOCKER_ENV_PATH",
            "RIKUNE_REMOVE_PRIVATE_ENV_SNAPSHOT_PATH",
            "RIKUNE_RESTORE_PRIVATE_ENV_PATH"
        )
        $snapshotPreviousEnvironment = @{}
        foreach ($name in $snapshotEnvironmentNames) {
            $snapshotPreviousEnvironment[$name] = Get-ProcessEnvironmentEntrySnapshot -Name $name
        }
        try {
            [Environment]::SetEnvironmentVariable("RIKUNE_STAGE_DOCKER_ENV_PATH", $targetPath, "Process")
            $privateSnapshot = [string](@(& $nodeCommand $nodeWriter) -join '')
            if ($LASTEXITCODE -ne 0) { throw "Node private env snapshot capture failed with exit code $LASTEXITCODE" }
            Remove-Item -LiteralPath "Env:RIKUNE_STAGE_DOCKER_ENV_PATH" -ErrorAction SilentlyContinue
            Assert-Contract (
                -not (Get-ProcessEnvironmentEntrySnapshot -Name "RIKUNE_STAGE_DOCKER_ENV_PATH").Exists
            ) "Node snapshot fixture must truly remove the stage selector"

            [Environment]::SetEnvironmentVariable("RIKUNE_REMOVE_PRIVATE_ENV_SNAPSHOT_PATH", $targetPath, "Process")
            $privateSnapshot | & $nodeCommand $nodeWriter
            if ($LASTEXITCODE -ne 0) { throw "Node private env snapshot removal failed with exit code $LASTEXITCODE" }
            Assert-Contract (-not (Test-Path -LiteralPath $targetPath)) "Snapshot removal must remove the exact protected source"
            Remove-Item -LiteralPath "Env:RIKUNE_REMOVE_PRIVATE_ENV_SNAPSHOT_PATH" -ErrorAction SilentlyContinue
            Assert-Contract (
                -not (Get-ProcessEnvironmentEntrySnapshot -Name "RIKUNE_REMOVE_PRIVATE_ENV_SNAPSHOT_PATH").Exists
            ) "Node snapshot fixture must truly remove the removal selector"

            [Environment]::SetEnvironmentVariable("RIKUNE_RESTORE_PRIVATE_ENV_PATH", $targetPath, "Process")
            $privateSnapshot | & $nodeCommand $nodeWriter
            if ($LASTEXITCODE -ne 0) { throw "Node private env snapshot restoration failed with exit code $LASTEXITCODE" }
        } finally {
            foreach ($name in $snapshotEnvironmentNames) {
                Restore-ProcessEnvironmentEntry -Name $name -Snapshot $snapshotPreviousEnvironment[$name]
            }
            foreach ($name in $snapshotEnvironmentNames) {
                Assert-ProcessEnvironmentEntryMatchesSnapshot `
                    -Name $name `
                    -Snapshot $snapshotPreviousEnvironment[$name] `
                    -Message "Node snapshot fixture must restore selector '$name' exactly"
            }
            $privateSnapshot = $null
        }
        Assert-Contract (
            [Convert]::ToBase64String([System.IO.File]::ReadAllBytes($targetPath)) -eq
                [Convert]::ToBase64String($snapshotOriginalBytes)
        ) "Windows private env snapshot restoration must preserve exact UTF-8 bytes"
        Assert-ProtectedFileAcl -Path $targetPath -Description "Restored Node Docker runtime env file"

        $temporaryFiles = @(Get-ChildItem -LiteralPath $aclTestRoot -Filter ".docker-runtime.env.*.tmp" -Force)
        Assert-Contract ($temporaryFiles.Count -eq 0) "Node secure env writer must not leave temporary files behind"

        $pm2Contract = Resolve-PinnedPm2Command -ProjectRoot $projectRoot
        $expectedPm2Command = Join-Path $projectRoot "node_modules\.bin\pm2.cmd"
        Assert-PathEqual $pm2Contract.Command $expectedPm2Command "Runtime installer must resolve the project-local PM2 command"
        Assert-Contract ($pm2Contract.Version -eq $expectedPm2Version) "Resolved local PM2 version must match the exact manifest pin"
    } finally {
        foreach ($name in $managedEnvironment.Keys) {
            if ($previousEnvironment.ContainsKey($name)) {
                Restore-ProcessEnvironmentEntry -Name $name -Snapshot $previousEnvironment[$name]
            }
        }
        Remove-Item -LiteralPath $aclTestRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
} else {
    Write-Host "Skipping Windows ACL integration smoke on non-Windows PowerShell"
}

Write-Host "PowerShell installer contracts verified"
