$ErrorActionPreference = "Stop"

$resultPrefix = "RIKUNE_WINDOWS_UTILS_PROBE="
$resultToken = "fullclr-utils-probe-bootstrap-failed-shape"
$probeRoot = $null
$compilerResult = $null
$helperResult = $null
$bootstrapPhase = "unclassified"

function Get-CanonicalWindowsSystemRoot {
    $systemRootValue = [Environment]::GetEnvironmentVariable("SystemRoot", "Process")
    $windirValue = [Environment]::GetEnvironmentVariable("WINDIR", "Process")
    if ([string]::IsNullOrWhiteSpace($systemRootValue)) {
        $systemRootValue = $windirValue
    }
    if ([string]::IsNullOrWhiteSpace($systemRootValue)) {
        throw "Trusted Windows system root is unavailable"
    }

    $systemRoot = [System.IO.Path]::GetFullPath($systemRootValue).TrimEnd('\')
    if ($systemRoot -notmatch '^[A-Za-z]:\\') {
        throw "Trusted Windows system root is not drive-qualified"
    }
    if (-not [string]::IsNullOrWhiteSpace($windirValue)) {
        $windir = [System.IO.Path]::GetFullPath($windirValue).TrimEnd('\')
        if (-not [string]::Equals($systemRoot, $windir, [StringComparison]::OrdinalIgnoreCase)) {
            throw "Trusted Windows system roots disagree"
        }
    }
    $systemDirectory = [System.IO.Path]::GetFullPath([Environment]::SystemDirectory).TrimEnd('\')
    $operatingSystemRoot = [System.IO.Directory]::GetParent($systemDirectory).FullName.TrimEnd('\')
    if (-not [string]::Equals(
        $systemRoot,
        $operatingSystemRoot,
        [StringComparison]::OrdinalIgnoreCase
    )) {
        throw "Trusted Windows system root does not match the operating system"
    }
    return $systemRoot
}

function Get-TrustedSignedFile {
    param(
        [string]$ExpectedPath
    )

    $expected = [System.IO.Path]::GetFullPath($ExpectedPath)
    $item = Get-Item -LiteralPath $expected -Force -ErrorAction Stop
    if (
        $item.PSIsContainer -or
        (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) -or
        -not [string]::Equals(
            [System.IO.Path]::GetFullPath($item.FullName),
            $expected,
            [StringComparison]::OrdinalIgnoreCase
        )
    ) {
        throw "Trusted probe dependency is not a canonical regular file"
    }

    $signature = Get-AuthenticodeSignature -LiteralPath $expected -ErrorAction Stop
    if ($signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid) {
        throw "Trusted probe dependency signature is invalid"
    }
    $signerName = $signature.SignerCertificate.GetNameInfo(
        [System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName,
        $false
    )
    if ($signerName -cnotin @(
        "Microsoft Corporation",
        "Microsoft Windows",
        "Microsoft Windows Publisher"
    )) {
        throw "Trusted probe dependency signer is invalid"
    }
    return $expected
}

function Assert-AutomationAssemblyIdentity {
    param(
        [string]$Path
    )

    $assemblyName = [System.Reflection.AssemblyName]::GetAssemblyName($Path)
    $publicKeyToken = $assemblyName.GetPublicKeyToken()
    $publicKeyTokenText = if ($null -eq $publicKeyToken) {
        ""
    } else {
        [Convert]::ToHexString($publicKeyToken).ToLowerInvariant()
    }
    if (
        $assemblyName.Name -cne "System.Management.Automation" -or
        $assemblyName.Version.ToString() -cne "3.0.0.0" -or
        $publicKeyTokenText -cne "31bf3856ad364e35"
    ) {
        throw "Trusted automation assembly identity is invalid"
    }
}

function Protect-ProbeDirectory {
    param(
        [string]$Path
    )

    $currentSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
    if ($null -eq $currentSid) {
        throw "Current Windows identity is unavailable"
    }

    $security = [System.Security.AccessControl.DirectorySecurity]::new()
    $security.SetOwner($currentSid)
    $security.SetAccessRuleProtection($true, $false)
    $inheritance = (
        [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
        [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
    )
    $rule = [System.Security.AccessControl.FileSystemAccessRule]::new(
        $currentSid,
        [System.Security.AccessControl.FileSystemRights]::FullControl,
        $inheritance,
        [System.Security.AccessControl.PropagationFlags]::None,
        [System.Security.AccessControl.AccessControlType]::Allow
    )
    $security.SetAccessRule($rule)
    Set-Acl -LiteralPath $Path -AclObject $security -ErrorAction Stop
}

function Get-BoundedEnvironmentValue {
    param(
        [string]$Name
    )

    $value = [Environment]::GetEnvironmentVariable($Name, "Process")
    if ($null -eq $value) {
        return ""
    }
    if ($value.Length -gt 32767 -or $value.IndexOf([char]0) -ge 0 -or $value -match '[\r\n]') {
        throw "Probe environment value is invalid"
    }
    return [string]$value
}

function Get-BootstrapFailureToken {
    param(
        [string]$Phase
    )

    switch -CaseSensitive ($Phase) {
        "system-root" {
            return "fullclr-utils-probe-bootstrap-system-root-failed-shape"
        }
        "compiler-trust" {
            return "fullclr-utils-probe-bootstrap-compiler-trust-failed-shape"
        }
        "automation-trust" {
            return "fullclr-utils-probe-bootstrap-automation-trust-failed-shape"
        }
        "workspace" {
            return "fullclr-utils-probe-bootstrap-workspace-failed-shape"
        }
        "compile" {
            return "fullclr-utils-probe-bootstrap-compile-failed-shape"
        }
        "helper" {
            return "fullclr-utils-probe-bootstrap-helper-failed-shape"
        }
        default {
            return "fullclr-utils-probe-bootstrap-failed-shape"
        }
    }
}

function Invoke-CapturedProcess {
    param(
        [System.Diagnostics.ProcessStartInfo]$StartInfo,
        [int]$TimeoutMilliseconds,
        [int]$MaximumCapturedBytes,
        [System.Text.Encoding]$OutputEncoding
    )

    if ($TimeoutMilliseconds -lt 1 -or $MaximumCapturedBytes -lt 1 -or $null -eq $OutputEncoding) {
        throw "Probe process bounds are invalid"
    }
    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $StartInfo
    $stdout = $null
    $stderr = $null
    $stdoutBytes = [byte[]]::new($MaximumCapturedBytes + 1)
    $stderrBytes = [byte[]]::new($MaximumCapturedBytes + 1)
    $stdoutCount = 0
    $stderrCount = 0
    $stdoutDone = $false
    $stderrDone = $false
    $timedOut = $false
    $overflow = $false
    $readFailed = $false
    $terminationFailed = $false
    $clock = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        if (-not $process.Start()) {
            throw "Probe process did not start"
        }

        $stdoutStream = $process.StandardOutput.BaseStream
        $stderrStream = $process.StandardError.BaseStream
        $stdoutTask = $stdoutStream.ReadAsync($stdoutBytes, 0, $stdoutBytes.Length)
        $stderrTask = $stderrStream.ReadAsync($stderrBytes, 0, $stderrBytes.Length)
        while ($true) {
            if (-not $stdoutDone -and $stdoutTask.IsCompleted) {
                try {
                    $bytesRead = [int]$stdoutTask.GetAwaiter().GetResult()
                } catch {
                    $readFailed = $true
                    break
                }
                if ($bytesRead -eq 0) {
                    $stdoutDone = $true
                } else {
                    $stdoutCount += $bytesRead
                    if ($stdoutCount -gt $MaximumCapturedBytes) {
                        $overflow = $true
                        break
                    }
                    $stdoutTask = $stdoutStream.ReadAsync(
                        $stdoutBytes,
                        $stdoutCount,
                        $stdoutBytes.Length - $stdoutCount
                    )
                }
            }
            if (-not $stderrDone -and $stderrTask.IsCompleted) {
                try {
                    $bytesRead = [int]$stderrTask.GetAwaiter().GetResult()
                } catch {
                    $readFailed = $true
                    break
                }
                if ($bytesRead -eq 0) {
                    $stderrDone = $true
                } else {
                    $stderrCount += $bytesRead
                    if ($stderrCount -gt $MaximumCapturedBytes) {
                        $overflow = $true
                        break
                    }
                    $stderrTask = $stderrStream.ReadAsync(
                        $stderrBytes,
                        $stderrCount,
                        $stderrBytes.Length - $stderrCount
                    )
                }
            }
            if ($process.HasExited -and $stdoutDone -and $stderrDone) {
                break
            }
            if ($clock.ElapsedMilliseconds -ge $TimeoutMilliseconds) {
                $timedOut = $true
                break
            }
            $null = $process.WaitForExit(20)
        }

        if ($timedOut -or $overflow -or $readFailed) {
            try {
                if (-not $process.HasExited) {
                    $process.Kill($true)
                    if (-not $process.WaitForExit(5000)) {
                        $terminationFailed = $true
                    }
                }
            } catch {
                try {
                    $terminationFailed = -not $process.HasExited
                } catch {
                    $terminationFailed = $true
                }
                $Error.Clear()
            }
            return [pscustomobject]@{
                ExitCode = if ($timedOut) { 124 } else { -1 }
                Stdout = ""
                Stderr = ""
                TimedOut = $timedOut
                Overflow = $overflow
                ReadFailed = $readFailed
                TerminationFailed = $terminationFailed
            }
        }
        $stdout = $OutputEncoding.GetString($stdoutBytes, 0, $stdoutCount)
        $stderr = $OutputEncoding.GetString($stderrBytes, 0, $stderrCount)
        return [pscustomobject]@{
            ExitCode = [int]$process.ExitCode
            Stdout = $stdout
            Stderr = $stderr
            TimedOut = $false
            Overflow = $false
            ReadFailed = $false
            TerminationFailed = $false
        }
    } finally {
        $clock.Stop()
        $stdout = $null
        $stderr = $null
        $stdoutBytes = $null
        $stderrBytes = $null
        $process.Dispose()
    }
}

function Test-CanonicalProbeRoot {
    param(
        [string]$Path
    )

    $trimCharacters = [char[]]@(
        [System.IO.Path]::DirectorySeparatorChar,
        [System.IO.Path]::AltDirectorySeparatorChar
    )
    $temporaryRoot = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath()).TrimEnd(
        $trimCharacters
    )
    $candidate = [System.IO.Path]::GetFullPath($Path)
    $expectedPrefix = $temporaryRoot + [System.IO.Path]::DirectorySeparatorChar
    $leaf = [System.IO.Path]::GetFileName($candidate)
    return (
        $candidate.StartsWith($expectedPrefix, [StringComparison]::OrdinalIgnoreCase) -and
        $leaf -match '^rikune-fullclr-utils-probe-[a-f0-9]{32}$'
    )
}

if (-not $IsWindows) {
    Write-Output ($resultPrefix + "skipped-non-windows-shape")
    exit 0
}

try {
    $bootstrapPhase = "system-root"
    $systemRoot = Get-CanonicalWindowsSystemRoot
    $system32 = Join-Path $systemRoot "System32"
    $systemDrive = $systemRoot.Substring(0, 2)
    $bootstrapPhase = "compiler-trust"
    $cscPath = Get-TrustedSignedFile -ExpectedPath (
        Join-Path $systemRoot "Microsoft.NET\Framework64\v4.0.30319\csc.exe"
    )
    $bootstrapPhase = "automation-trust"
    $automationAssemblyPath = Get-TrustedSignedFile -ExpectedPath (
        Join-Path $system32 "WindowsPowerShell\v1.0\System.Management.Automation.dll"
    )
    Assert-AutomationAssemblyIdentity -Path $automationAssemblyPath

    $bootstrapPhase = "workspace"
    $probeRoot = Join-Path (
        [System.IO.Path]::GetTempPath()
    ) "rikune-fullclr-utils-probe-$([Guid]::NewGuid().ToString('N'))"
    if (-not (Test-CanonicalProbeRoot -Path $probeRoot)) {
        throw "Probe root is outside the exclusive temporary boundary"
    }
    $null = New-Item -ItemType Directory -Path $probeRoot -ErrorAction Stop
    Protect-ProbeDirectory -Path $probeRoot

    $sourcePath = Join-Path $probeRoot "Probe.cs"
    $helperPath = Join-Path $probeRoot "Probe.exe"
    @'
using System;
using System.IO;
using System.Reflection;
using System.Runtime.CompilerServices;

internal static class Program
{
    private const string UtilsTypeName = "System.Management.Automation.Utils";
    private const string RegistryTypeName = "Microsoft.Win32.Registry";
    private const string StringComparerTypeName = "System.StringComparer";
    private const string PlatformTypeName = "System.Management.Automation.Platform";
    private const string RegistryToken = "fullclr-utils-inner-registry-type-init-shape";
    private const string StringComparerToken = "fullclr-utils-inner-string-comparer-type-init-shape";
    private const string PlatformToken = "fullclr-utils-inner-platform-type-init-shape";
    private const string GenericToken = "fullclr-utils-inner-other-shape";
    private const string PassedToken = "fullclr-utils-probe-passed-shape";
    private const string InternalFailureToken = "fullclr-utils-probe-internal-failed-shape";
    private static readonly TextWriter OriginalOut = Console.Out;

    private static int Emit(int exitCode, string token)
    {
        Console.SetOut(OriginalOut);
        OriginalOut.Write(token);
        OriginalOut.Write("\r\n");
        OriginalOut.Flush();
        return exitCode;
    }

    private static bool HasExpectedIdentity(Assembly assembly)
    {
        AssemblyName name = assembly.GetName();
        byte[] publicKeyToken = name.GetPublicKeyToken();
        string token = publicKeyToken == null
            ? string.Empty
            : BitConverter.ToString(publicKeyToken).Replace("-", string.Empty).ToLowerInvariant();
        return string.Equals(name.Name, "System.Management.Automation", StringComparison.Ordinal)
            && name.Version != null
            && string.Equals(name.Version.ToString(), "3.0.0.0", StringComparison.Ordinal)
            && string.Equals(token, "31bf3856ad364e35", StringComparison.Ordinal);
    }

    private static Exception UnwrapTargetInvocation(Exception exception)
    {
        TargetInvocationException invocation = exception as TargetInvocationException;
        while (invocation != null && invocation.InnerException != null)
        {
            exception = invocation.InnerException;
            invocation = exception as TargetInvocationException;
        }
        return exception;
    }

    private static int Classify(Exception exception)
    {
        TypeInitializationException outer = UnwrapTargetInvocation(exception) as TypeInitializationException;
        if (outer == null || !string.Equals(outer.TypeName, UtilsTypeName, StringComparison.Ordinal))
        {
            return Emit(25, InternalFailureToken);
        }

        TypeInitializationException nested = outer.InnerException as TypeInitializationException;
        if (nested == null)
        {
            return Emit(23, GenericToken);
        }
        if (string.Equals(nested.TypeName, RegistryTypeName, StringComparison.Ordinal))
        {
            return Emit(20, RegistryToken);
        }
        if (string.Equals(nested.TypeName, StringComparerTypeName, StringComparison.Ordinal))
        {
            return Emit(21, StringComparerToken);
        }
        if (string.Equals(nested.TypeName, PlatformTypeName, StringComparison.Ordinal))
        {
            return Emit(22, PlatformToken);
        }
        return Emit(23, GenericToken);
    }

    private static int Main(string[] args)
    {
        Console.SetOut(TextWriter.Null);
        Console.SetError(TextWriter.Null);
        if (args == null || args.Length != 1)
        {
            return Emit(25, InternalFailureToken);
        }

        Assembly assembly;
        Type utils;
        try
        {
            assembly = Assembly.LoadFrom(args[0]);
            if (!HasExpectedIdentity(assembly))
            {
                return Emit(25, InternalFailureToken);
            }
            utils = assembly.GetType(UtilsTypeName, true, false);
        }
        catch
        {
            return Emit(25, InternalFailureToken);
        }

        try
        {
            RuntimeHelpers.RunClassConstructor(utils.TypeHandle);
            return Emit(24, PassedToken);
        }
        catch (Exception exception)
        {
            return Classify(exception);
        }
    }
}
'@ | Set-Content -LiteralPath $sourcePath -Encoding utf8NoBOM

    $bootstrapPhase = "compile"
    $compileInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $compileInfo.FileName = $cscPath
    $compileInfo.UseShellExecute = $false
    $compileInfo.CreateNoWindow = $true
    $compileInfo.RedirectStandardOutput = $true
    $compileInfo.RedirectStandardError = $true
    $compileInfo.StandardOutputEncoding = [System.Text.Encoding]::UTF8
    $compileInfo.StandardErrorEncoding = [System.Text.Encoding]::UTF8
    foreach ($argument in @(
        "/nologo",
        "/target:exe",
        "/platform:x64",
        "/optimize+",
        "/debug-",
        "/out:$helperPath",
        $sourcePath
    )) {
        $compileInfo.ArgumentList.Add($argument)
    }
    $compilerResult = Invoke-CapturedProcess `
        -StartInfo $compileInfo `
        -TimeoutMilliseconds 30000 `
        -MaximumCapturedBytes 4096 `
        -OutputEncoding ([System.Text.Encoding]::UTF8)
    if (
        $compilerResult.TimedOut -or
        $compilerResult.Overflow -or
        $compilerResult.ReadFailed -or
        $compilerResult.TerminationFailed -or
        $compilerResult.ExitCode -ne 0 -or
        -not (Test-Path -LiteralPath $helperPath -PathType Leaf)
    ) {
        throw "FullCLR probe compilation failed"
    }
    $compilerResult = $null

    $bootstrapPhase = "helper"
    $helperInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $helperInfo.FileName = $helperPath
    $helperInfo.WorkingDirectory = Split-Path -Parent $PSScriptRoot
    $helperInfo.UseShellExecute = $false
    $helperInfo.CreateNoWindow = $true
    $helperInfo.RedirectStandardOutput = $true
    $helperInfo.RedirectStandardError = $true
    $helperInfo.StandardOutputEncoding = [System.Text.Encoding]::ASCII
    $helperInfo.StandardErrorEncoding = [System.Text.Encoding]::ASCII
    $helperInfo.ArgumentList.Add($automationAssemblyPath)
    $helperInfo.Environment.Clear()
    $temporaryPath = Get-BoundedEnvironmentValue -Name "TEMP"
    if ([string]::IsNullOrEmpty($temporaryPath)) {
        $temporaryPath = Get-BoundedEnvironmentValue -Name "TMP"
    }
    $tmpPath = Get-BoundedEnvironmentValue -Name "TMP"
    if ([string]::IsNullOrEmpty($tmpPath)) {
        $tmpPath = $temporaryPath
    }
    $probeEnvironment = [ordered]@{
        HOMEDRIVE = $systemDrive
        HOMEPATH = '\'
        LOGONSERVER = ''
        PATH = $system32
        SYSTEMDRIVE = $systemDrive
        SYSTEMROOT = $systemRoot
        TEMP = $temporaryPath
        TMP = $tmpPath
        USERDOMAIN = ''
        USERNAME = ''
        USERPROFILE = ''
        WINDIR = $systemRoot
        PSModuleAnalysisCachePath = 'NUL'
        PSModulePath = (Join-Path $system32 "WindowsPowerShell\v1.0\Modules")
        RIKUNE_PRIVATE_ENV_PATH = $helperPath
        RIKUNE_PRIVATE_ENV_ACL_MODE = 'verify'
    }
    foreach ($entry in $probeEnvironment.GetEnumerator()) {
        $helperInfo.Environment[[string]$entry.Key] = [string]$entry.Value
    }

    $helperResult = Invoke-CapturedProcess `
        -StartInfo $helperInfo `
        -TimeoutMilliseconds 10000 `
        -MaximumCapturedBytes 256 `
        -OutputEncoding ([System.Text.Encoding]::ASCII)
    $expectedResults = @{
        20 = "fullclr-utils-inner-registry-type-init-shape"
        21 = "fullclr-utils-inner-string-comparer-type-init-shape"
        22 = "fullclr-utils-inner-platform-type-init-shape"
        23 = "fullclr-utils-inner-other-shape"
        24 = "fullclr-utils-probe-passed-shape"
        25 = "fullclr-utils-probe-internal-failed-shape"
    }
    $expectedToken = [string]$expectedResults[$helperResult.ExitCode]
    if ($helperResult.TerminationFailed) {
        $resultToken = "fullclr-utils-probe-protocol-invalid-shape"
    } elseif ($helperResult.TimedOut) {
        $resultToken = "fullclr-utils-probe-timeout-shape"
    } elseif (
        $helperResult.Overflow -or
        $helperResult.ReadFailed -or
        [string]::IsNullOrEmpty($expectedToken) -or
        $helperResult.Stderr -cne "" -or
        $helperResult.Stdout -cne ($expectedToken + "`r`n")
    ) {
        $resultToken = "fullclr-utils-probe-protocol-invalid-shape"
    } else {
        $resultToken = $expectedToken
    }
} catch {
    $resultToken = Get-BootstrapFailureToken -Phase $bootstrapPhase
} finally {
    $compilerResult = $null
    $helperResult = $null
    try {
        if ($null -ne $probeRoot) {
            if (-not (Test-CanonicalProbeRoot -Path $probeRoot)) {
                throw "Probe cleanup boundary is invalid"
            }
            $probeItem = Get-Item -LiteralPath $probeRoot -Force -ErrorAction SilentlyContinue
            if ($null -ne $probeItem) {
                if (
                    -not $probeItem.PSIsContainer -or
                    (($probeItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0)
                ) {
                    throw "Probe cleanup target is invalid"
                }
                Remove-Item -LiteralPath $probeRoot -Recurse -Force -ErrorAction Stop
                if (Test-Path -LiteralPath $probeRoot) {
                    throw "Probe cleanup did not remove the exclusive root"
                }
            }
        }
    } catch {
        $resultToken = "fullclr-utils-probe-cleanup-failed-shape"
    } finally {
        $Error.Clear()
    }
}

Write-Output ($resultPrefix + $resultToken)
