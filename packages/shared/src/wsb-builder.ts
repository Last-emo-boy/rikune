export interface WsbConfig {
  runtimeDirHost: string
  runtimeFileName: string
  workersDirHost: string
  inboxDir: string
  outboxDir: string
  readyFileSandbox: string
  runtimeApiKey?: string
  setupDirHost?: string
  nodeDirHost?: string
  nodeFileName?: string
  nodeModulesDirHost?: string
  pythonDirHost?: string
  pythonFileName?: string
}

export function escapeXml(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;')
}

function quotePowerShellString(str: string): string {
  return `'${str.replace(/'/g, "''")}'`
}

function buildPowerShellArray(values: string[]): string {
  return `@(${values.map(quotePowerShellString).join(', ')})`
}

function buildEncodedPowerShellCommand(script: string): string {
  return Buffer.from(script, 'utf16le').toString('base64')
}

export function buildWsbXml(cfg: WsbConfig): string {
  const setupFolder = cfg.setupDirHost
    ? `    <MappedFolder>\n      <HostFolder>${escapeXml(cfg.setupDirHost)}</HostFolder>\n      <SandboxFolder>C:\\rikune-setup</SandboxFolder>\n      <ReadOnly>true</ReadOnly>\n    </MappedFolder>`
    : ''

  const nodePathSandbox = cfg.nodeDirHost
    ? `C:\\rikune-node\\${cfg.nodeFileName || 'node.exe'}`
    : 'node'
  const pythonPathSandbox = cfg.pythonDirHost
    ? `C:\\rikune-python\\${cfg.pythonFileName || 'python.exe'}`
    : undefined

  const runtimeEnvCommands = [
    cfg.runtimeApiKey ? `$env:RUNTIME_API_KEY = ${quotePowerShellString(cfg.runtimeApiKey)}` : undefined,
    pythonPathSandbox ? `$env:RUNTIME_PYTHON_PATH = ${quotePowerShellString(pythonPathSandbox)}` : undefined,
  ].filter(Boolean)

  const runtimeArgs = [
    cfg.runtimeFileName,
    '--host',
    '0.0.0.0',
    '--port',
    '18081',
    '--inbox',
    'C:\\rikune-inbox',
    '--outbox',
    'C:\\rikune-outbox',
    '--ready-file',
    cfg.readyFileSandbox,
  ]
  if (pythonPathSandbox) {
    runtimeArgs.push('--python-path', pythonPathSandbox)
  }

  const setupCommand = cfg.setupDirHost
    ? [
        `if (Test-Path -LiteralPath 'C:\\rikune-setup\\setup-sandbox-env.ps1') {`,
        `  & 'C:\\rikune-setup\\setup-sandbox-env.ps1'`,
        `}`,
      ]
    : []
  const defenderExclusionCommand = [
    `$defenderService = Get-Service -Name WinDefend -ErrorAction SilentlyContinue`,
    `if (-not $defenderService -or $defenderService.Status -ne 'Running') {`,
    `  "Defender service is not running; exclusion setup skipped" | Add-Content -Path $startupLog`,
    `} else {`,
    `  $defenderExclusionPaths = @('C:\\rikune-runtime', 'C:\\rikune-workers', 'C:\\rikune-inbox', 'C:\\rikune-outbox')`,
    `  foreach ($defenderPath in $defenderExclusionPaths) {`,
    `    if (Test-Path -LiteralPath $defenderPath) {`,
    `      try {`,
    `        Add-MpPreference -ExclusionPath $defenderPath -ErrorAction Stop`,
    `        "Defender exclusion added: $defenderPath" | Add-Content -Path $startupLog`,
    `      } catch {`,
    `        "Defender exclusion failed: $defenderPath :: $($_.Exception.Message)" | Add-Content -Path $startupLog`,
    `      }`,
    `    }`,
    `  }`,
    `}`,
  ]
  const runtimeScript = [
    `$ErrorActionPreference = 'Continue'`,
    `$startupLog = 'C:\\rikune-outbox\\runtime-startup.log'`,
    `"Rikune runtime startup: $(Get-Date -Format o)" | Out-File -FilePath $startupLog -Encoding utf8`,
    ...defenderExclusionCommand,
    ...setupCommand,
    `Set-Location -LiteralPath 'C:\\rikune-runtime'`,
    ...runtimeEnvCommands,
    `$runtimeArgs = ${buildPowerShellArray(runtimeArgs)}`,
    `try {`,
    `  $runtimeProcess = Start-Process -FilePath ${quotePowerShellString(nodePathSandbox)} -ArgumentList $runtimeArgs -WorkingDirectory 'C:\\rikune-runtime' -WindowStyle Hidden -RedirectStandardOutput 'C:\\rikune-outbox\\runtime.stdout.log' -RedirectStandardError 'C:\\rikune-outbox\\runtime.stderr.log' -PassThru`,
    `  "Runtime process started: pid=$($runtimeProcess.Id)" | Add-Content -Path $startupLog`,
    `} catch {`,
    `  "Runtime process failed: $($_.Exception.Message)" | Add-Content -Path $startupLog`,
    `  $_ | Out-String | Add-Content -Path 'C:\\rikune-outbox\\runtime.stderr.log'`,
    `}`,
  ].join('\r\n')
  const logonCommand = `powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand ${buildEncodedPowerShellCommand(runtimeScript)}`

  const mappedFolders = [
    `    <MappedFolder>\n      <HostFolder>${escapeXml(cfg.runtimeDirHost)}</HostFolder>\n      <SandboxFolder>C:\\rikune-runtime</SandboxFolder>\n      <ReadOnly>true</ReadOnly>\n    </MappedFolder>`,
    `    <MappedFolder>\n      <HostFolder>${escapeXml(cfg.workersDirHost)}</HostFolder>\n      <SandboxFolder>C:\\rikune-workers</SandboxFolder>\n      <ReadOnly>true</ReadOnly>\n    </MappedFolder>`,
    `    <MappedFolder>\n      <HostFolder>${escapeXml(cfg.inboxDir)}</HostFolder>\n      <SandboxFolder>C:\\rikune-inbox</SandboxFolder>\n      <ReadOnly>false</ReadOnly>\n    </MappedFolder>`,
    `    <MappedFolder>\n      <HostFolder>${escapeXml(cfg.outboxDir)}</HostFolder>\n      <SandboxFolder>C:\\rikune-outbox</SandboxFolder>\n      <ReadOnly>false</ReadOnly>\n    </MappedFolder>`,
  ]

  if (cfg.nodeDirHost) {
    mappedFolders.push(
      `    <MappedFolder>\n      <HostFolder>${escapeXml(cfg.nodeDirHost)}</HostFolder>\n      <SandboxFolder>C:\\rikune-node</SandboxFolder>\n      <ReadOnly>true</ReadOnly>\n    </MappedFolder>`
    )
  }

  if (cfg.nodeModulesDirHost) {
    mappedFolders.push(
      `    <MappedFolder>\n      <HostFolder>${escapeXml(cfg.nodeModulesDirHost)}</HostFolder>\n      <SandboxFolder>C:\\node_modules</SandboxFolder>\n      <ReadOnly>true</ReadOnly>\n    </MappedFolder>`
    )
  }

  if (cfg.pythonDirHost) {
    mappedFolders.push(
      `    <MappedFolder>\n      <HostFolder>${escapeXml(cfg.pythonDirHost)}</HostFolder>\n      <SandboxFolder>C:\\rikune-python</SandboxFolder>\n      <ReadOnly>true</ReadOnly>\n    </MappedFolder>`
    )
  }

  if (setupFolder) {
    mappedFolders.push(setupFolder)
  }

  return `<Configuration>\n  <Networking>Enable</Networking>\n  <MappedFolders>\n${mappedFolders.join('\n')}\n  </MappedFolders>\n  <LogonCommand>\n    <Command>${escapeXml(logonCommand)}</Command>\n  </LogonCommand>\n</Configuration>\n`
}
