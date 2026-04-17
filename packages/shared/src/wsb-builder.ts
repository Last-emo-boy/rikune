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

function quoteCmdArg(str: string): string {
  return `"${str.replace(/"/g, '')}"`
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
    cfg.runtimeApiKey ? `set "RUNTIME_API_KEY=${cfg.runtimeApiKey}"` : undefined,
    pythonPathSandbox ? `set "RUNTIME_PYTHON_PATH=${pythonPathSandbox}"` : undefined,
  ].filter(Boolean)

  const runtimeArgs = [
    quoteCmdArg(cfg.runtimeFileName),
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
    runtimeArgs.push('--python-path', quoteCmdArg(pythonPathSandbox))
  }

  const runtimeCommand = [
    ...runtimeEnvCommands,
    `start "" /b ${quoteCmdArg(nodePathSandbox)} ${runtimeArgs.join(' ')}`,
  ].join(' && ')
  const logonCommand = cfg.setupDirHost
    ? `powershell -ExecutionPolicy Bypass -File C:\\rikune-setup\\setup-sandbox-env.ps1 && cmd /c "cd /d C:\\rikune-runtime && ${runtimeCommand}"`
    : `cmd /c "cd /d C:\\rikune-runtime && ${runtimeCommand}"`

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
