export interface WsbConfig {
  runtimeDirHost: string
  runtimeFileName: string
  workersDirHost: string
  inboxDir: string
  outboxDir: string
  readyFileSandbox: string
  runtimeApiKey?: string
  setupDirHost?: string
}

export function escapeXml(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;')
}

export function buildWsbXml(cfg: WsbConfig): string {
  const setupFolder = cfg.setupDirHost
    ? `    <MappedFolder>\n      <HostFolder>${escapeXml(cfg.setupDirHost)}</HostFolder>\n      <SandboxFolder>C:\\rikune-setup</SandboxFolder>\n      <ReadOnly>true</ReadOnly>\n    </MappedFolder>`
    : ''

  const runtimeEnvPrefix = cfg.runtimeApiKey
    ? `set \"RUNTIME_API_KEY=${escapeXml(cfg.runtimeApiKey)}\" && `
    : ''
  const runtimeCommand = `${runtimeEnvPrefix}start /b node ${cfg.runtimeFileName} --host 0.0.0.0 --port 18081 --inbox C:\\rikune-inbox --outbox C:\\rikune-outbox --ready-file ${cfg.readyFileSandbox}`
  const logonCommand = cfg.setupDirHost
    ? `powershell -ExecutionPolicy Bypass -File C:\\rikune-setup\\setup-sandbox-env.ps1 &amp;&amp; cmd /c "cd /d C:\\rikune-runtime &amp;&amp; ${runtimeCommand}"`
    : `cmd /c "cd /d C:\\rikune-runtime &amp;&amp; ${runtimeCommand}"`

  const mappedFolders = [
    `    <MappedFolder>\n      <HostFolder>${escapeXml(cfg.runtimeDirHost)}</HostFolder>\n      <SandboxFolder>C:\\rikune-runtime</SandboxFolder>\n      <ReadOnly>true</ReadOnly>\n    </MappedFolder>`,
    `    <MappedFolder>\n      <HostFolder>${escapeXml(cfg.workersDirHost)}</HostFolder>\n      <SandboxFolder>C:\\rikune-workers</SandboxFolder>\n      <ReadOnly>true</ReadOnly>\n    </MappedFolder>`,
    `    <MappedFolder>\n      <HostFolder>${escapeXml(cfg.inboxDir)}</HostFolder>\n      <SandboxFolder>C:\\rikune-inbox</SandboxFolder>\n      <ReadOnly>false</ReadOnly>\n    </MappedFolder>`,
    `    <MappedFolder>\n      <HostFolder>${escapeXml(cfg.outboxDir)}</HostFolder>\n      <SandboxFolder>C:\\rikune-outbox</SandboxFolder>\n      <ReadOnly>false</ReadOnly>\n    </MappedFolder>`,
  ]

  if (setupFolder) {
    mappedFolders.push(setupFolder)
  }

  return `<Configuration>\n  <Networking>Enable</Networking>\n  <MappedFolders>\n${mappedFolders.join('\n')}\n  </MappedFolders>\n  <LogonCommand>\n    <Command>${logonCommand}</Command>\n  </LogonCommand>\n</Configuration>\n`
}
