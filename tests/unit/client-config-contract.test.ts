import fs from 'node:fs'
import path from 'node:path'
import { describe, expect, test } from '@jest/globals'

const read = (relativePath: string): string =>
  fs.readFileSync(path.join(process.cwd(), relativePath), 'utf8')

const readPowerShellParameters = (relativePath: string): string => {
  const source = read(relativePath)
  const parameterBlock = source.match(/^param\(([\s\S]*?)^\)/mu)?.[1]
  if (parameterBlock === undefined) throw new Error(`Missing PowerShell param block: ${relativePath}`)
  return parameterBlock
}

describe('MCP client configuration contract', () => {
  test('keeps client-owned configuration out of the Docker installer', () => {
    const installer = read('install-docker.ps1')
    const wrapper = read('rikune.ps1')

    expect(installer).not.toContain('ConfigureClient')
    expect(installer).not.toContain('Configure-McpClient')
    expect(installer).not.toContain('Set-CodexMcpConfig')
    expect(installer).not.toContain('command = "rikune-agent"')
    expect(wrapper).not.toContain('ConfigureClient')
    expect(read('INSTALL.md')).not.toContain('-ConfigureClient')
  })

  test('documents a schema-correct credential-free VS Code Docker stdio server', () => {
    const guide = read('COPILOT_INSTALLATION.md')

    expect(guide).toContain('`.vscode/mcp.json`')
    expect(guide).toContain('"servers"')
    expect(guide).not.toContain('"mcpServers"')
    expect(guide).toContain('"type": "stdio"')
    expect(guide).toContain('"API_ENABLED=false"')
    expect(guide).toContain('"rikune-analyzer"')
    expect(guide).not.toMatch(/RIKUNE_(?:ANALYZER_)?API_KEY/u)
    expect(guide).not.toContain('RUNTIME_HOST_AGENT_API_KEY')
    expect(guide).not.toContain('RUNTIME_API_KEY')

    for (const relativePath of ['README.md', 'README_zh.md', 'DEPLOYMENT.md']) {
      const documentedConfig = read(relativePath)
      expect(documentedConfig).toContain('"API_ENABLED=false"')
    }
  })

  test('never exposes runtime credentials as public PowerShell argv parameters', () => {
    const dockerParameters = readPowerShellParameters('install-docker.ps1')
    const wrapperParameters = readPowerShellParameters('rikune.ps1')
    const runtimeParameters = readPowerShellParameters('install-runtime-windows.ps1')

    for (const parameters of [dockerParameters, wrapperParameters]) {
      expect(parameters).not.toMatch(/\$(?:HostAgentApiKey|RuntimeApiKey)\b/u)
    }
    expect(runtimeParameters).not.toMatch(/\$ApiKey\b/u)
    expect(runtimeParameters).toContain('$ReadApiKeyFromStdin')

    const wrapper = read('rikune.ps1')
    expect(wrapper).toContain(
      '$childEnvironment.RIKUNE_HOST_AGENT_API_KEY = $env:RUNTIME_HOST_AGENT_API_KEY'
    )
    expect(wrapper).toContain(
      '$childEnvironment.RIKUNE_RUNTIME_NODE_API_KEY = $env:RUNTIME_API_KEY'
    )
  })
})
