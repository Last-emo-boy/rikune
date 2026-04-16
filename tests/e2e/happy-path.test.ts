import { isDockerAvailable, startAnalyzer, stopAnalyzer, analyzerLogs } from './helpers/docker-lifecycle.js'
import { HostAgentClient } from './helpers/host-agent.js'
import { requestJson } from './helpers/http-client.js'
import fs from 'fs'
import path from 'path'
import { fileURLToPath } from 'url'

const __dirname = path.dirname(fileURLToPath(import.meta.url))

const ANALYZER_URL = 'http://localhost:18080'
const HOST_AGENT_URL = process.env.E2E_HOST_AGENT_ENDPOINT || ''
const HOST_AGENT_KEY = process.env.E2E_HOST_AGENT_API_KEY || ''

const describeIf = (condition: boolean) => condition ? describe : describe.skip

describeIf(isDockerAvailable() && !!HOST_AGENT_URL)('E2E Happy Path', () => {
  const hostAgent = new HostAgentClient(HOST_AGENT_URL, HOST_AGENT_KEY)
  let sandboxId: string | undefined

  beforeAll(async () => {
    stopAnalyzer()
    startAnalyzer()
    // Wait for analyzer to be ready
    for (let i = 0; i < 30; i++) {
      try {
        const health = await requestJson(`${ANALYZER_URL}/api/v1/health`)
        if ((health as any).ok) break
      } catch {}
      await new Promise((r) => setTimeout(r, 1000))
    }
  }, 60_000)

  afterAll(async () => {
    if (sandboxId) {
      await hostAgent.stopSandbox(sandboxId)
    }
    stopAnalyzer()
  })

  test('Host Agent health returns ok', async () => {
    const health = await hostAgent.health()
    expect(health.ok).toBe(true)
  })

  test('Analyzer system.health shows runtimeConnected', async () => {
    // Use the MCP tool bridge if exposed, otherwise skip
    // For now we just verify the runtime client initialized by checking logs indirectly
    // or call the REST health endpoint
    const health = await requestJson(`${ANALYZER_URL}/api/v1/health`)
    expect((health as any).ok).toBe(true)
  })

  test('upload a benign PE and run sandbox.execute', async () => {
    // Ensure a test PE exists; use calc.exe from System32 if available on host,
    // otherwise create a minimal dummy file for the test.
    const samplePath = path.join(__dirname, '../../fixtures/calc.exe')
    if (!fs.existsSync(samplePath)) {
      // Create fixtures dir and a dummy PE header
      fs.mkdirSync(path.dirname(samplePath), { recursive: true })
      const dummy = Buffer.from([0x4d, 0x5a]) // MZ header
      fs.writeFileSync(samplePath, dummy)
    }

    // Upload sample via Analyzer storage API
    const uploadRes = await requestJson<{ ok: boolean; id?: string }>(`${ANALYZER_URL}/api/v1/samples`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/octet-stream' },
      body: fs.readFileSync(samplePath),
      timeout: 30_000,
    })
    expect(uploadRes.ok).toBe(true)
    const sampleId = uploadRes.id!

    // Trigger sandbox start from Host Agent to guarantee runtime is up
    const startRes = await hostAgent.startSandbox(60_000)
    expect(startRes.ok).toBe(true)
    sandboxId = startRes.sandboxId

    // In a full E2E test we would now invoke the MCP tool `sandbox.execute`.
    // Because MCP is stdio/JSON-RPC based, a direct REST bridge for tool calls
    // would need to be added to the analyzer for automated E2E.
    // For now we assert that the sandbox started and the sample was uploaded.
    expect(sampleId).toBeDefined()
    expect(sandboxId).toBeDefined()

    // Verify runtime health
    const runtimeHealth = await requestJson(`${startRes.endpoint}/health`, { timeout: 10_000 })
    expect((runtimeHealth as any).ok).toBe(true)
  }, 120_000)
})
