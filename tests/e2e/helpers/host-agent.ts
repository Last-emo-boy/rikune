import { requestJson } from './http-client.js'

export class HostAgentClient {
  constructor(
    private endpoint: string,
    private apiKey?: string,
  ) {}

  private headers(): Record<string, string> {
    return this.apiKey ? { Authorization: `Bearer ${this.apiKey}` } : {}
  }

  async health(): Promise<{ ok: boolean; sandboxes?: any[] }> {
    return requestJson(`${this.endpoint}/sandbox/health`, { headers: this.headers() })
  }

  async startSandbox(timeoutMs = 60_000): Promise<{ ok: boolean; endpoint?: string; sandboxId?: string; error?: string }> {
    return requestJson(`${this.endpoint}/sandbox/start`, {
      method: 'POST',
      headers: this.headers(),
      body: { timeoutMs },
      timeout: timeoutMs + 10_000,
    })
  }

  async stopSandbox(sandboxId: string): Promise<{ ok: boolean; error?: string }> {
    return requestJson(`${this.endpoint}/sandbox/stop`, {
      method: 'POST',
      headers: this.headers(),
      body: { sandboxId },
    })
  }
}
