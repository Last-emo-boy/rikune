import http from 'http'

export interface RequestOptions {
  method?: string
  headers?: Record<string, string>
  body?: unknown
  timeout?: number
}

export function requestJson<T = unknown>(urlStr: string, opts: RequestOptions = {}): Promise<T> {
  return new Promise((resolve, reject) => {
    const url = new URL(urlStr)
    const payload = opts.body !== undefined ? JSON.stringify(opts.body) : undefined
    const headers: Record<string, string> = {
      'Accept': 'application/json',
      ...opts.headers,
    }
    if (payload) {
      headers['Content-Type'] = 'application/json'
      headers['Content-Length'] = Buffer.byteLength(payload).toString()
    }

    const req = http.request(
      {
        hostname: url.hostname,
        port: url.port || (url.protocol === 'https:' ? 443 : 80),
        path: url.pathname + url.search,
        method: opts.method || 'GET',
        headers,
        timeout: opts.timeout || 30_000,
      },
      (res) => {
        const chunks: Buffer[] = []
        res.on('data', (c) => chunks.push(c))
        res.on('end', () => {
          const raw = Buffer.concat(chunks).toString('utf-8')
          try {
            resolve(JSON.parse(raw) as T)
          } catch {
            resolve(raw as T)
          }
        })
      },
    )
    req.on('error', reject)
    req.on('timeout', () => {
      req.destroy()
      reject(new Error('Request timeout'))
    })
    if (payload) req.write(payload)
    req.end()
  })
}
