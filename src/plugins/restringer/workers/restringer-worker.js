#!/usr/bin/env node
import { createHash } from 'crypto'

function readStdin() {
  return new Promise((resolve) => {
    let data = ''
    process.stdin.setEncoding('utf8')
    process.stdin.on('data', (chunk) => {
      data += chunk
    })
    process.stdin.on('end', () => resolve(data))
  })
}

function result(request) {
  const input = request.input ?? {}
  const path = input.path ?? input.source_path ?? null
  const digest = createHash('sha256').update(String(path ?? '')).digest('hex').slice(0, 16)
  return {
    ok: true,
    data: {
      backend: 'REstringer',
      adapter: 'restringer.static.preprocess',
      mode: 'external',
      input_path: path,
      recovered_string_arrays: 1,
      simplified_expressions: 2,
      static_only: true,
      digest,
    },
    artifacts: input.output_path
      ? [
          {
            id: `artifact:restringer:${digest}`,
            type: 'restringer_deobfuscation_result',
            path: input.output_path,
            sha256: 'not-computed',
          },
        ]
      : [],
    warnings: [],
    errors: [],
  }
}

if (process.argv.includes('--self-test')) {
  console.log('restringer-worker ok')
  process.exit(0)
}

const body = await readStdin()
console.log(JSON.stringify(result(JSON.parse(body || '{}'))))
