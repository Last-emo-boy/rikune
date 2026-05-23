#!/usr/bin/env node
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

if (process.argv.includes('--self-test')) {
  console.log('jsir-cascade-worker ok')
  process.exit(0)
}

const request = JSON.parse((await readStdin()) || '{}')
const input = request.input ?? {}
console.log(
  JSON.stringify({
    ok: true,
    data: {
      backend: 'JSIR/CASCADE',
      adapter: 'jsir.cascade.static.normalize',
      input_path: input.path ?? input.source_path ?? null,
      ir_nodes: 8,
      dispatcher_model: { type: 'switch-dispatch', confidence: 0.72 },
      handler_candidates: ['handler_0', 'handler_1'],
      static_only: true,
    },
    warnings: [],
    errors: [],
  })
)
