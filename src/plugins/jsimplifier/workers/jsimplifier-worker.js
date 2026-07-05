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
  console.log('jsimplifier-worker ok')
  process.exit(0)
}

const request = JSON.parse((await readStdin()) || '{}')
const input = request.input ?? {}
console.log(
  JSON.stringify({
    ok: true,
    data: {
      backend: 'JSIMPLIFIER',
      adapter: 'jsimplifier.static.pipeline',
      input_path: input.path ?? input.source_path ?? null,
      pass_timeline: ['parse', 'constant-fold', 'dead-branch-prune', 'identifier-score'],
      confidence_breakdown: { syntax: 0.9, string_recovery: 0.75, control_flow: 0.65 },
      static_only: true,
    },
    warnings: [],
    errors: [],
  })
)
