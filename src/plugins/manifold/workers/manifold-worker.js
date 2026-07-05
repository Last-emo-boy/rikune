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
  console.log('manifold-worker ok')
  process.exit(0)
}

const request = JSON.parse((await readStdin()) || '{}')
const input = request.input ?? {}
console.log(
  JSON.stringify({
    ok: true,
    data: {
      backend: 'Manifold',
      adapter: 'manifold.declarative.fact.extract',
      input_path: input.path ?? input.source_path ?? null,
      facts: { functions: 1, blocks: 3, edges: 2, calls: 1 },
      agreement: { agreed: 4, conflicting: 0, missing: 1 },
    },
    warnings: [],
    errors: [],
  })
)
