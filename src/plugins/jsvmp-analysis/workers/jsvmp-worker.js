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
  console.log('jsvmp-worker ok')
  process.exit(0)
}

const request = JSON.parse((await readStdin()) || '{}')
const input = request.input ?? {}
console.log(
  JSON.stringify({
    ok: true,
    data: {
      backend: 'JSVMP Analysis',
      adapter: 'jsvmp.static.parser',
      input_path: input.path ?? input.source_path ?? null,
      bytecode_candidates: 1,
      dispatcher_candidates: 1,
      static_only: true,
    },
    warnings: [],
    errors: [],
  })
)
