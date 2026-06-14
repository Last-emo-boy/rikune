#!/usr/bin/env node

const mode = process.argv[2] ?? 'success'

if (mode === 'self-test') {
  console.log('fixture ok')
  process.exit(0)
}

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

const request = JSON.parse((await readStdin()) || '{}')

if (mode === 'malformed') {
  console.log('not-json')
  process.exit(0)
}

if (mode === 'large') {
  console.log('x'.repeat(2048))
  process.exit(0)
}

if (mode === 'slow') {
  await new Promise((resolve) => setTimeout(resolve, 250))
}

if (mode === 'fail') {
  console.error('fixture failed')
  process.exit(2)
}

if (mode === 'leak') {
  console.error(`token=${process.env.RIKUNE_TEST_SECRET_VALUE || 'missing'}`)
  console.error(`path=${process.cwd()}\\sensitive\\fixture.bin`)
  process.exit(2)
}

console.log(
  JSON.stringify({
    ok: true,
    data: {
      backend: request.backend?.backendName ?? 'FixtureBackend',
      adapter: request.backend?.adapter ?? 'fixture.adapter',
      external: true,
      input_path: request.input?.path ?? null,
    },
    warnings: [],
    errors: [],
  })
)
