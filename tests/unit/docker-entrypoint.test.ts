import { execFileSync } from 'node:child_process'
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { describe, expect, test } from '@jest/globals'

const entrypointPath = resolve(process.cwd(), 'docker-entrypoint.sh')
const dockerfileTemplatePath = resolve(process.cwd(), 'docker', 'Dockerfile.template')

describe('Docker entrypoint command contract', () => {
  test('is valid Bash and forwards Docker CMD or runtime overrides', () => {
    execFileSync('bash', ['-n', entrypointPath])

    const source = readFileSync(entrypointPath, 'utf8')
    const dockerfileTemplate = readFileSync(dockerfileTemplatePath, 'utf8')

    expect(source).toMatch(/if \[ "\$#" -eq 0 \]; then\s+set -- node dist\/index\.js\s+fi/)
    expect(source).toMatch(/exec "\$@"\s*$/)
    expect(source).not.toMatch(/exec node dist\/index\.js\s*$/)
    expect(dockerfileTemplate).toContain('ENTRYPOINT ["/docker-entrypoint.sh"]')
    expect(dockerfileTemplate).toContain('CMD ["node", "dist/index.js"]')
  })
})
