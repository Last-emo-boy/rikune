import fs from 'node:fs'
import path from 'node:path'
import { describe, expect, test } from '@jest/globals'

const repositoryRoot = process.cwd()
const generatedComposeFiles = [
  'docker-compose.analyzer.yml',
  'docker-compose.hybrid.yml',
]

describe('Docker Compose contracts', () => {
  test('pins every generated Analyzer image to linux/amd64', () => {
    const generator = fs.readFileSync(
      path.join(repositoryRoot, 'scripts/generate-docker.mjs'),
      'utf8'
    )
    expect(generator).toContain('    platform: linux/amd64')

    for (const relativePath of generatedComposeFiles) {
      const compose = fs.readFileSync(path.join(repositoryRoot, relativePath), 'utf8')
      expect(compose).toContain('# Auto-generated from plugin systemDeps.')
      expect(compose.match(/^    platform: linux\/amd64$/gmu)).toHaveLength(1)
    }
  })

  test('loads the installer-owned runtime env for every npm Compose entrypoint', () => {
    const manifest = JSON.parse(
      fs.readFileSync(path.join(repositoryRoot, 'package.json'), 'utf8')
    ) as { scripts: Record<string, string> }

    for (const scriptName of [
      'docker:build',
      'docker:build:static',
      'docker:build:hybrid',
      'docker:up:static',
      'docker:up:full',
      'docker:up:hybrid',
    ]) {
      expect(manifest.scripts[scriptName]).toContain(
        'docker compose --env-file .docker-runtime.env -f '
      )
    }

    expect(manifest.scripts['docker:test']).toBe(
      'docker run --rm --entrypoint /usr/local/bin/validate-docker-full-stack.sh rikune:latest'
    )
  })
})
