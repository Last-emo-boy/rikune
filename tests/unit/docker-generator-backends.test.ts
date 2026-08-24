import { execFileSync, spawnSync } from 'child_process'
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'fs'
import { describe, expect, test } from '@jest/globals'
import { tmpdir } from 'os'
import { join } from 'path'
import YAML from 'yaml'

function dockerDryRun(args: string[] = []): string {
  return execFileSync('node', ['scripts/generate-docker.mjs', '--dry-run', ...args], {
    cwd: process.cwd(),
    encoding: 'utf8',
    env: { ...process.env },
  })
}

function runGeneratorWithSourceRewrite(rewriteSource: string) {
  const tempRoot = mkdtempSync(join(tmpdir(), 'rikune-docker-supply-chain-'))
  const preloadPath = join(tempRoot, 'rewrite-source.cjs')
  writeFileSync(
    preloadPath,
    [
      "const fs = require('node:fs')",
      "const { syncBuiltinESMExports } = require('node:module')",
      'const original = fs.readFileSync',
      `const rewrite = ${rewriteSource}`,
      'fs.readFileSync = (path, ...args) => {',
      '  const content = original(path, ...args)',
      "  return typeof content === 'string' ? rewrite(String(path), content) : content",
      '}',
      'syncBuiltinESMExports()',
      '',
    ].join('\n')
  )

  const result = spawnSync(
    process.execPath,
    ['scripts/generate-docker.mjs', '--profile=static', `--output=${join(tempRoot, 'output')}`],
    {
      cwd: process.cwd(),
      encoding: 'utf8',
      env: { ...process.env, NODE_OPTIONS: `--require=${preloadPath}` },
    }
  )
  const composePath = join(tempRoot, 'output', 'docker-compose.analyzer.yml')
  const generatedCompose = existsSync(composePath) ? readFileSync(composePath, 'utf8') : ''
  rmSync(tempRoot, { recursive: true, force: true })
  return { ...result, generatedCompose }
}

describe('docker generator backend install reports', () => {
  test('prints backend install route classification', () => {
    const output = dockerDryRun(['--include=restringer,jsimplifier,manifold,wabt'])

    expect(output).toContain('Backend install profile: default')
    expect(output).toContain('restringer: installed')
    expect(output).toContain('jsimplifier: installed')
    expect(output).toContain('manifold: installed')
    expect(output).toContain('wabt: installed')
  })

  test('profile-gated backend is skipped by default and enabled by optional profile', () => {
    const skipped = dockerDryRun(['--include=jsir-cascade'])
    expect(skipped).toContain('jsir-cascade: profile-gated (optional) skipped')

    const enabled = dockerDryRun(['--include=jsir-cascade', '--backend-profile=optional'])
    expect(enabled).toContain('jsir-cascade: profile-gated (optional) enabled')
  })

  test('optional JVM decompiler profile installs Java and CFR through its fragment', () => {
    const skipped = dockerDryRun(['--include=jvm-decompile'])
    expect(skipped).toContain('jvm-decompile: profile-gated (optional) skipped')
    expect(skipped).not.toContain('jvm-decompile: installed')

    const enabled = dockerDryRun(['--include=jvm-decompile', '--backend-profile=optional'])
    expect(enabled).toContain('--include dependencies: added jvm')
    expect(enabled).toContain('Runtime plugins (2): jvm, jvm-decompile')
    expect(enabled).toContain('jvm-decompile: profile-gated (optional) enabled')
    expect(enabled).not.toContain('jvm-decompile: installed')
    expect(enabled).toContain('jvm-decompile (jvm-decompile) [args, stage, runtime]')
  })

  test('all declared backend routes avoid missing install classifications', () => {
    const output = dockerDryRun()

    expect(output).not.toContain('Metadata load warnings')
    expect(output).not.toMatch(/^\s+- .*: missing /m)
    expect(output).toContain('javascript-deobfuscation: validation-only (default) skipped')
    expect(output).toContain('remill: byo (heavy) skipped')
    expect(output).toContain('revng: sidecar (heavy) skipped')
    expect(output).toContain('qbdi: byo (runtime) skipped')
    expect(output).toContain('culifter: byo (gpu) skipped')
    expect(output).toContain('qiling: validation-only (default) skipped')
  })

  test('optional backend profile enables optional static backends without enabling BYO routes', () => {
    const output = dockerDryRun([
      '--include=jsir-cascade,jsvmp-analysis,gtirb,radare2,remill,revng,qbdi,culifter',
      '--backend-profile=optional',
    ])

    expect(output).toContain('jsir-cascade: profile-gated (optional) enabled')
    expect(output).toContain('jsvmp-analysis: profile-gated (optional) enabled')
    expect(output).toContain('gtirb: profile-gated (optional) enabled')
    expect(output).toContain('radare2: profile-gated (optional) enabled')
    expect(output).toContain('remill: byo (heavy) skipped')
    expect(output).toContain('revng: sidecar (heavy) skipped')
    expect(output).toContain('qbdi: byo (runtime) skipped')
    expect(output).toContain('culifter: byo (gpu) skipped')
  })

  test('compose dry-run reports selected backend profile', () => {
    const output = dockerDryRun(['--backend-profile=research', '--include=miasm'])

    expect(output).toContain('Backend install profile: research')
    expect(output).toContain('dynamic-python: profile-gated (license-gated) enabled')
  })

  test('creates nested profile paths below a new output directory', () => {
    const outputDir = mkdtempSync(join(tmpdir(), 'rikune-docker-output-'))
    try {
      execFileSync(
        'node',
        [
          'scripts/generate-docker.mjs',
          '--profile=hybrid',
          '--include=jvm-decompile',
          '--backend-profile=optional',
          `--output=${outputDir}`,
        ],
        {
          cwd: process.cwd(),
          encoding: 'utf8',
          env: { ...process.env },
        }
      )

      expect(existsSync(join(outputDir, 'docker', 'Dockerfile.hybrid'))).toBe(true)
      expect(existsSync(join(outputDir, 'docker-compose.hybrid.yml'))).toBe(true)
    } finally {
      rmSync(outputDir, { recursive: true, force: true })
    }
  })

  test('keeps static and hybrid Dockerfile identities separate in all-profile generation', () => {
    const outputDir = mkdtempSync(join(tmpdir(), 'rikune-docker-all-output-'))
    try {
      execFileSync(
        'node',
        ['scripts/generate-docker.mjs', '--all-profiles', `--output=${outputDir}`],
        {
          cwd: process.cwd(),
          encoding: 'utf8',
          env: { ...process.env },
        }
      )

      const staticDockerfile = readFileSync(
        join(outputDir, 'docker', 'Dockerfile.analyzer'),
        'utf8'
      )
      const hybridDockerfile = readFileSync(join(outputDir, 'docker', 'Dockerfile.hybrid'), 'utf8')
      const fullDockerfile = readFileSync(join(outputDir, 'Dockerfile'), 'utf8')
      const staticCompose = readFileSync(join(outputDir, 'docker-compose.analyzer.yml'), 'utf8')
      const hybridCompose = readFileSync(join(outputDir, 'docker-compose.hybrid.yml'), 'utf8')

      expect(staticDockerfile).toContain("RUN printf 'static\\n' > /app/.rikune-static-profile")
      expect(staticDockerfile).toContain(
        'RIKUNE_STATIC_PROFILE_LOCK_PATH=/app/static-profile.lock.json'
      )
      expect(staticDockerfile).toContain('USER 1000:1000')
      expect(hybridDockerfile).not.toContain('/app/.rikune-static-profile')
      expect(hybridDockerfile).toContain('USER 1000:1000')
      expect(hybridDockerfile).toContain('scripts/verify-hybrid-runtime.mjs')
      expect(hybridDockerfile).toContain('chmod 0555 ./scripts/secure-fs-helper.py')
      expect(fullDockerfile).toContain(
        'COPY scripts/validate-docker-full-stack.sh /usr/local/bin/validate-docker-full-stack.sh'
      )
      expect(fullDockerfile).toContain(
        'chmod 0555 /usr/local/bin/validate-docker-full-stack.sh'
      )
      expect(staticDockerfile).not.toContain('validate-docker-full-stack.sh')
      expect(hybridDockerfile).not.toContain('validate-docker-full-stack.sh')
      expect(staticCompose).toContain('dockerfile: docker/Dockerfile.analyzer')
      expect(hybridCompose).toContain('dockerfile: docker/Dockerfile.hybrid')
      expect(hybridCompose).toContain(
        'RIKUNE_ALLOW_INSECURE_RUNTIME_HTTP=${RIKUNE_ALLOW_INSECURE_RUNTIME_HTTP:-false}'
      )
    } finally {
      rmSync(outputDir, { recursive: true, force: true })
    }
  })

  test('derives every static Compose backend binding from the exact lock', () => {
    const lock = JSON.parse(readFileSync(join(process.cwd(), 'static-profile.lock.json'), 'utf8'))
    const compose = YAML.parse(
      readFileSync(join(process.cwd(), 'docker-compose.analyzer.yml'), 'utf8')
    )
    const environment = new Map<string, string>(
      compose.services.analyzer.environment.map((entry: string) => {
        const separator = entry.indexOf('=')
        return [entry.slice(0, separator), entry.slice(separator + 1)]
      })
    )

    for (const binding of lock.required_backends.flatMap((backend: any) => backend.environment)) {
      if (binding.must_be_unset) expect(environment.has(binding.name)).toBe(false)
      else if (binding.required) expect(environment.get(binding.name)).toBe(binding.value)
    }
  })

  test('generates only immutable external FROM references and verified direct downloads', () => {
    const outputDir = mkdtempSync(join(tmpdir(), 'rikune-docker-pinned-'))
    try {
      execFileSync(
        process.execPath,
        [
          'scripts/generate-docker.mjs',
          '--profile=full',
          '--backend-profile=all',
          `--output=${outputDir}`,
        ],
        { cwd: process.cwd(), encoding: 'utf8', env: { ...process.env } }
      )
      const dockerfile = readFileSync(join(outputDir, 'Dockerfile'), 'utf8')
      const stages = new Set<string>()
      for (const line of dockerfile.split('\n')) {
        const match = line.match(/^FROM\s+(\S+)(?:\s+AS\s+(\S+))?$/i)
        if (!match) continue
        if (!stages.has(match[1].toLowerCase()) && match[1] !== 'scratch') {
          expect(match[1]).toMatch(/^[^@\s]+:[^@\s]+@sha256:[a-f0-9]{64}$/)
        }
        if (match[2]) stages.add(match[2].toLowerCase())
      }
      expect(dockerfile).toContain(
        'FROM mcr.microsoft.com/dotnet/runtime:8.0-bookworm-slim@sha256:'
      )
      expect(dockerfile).toContain('--configfile /tmp/NuGet.Config')
      expect(dockerfile).not.toContain('packages-microsoft-prod.deb')
      expect(dockerfile).toContain('sha256sum -c -')
      expect(dockerfile).not.toMatch(/^ARG\s+\S*_SHA256(?:=|\s|$)/m)
    } finally {
      rmSync(outputDir, { recursive: true, force: true })
    }
  })

  test('prefers current source metadata over stale compiled plugin metadata', () => {
    const result = runGeneratorWithSourceRewrite(`(_path, content) => content`)
    const source = readFileSync(join(process.cwd(), 'src/plugins/ghidra/index.ts'), 'utf8')
    const sourceVersion = source.match(/GHIDRA_VERSION:\s*'([^']+)'/)?.[1]

    expect(result.status).toBe(0)
    expect(sourceVersion).toBe('12.1.3')
    expect(result.generatedCompose).toContain(`GHIDRA_VERSION: "${sourceVersion}"`)

    const distPath = join(process.cwd(), 'dist/plugins/ghidra/index.js')
    if (existsSync(distPath)) {
      const dist = readFileSync(distPath, 'utf8')
      const distVersion = dist.match(/GHIDRA_VERSION:\s*['"]([^'"]+)['"]/)?.[1]
      if (distVersion && distVersion !== sourceVersion) {
        expect(result.generatedCompose).not.toContain(`GHIDRA_VERSION: "${distVersion}"`)
      }
    }
  })

  test('rejects a bare external FROM during generation', () => {
    const result = runGeneratorWithSourceRewrite(
      `(path, content) => path.endsWith('Dockerfile.template') ? content.replace(/FROM node:22-slim@sha256:[a-f0-9]{64} AS builder/, 'FROM node:22-slim AS builder') : content`
    )

    expect(result.status).not.toBe(0)
    expect(result.stderr).toContain(
      'External FROM must use an immutable tag@sha256 OCI index digest'
    )
  })

  test('rejects a direct download consumed before SHA256 verification', () => {
    const result = runGeneratorWithSourceRewrite(
      `(path, content) => path.endsWith('ghidra.dockerfile') ? content.replace(/^.*93a5d11a9ad510622acaaf908c556a7b9b764d338e78a7567f3689bf5081fd54.*sha256sum.*\\n/m, '') : content`
    )

    expect(result.status).not.toBe(0)
    expect(result.stderr).toContain(
      'Direct download must be immediately followed by SHA256 verification before consumption'
    )
  })

  test('rejects an unhashed Python install in the static profile', () => {
    const result = runGeneratorWithSourceRewrite(
      `(path, content) => path.endsWith('Dockerfile.template') ? content.replace(' --require-hashes', '') : content`
    )

    expect(result.status).not.toBe(0)
    expect(result.stderr).toContain('Static profile Python install must use --require-hashes')
  })

  test('rejects a Python package upgrade in the static profile', () => {
    const result = runGeneratorWithSourceRewrite(
      `(path, content) => path.endsWith('Dockerfile.template') ? content.replace('pip install --no-cache-dir --require-hashes', 'pip install --no-cache-dir --upgrade --require-hashes') : content`
    )

    expect(result.status).not.toBe(0)
    expect(result.stderr).toContain(
      'Static profile must not upgrade Python packages during image generation'
    )
  })

  test('rejects bundled Qiling while its dependency chain is below the vulnerability baseline', () => {
    const result = runGeneratorWithSourceRewrite(
      `(path, content) => path.endsWith('Dockerfile.template') ? content.replace('WORKDIR /app', 'WORKDIR /app\\nRUN python3 -m pip install qiling') : content`
    )

    expect(result.status).not.toBe(0)
    expect(result.stderr).toContain(
      'Generated profiles must not bundle Qiling while its supported dependency chain is below the release vulnerability baseline'
    )
  })

  test.each(['/opt/rikune-venvs/gtirb'])(
    'rejects non-release optional Python dependency %s in the static profile',
    (optionalDependency) => {
      const result = runGeneratorWithSourceRewrite(
        `(path, content) => path.endsWith('Dockerfile.template') ? content.replace('WORKDIR /app', 'WORKDIR /app\\n# ${optionalDependency}') : content`
      )

      expect(result.status).not.toBe(0)
      expect(result.stderr).toContain(
        'Static profile must not include non-release optional Python dependency'
      )
    }
  )

  test('is deterministic when filesystem directory iteration order changes', () => {
    const tempRoot = mkdtempSync(join(tmpdir(), 'rikune-docker-order-'))
    const normalOutput = join(tempRoot, 'normal')
    const reversedOutput = join(tempRoot, 'reversed')
    const preloadPath = join(tempRoot, 'reverse-readdir.cjs')
    writeFileSync(
      preloadPath,
      [
        "const fs = require('node:fs')",
        "const { syncBuiltinESMExports } = require('node:module')",
        'const original = fs.readdirSync',
        'fs.readdirSync = (...args) => {',
        '  const entries = original(...args)',
        '  return Array.isArray(entries) ? [...entries].reverse() : entries',
        '}',
        'syncBuiltinESMExports()',
        '',
      ].join('\n')
    )

    try {
      const generate = (output: string, nodeOptions?: string) =>
        execFileSync(
          'node',
          ['scripts/generate-docker.mjs', '--profile=static', `--output=${output}`],
          {
            cwd: process.cwd(),
            encoding: 'utf8',
            env: {
              ...process.env,
              ...(nodeOptions ? { NODE_OPTIONS: nodeOptions } : {}),
            },
          }
        )

      generate(normalOutput)
      generate(reversedOutput, `--require=${preloadPath}`)

      for (const relativePath of [
        'docker/Dockerfile.analyzer',
        'docker-compose.analyzer.yml',
        'static-profile.lock.json',
      ]) {
        expect(readFileSync(join(reversedOutput, relativePath))).toEqual(
          readFileSync(join(normalOutput, relativePath))
        )
      }
    } finally {
      rmSync(tempRoot, { recursive: true, force: true })
    }
  })
})
