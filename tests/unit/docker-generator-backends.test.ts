import { execFileSync } from 'child_process'
import { existsSync, mkdtempSync, rmSync } from 'fs'
import { describe, expect, test } from '@jest/globals'
import { tmpdir } from 'os'
import { join } from 'path'

function dockerDryRun(args: string[] = []): string {
  return execFileSync('node', ['scripts/generate-docker.mjs', '--dry-run', ...args], {
    cwd: process.cwd(),
    encoding: 'utf8',
    env: { ...process.env },
  })
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
          '--profile=static',
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

      expect(existsSync(join(outputDir, 'docker', 'Dockerfile.analyzer'))).toBe(true)
      expect(existsSync(join(outputDir, 'docker-compose.analyzer.yml'))).toBe(true)
    } finally {
      rmSync(outputDir, { recursive: true, force: true })
    }
  })
})
