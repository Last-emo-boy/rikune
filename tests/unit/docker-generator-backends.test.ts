import { execFileSync } from 'child_process'
import { describe, expect, test } from '@jest/globals'

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
})
