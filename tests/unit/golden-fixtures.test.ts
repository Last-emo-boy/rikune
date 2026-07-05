import fs from 'fs'
import path from 'path'
import { describe, expect, test } from '@jest/globals'

const manifestPath = path.join(process.cwd(), 'tests', 'fixtures', 'golden-samples.manifest.json')

describe('golden fixture manifest', () => {
  test('documents only safe default fixtures and required sample classes', () => {
    const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8')) as any

    expect(manifest.policy).toEqual(
      expect.objectContaining({
        allows_live_malware: false,
        allows_host_execution: false,
        default_ci_static_only: true,
      })
    )

    const fixtures = manifest.fixtures as any[]
    expect(fixtures.length).toBeGreaterThanOrEqual(8)
    expect(fixtures.every((fixture) => fixture.default_ci === true)).toBe(true)
    expect(
      fixtures.every((fixture) => fixture.runtime?.requires_live_execution === false)
    ).toBe(true)

    expect(fixtures.map((fixture) => fixture.class)).toEqual(
      expect.arrayContaining([
        'pe',
        'packed-pe',
        'dotnet-pe',
        'dll',
        'elf',
        'macho',
        'apk',
        'degraded-environment',
      ])
    )

    const peFastProfile = fixtures.find((fixture) => fixture.id === 'synthetic-pe-fast-profile')
    expect(peFastProfile.expected_signals.stage_plan).toEqual([
      'fast_profile',
      'enrich_static',
      'function_map',
      'summarize',
    ])
    expect(peFastProfile.expected_signals.evidence_families).toContain('backend_preview')

    const degraded = fixtures.find(
      (fixture) => fixture.id === 'degraded-missing-optional-backends'
    )
    expect(degraded.expected_signals.degradation).toEqual(
      expect.arrayContaining(['runtime_not_started', 'optional_backends_unavailable'])
    )
    expect(degraded.runtime.expected_actual_mode).toBe('plan_only')
  })
})
