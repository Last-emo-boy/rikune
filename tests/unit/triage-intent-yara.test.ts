import { describe, expect, test } from '@jest/globals'
import {
  applyIntentAwareYaraAdjustments,
  buildLibraryProfile,
  calculateThreatLevelV2,
  extractCrateNameFromCargoPath,
} from '../../src/workflows/triage.js'

describe('triage intent-aware YARA adjustments', () => {
  test('downgrades generic trojan signals for dual-use tooling intent', () => {
    const adjusted = applyIntentAwareYaraAdjustments(
      [
        {
          rule: 'Generic_Trojan',
          level: 'high',
          score: 0.82,
          stringOnly: false,
          generic: true,
        },
      ],
      {
        label: 'dual_use_tool',
        confidence: 0.78,
        evidence: [],
        counter_evidence: [],
      }
    )

    expect(adjusted[0]?.level).toBe('low')
    expect(adjusted[0]?.score).toBeCloseTo(0.37, 2)
  })

  test('downgrades generic trojan signals by one level for operator utility intent', () => {
    const adjusted = applyIntentAwareYaraAdjustments(
      [
        {
          rule: 'Generic_Trojan',
          level: 'high',
          score: 0.82,
          stringOnly: false,
          generic: true,
        },
      ],
      {
        label: 'operator_utility',
        confidence: 0.62,
        evidence: [],
        counter_evidence: [],
      }
    )

    expect(adjusted[0]?.level).toBe('medium')
    expect(adjusted[0]?.score).toBeCloseTo(0.57, 2)
  })

  test('does not downgrade malware-specific signals', () => {
    const adjusted = applyIntentAwareYaraAdjustments(
      [
        {
          rule: 'Backdoor_Family_X',
          level: 'high',
          score: 0.91,
          stringOnly: false,
          generic: false,
        },
      ],
      {
        label: 'dual_use_tool',
        confidence: 0.78,
        evidence: [],
        counter_evidence: [],
      }
    )

    expect(adjusted[0]?.level).toBe('high')
    expect(adjusted[0]?.score).toBe(0.91)
  })

  test('keeps dual-use operator tooling at least suspicious when capabilities are present', () => {
    const adjustedSignals = applyIntentAwareYaraAdjustments(
      [
        {
          rule: 'Generic_Trojan',
          level: 'high',
          score: 0.82,
          stringOnly: false,
          generic: true,
        },
      ],
      {
        label: 'dual_use_tool',
        confidence: 0.78,
        evidence: [],
        counter_evidence: [],
      }
    )

    const threat = calculateThreatLevelV2(
      adjustedSignals,
      ['kernel32.dll!WriteProcessMemory', 'kernel32.dll!CreateProcessW'],
      ['cmd.exe /c whoami'],
      {
        label: 'dual_use_tool',
        confidence: 0.78,
        evidence: [],
        counter_evidence: [],
      }
    )

    expect(threat.level).toBe('suspicious')
  })

  test('extracts crate names from cargo registry paths', () => {
    expect(
      extractCrateNameFromCargoPath(
        'C:\\Users\\user\\.cargo\\registry\\src\\index.crates.io-1949cf8c6b5b557f\\iced-x86-1.21.0\\src\\decoder.rs'
      )
    ).toBe('iced-x86')
  })

  test('builds library profile from cargo paths and runtime hints', () => {
    const profile = buildLibraryProfile(
      {
        cargoPaths: [
          'C:\\Users\\user\\.cargo\\registry\\src\\index.crates.io-1949cf8c6b5b557f\\tokio-1.44.0\\src\\runtime\\mod.rs',
          'C:\\Users\\user\\.cargo\\registry\\src\\index.crates.io-1949cf8c6b5b557f\\goblin-0.8.2\\src\\pe\\mod.rs',
        ],
        crateNames: ['tokio', 'goblin', 'iced-x86'],
        libraryHints: ['tokio', 'goblin', 'iced-x86'],
        rustMarkers: ['core::panicking', '\\src\\main.rs'],
      },
      {
        suspected: [{ runtime: 'rust', confidence: 0.93 }],
      }
    )

    expect(profile).toBeDefined()
    expect(profile?.ecosystems).toContain('rust')
    expect(profile?.top_crates).toEqual(expect.arrayContaining(['tokio', 'goblin', 'iced-x86']))
    expect(profile?.notable_libraries).toEqual(
      expect.arrayContaining(['tokio', 'goblin', 'iced-x86'])
    )
    expect(profile?.evidence.some((item) => item.includes('Cargo/library references observed'))).toBe(
      true
    )
  })
})
