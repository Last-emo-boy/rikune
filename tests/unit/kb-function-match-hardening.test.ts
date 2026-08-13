/**
 * Security and resource-boundary regressions for kb.function.match.
 */

import { describe, expect, jest, test } from '@jest/globals'
import {
  createKbFunctionMatchHandler,
  enrichKbFunctionMatchResultData,
  KbFunctionMatchInputSchema,
  KbFunctionMatchOutputSchema,
} from '../../src/plugins/kb-collaboration/tools/kb-function-match.js'

type FunctionRecord = Record<string, unknown>
type FunctionKbRow = Record<string, unknown>

function functionEvidence(functions: FunctionRecord[]) {
  return [
    {
      evidence_family: 'function_index',
      result_json: { data: { functions } },
    },
  ]
}

function createHarness(input: {
  targetFunctions: FunctionRecord[]
  referenceFunctions?: FunctionRecord[]
  targetEvidence?: unknown[]
  referenceEvidence?: unknown[]
  kbRows?: FunctionKbRow[]
  targetSampleId?: string
  sample?: Record<string, unknown>
}) {
  const targetSampleId = input.targetSampleId ?? 'sha256:target'
  const querySql = jest.fn((sql?: string, _params?: unknown[]) => {
    if (/COUNT\(\*\) AS scanned_rows/i.test(String(sql))) {
      const count = input.kbRows?.length ?? 0
      return [{ scanned_rows: count, oversized_rows: 0, eligible_rows: count }]
    }
    return input.kbRows ?? []
  })
  const database = {
    findSample: jest.fn(() => input.sample ?? { id: 'target' }),
    findAnalysisEvidenceBySample: jest.fn((sampleId: string) =>
      sampleId === targetSampleId
        ? (input.targetEvidence ?? functionEvidence(input.targetFunctions))
        : (input.referenceEvidence ?? functionEvidence(input.referenceFunctions ?? []))
    ),
    querySql,
  }
  const handler = createKbFunctionMatchHandler({
    workspaceManager: {},
    database,
    persistStaticAnalysisJsonArtifact: jest.fn(async () => undefined),
  } as any)

  return { handler, querySql }
}

function matchingKbRow(overrides: FunctionKbRow = {}): FunctionKbRow {
  return {
    id: 'kb-match',
    features_apis_json: '["CreateFileW","ReadFile"]',
    features_strings_json: '["settings.bin"]',
    features_cfg_shape: 'blocks:4;edges:5;loops:1',
    features_crypto_constants_json: '["0x9e3779b9"]',
    semantics_name: 'read_settings',
    semantics_confidence: 0.98,
    semantics_source: 'human',
    samples_json: '[]',
    ...overrides,
  }
}

const matchingTarget: FunctionRecord = {
  address: '0x401000',
  name: 'sub_401000',
  api_calls: ['CreateFileW', 'ReadFile'],
  strings: ['settings.bin'],
  cfg_shape: 'blocks:4;edges:5;loops:1',
  crypto_constants: ['0x9e3779b9'],
}

describe('kb.function.match hardening', () => {
  test.each([
    ['algorithm-qualified SHA-256', `sha256:${'a'.repeat(64)}`],
    ['algorithm inferred from digest length', 'B'.repeat(64)],
  ])('accepts an exact match for a valid %s digest', async (_label, digest) => {
    const { handler } = createHarness({
      targetFunctions: [{ address: '0x401100', name: 'target_fn', hash: digest }],
      referenceFunctions: [{ address: '0x501100', name: 'reference_fn', byte_hash: digest }],
    })

    const result = await handler(
      KbFunctionMatchInputSchema.parse({
        sample_id: 'sha256:target',
        match_against: ['sha256:reference'],
        min_confidence: 1,
      })
    )

    expect(result.ok).toBe(true)
    expect(result.data).toEqual(
      expect.objectContaining({
        exact_matches: 1,
        match_count: 1,
        matches: [
          expect.objectContaining({
            confidence: 1,
            match_basis: expect.arrayContaining(['exact_hash']),
          }),
        ],
      })
    )
  })

  test.each([
    ['short placeholder', 'same-hash'],
    ['MD5 digest', 'c'.repeat(32)],
    ['SHA-1 digest', `sha1:${'d'.repeat(40)}`],
  ])('never treats two identical %s values as exact', async (_label, digest) => {
    const { handler } = createHarness({
      targetFunctions: [{ address: '0x401120', name: 'target_fn', hash: digest }],
      referenceFunctions: [{ address: '0x501120', name: 'reference_fn', byte_hash: digest }],
    })

    const result = await handler(
      KbFunctionMatchInputSchema.parse({
        sample_id: 'sha256:target',
        match_against: ['sha256:reference'],
      })
    )

    expect(result.ok).toBe(true)
    expect(result.data).toEqual(
      expect.objectContaining({
        exact_matches: 0,
        match_count: 0,
        matches: [],
      })
    )
  })

  test.each(['md5', 'sha1', 'unsupported'])(
    'fails closed when a 64-hex digest declares unsupported algorithm %s',
    async (hash_algorithm) => {
      const digest = 'e'.repeat(64)
      const { handler } = createHarness({
        targetFunctions: [{ address: '0x401125', name: 'target_fn', hash: digest, hash_algorithm }],
        referenceFunctions: [
          { address: '0x501125', name: 'reference_fn', hash: digest, hash_algorithm },
        ],
      })

      const result = await handler({
        sample_id: 'sha256:target',
        match_against: ['sha256:reference'],
      })

      expect(result.ok).toBe(true)
      expect(result.data).toEqual(
        expect.objectContaining({ exact_matches: 0, match_count: 0, matches: [] })
      )
    }
  )

  test('fails closed and reports malformed function_kb samples_json', async () => {
    const { handler } = createHarness({
      targetFunctions: [matchingTarget],
      kbRows: [matchingKbRow({ samples_json: '["sha256:reference"' })],
    })

    const result = await handler(KbFunctionMatchInputSchema.parse({ sample_id: 'sha256:target' }))

    expect(result.ok).toBe(true)
    expect(result.data).toEqual(
      expect.objectContaining({
        reference_function_count: 0,
        match_count: 0,
      })
    )
    const diagnosticText = JSON.stringify({
      warnings: result.warnings ?? [],
      diagnostics: (result.data as any)?.diagnostics,
      analysis_limits: (result.data as any)?.analysis_limits,
    })
    expect(diagnosticText).toMatch(
      /(?:malformed|invalid).*samples_json|samples_json.*(?:malformed|invalid)/i
    )
  })

  test('excludes every KB row associated with the target, even when other samples are present', async () => {
    const { handler } = createHarness({
      targetFunctions: [matchingTarget],
      kbRows: [
        matchingKbRow({
          samples_json: '["sha256:target","sha256:other"]',
        }),
      ],
    })

    const result = await handler(KbFunctionMatchInputSchema.parse({ sample_id: 'sha256:target' }))

    expect(result.ok).toBe(true)
    expect(result.data).toEqual(
      expect.objectContaining({
        reference_function_count: 0,
        exact_matches: 0,
        match_count: 0,
      })
    )
  })

  test('finds target provenance beyond the feature-list limit and still excludes the KB row', async () => {
    const provenance = Array.from({ length: 512 }, (_, index) => `sha256:other-${index}`)
    provenance.push('sha256:target')
    const { handler } = createHarness({
      targetFunctions: [matchingTarget],
      kbRows: [matchingKbRow({ samples_json: JSON.stringify(provenance) })],
    })

    const result = await handler(KbFunctionMatchInputSchema.parse({ sample_id: 'sha256:target' }))

    expect(result.ok).toBe(true)
    expect(result.data).toEqual(
      expect.objectContaining({
        reference_function_count: 0,
        match_count: 0,
        diagnostics: expect.objectContaining({ self_referential_kb_rows_excluded: 1 }),
      })
    )
  })

  test('normalizes raw and prefixed SHA-256 provenance before excluding self references', async () => {
    const digest = 'f'.repeat(64)
    const targetSampleId = `sha256:${digest}`
    const { handler } = createHarness({
      targetSampleId,
      sample: { id: targetSampleId, sha256: digest },
      targetFunctions: [matchingTarget],
      kbRows: [matchingKbRow({ samples_json: JSON.stringify([digest]) })],
    })

    const result = await handler({ sample_id: targetSampleId })

    expect(result.ok).toBe(true)
    expect(result.data).toEqual(
      expect.objectContaining({
        reference_function_count: 0,
        match_count: 0,
        diagnostics: expect.objectContaining({ self_referential_kb_rows_excluded: 1 }),
      })
    )
  })

  test('keeps legacy API-plus-size similarity while forcing review-tier confidence', async () => {
    const { handler } = createHarness({
      targetFunctions: [
        {
          address: '0x401200',
          name: 'target_reader',
          size: 80,
          api_calls: ['CreateFileW', 'ReadFile'],
        },
      ],
      referenceFunctions: [
        {
          address: '0x501200',
          name: 'reference_reader',
          size: 80,
          api_calls: ['CreateFileW', 'ReadFile'],
        },
      ],
    })

    const result = await handler(
      KbFunctionMatchInputSchema.parse({
        sample_id: 'sha256:target',
        match_against: ['sha256:reference'],
      })
    )

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.match_count).toBe(1)
    expect(data.high_confidence_matches).toBe(0)
    expect(data.matches[0]).toEqual(
      expect.objectContaining({
        similarity: 1,
        legacy_similarity: 1,
        confidence_tier: 'review',
        match_basis: expect.arrayContaining(['api_calls', 'size']),
      })
    )
    expect(data.matches[0].confidence).toBeGreaterThanOrEqual(0.7)
    expect(data.matches[0].confidence).toBeLessThan(0.8)
    expect(data.matches[0].calibration).toEqual(
      expect.objectContaining({
        applied_cap: 'legacy_review',
        applied_cap_value: 0.79,
        final_score: 0.79,
      })
    )
    expect(data.matches[0].calibration.final_score).toBe(
      Math.min(
        data.matches[0].calibration.pre_cap_score,
        data.matches[0].calibration.applied_cap_value
      )
    )
  })

  test('does not let a negligible second-view overlap escape the legacy review cap', async () => {
    const targetStrings = [
      'shared-token',
      ...Array.from({ length: 511 }, (_, index) => `t-${index}`),
    ]
    const referenceStrings = [
      'shared-token',
      ...Array.from({ length: 511 }, (_, index) => `r-${index}`),
    ]
    const { handler } = createHarness({
      targetFunctions: [
        {
          address: '0x401205',
          name: 'target_reader',
          size: 80,
          api_calls: ['CreateFileW', 'ReadFile'],
          strings: targetStrings,
        },
      ],
      referenceFunctions: [
        {
          address: '0x501205',
          name: 'reference_reader',
          size: 80,
          api_calls: ['CreateFileW', 'ReadFile'],
          strings: referenceStrings,
        },
      ],
    })

    const result = await handler({
      sample_id: 'sha256:target',
      match_against: ['sha256:reference'],
    })

    expect(result.ok).toBe(true)
    const match = (result.data as any).matches[0]
    expect(match.score_breakdown.strings).toBeGreaterThan(0)
    expect(match.score_breakdown.strings).toBeLessThan(match.calibration.strong_signal_min_score)
    expect(match).toEqual(expect.objectContaining({ confidence: 0.79, confidence_tier: 'review' }))
    expect(match.calibration).toEqual(
      expect.objectContaining({
        mode: 'legacy_api_size',
        independent_signal_count: 1,
        applied_cap: 'legacy_review',
      })
    )
  })

  test('binds the KB reference limit and reports truncation diagnostics', async () => {
    const rows = [
      matchingKbRow({ id: 'kb-one', semantics_name: 'candidate_one' }),
      matchingKbRow({ id: 'kb-two', semantics_name: 'candidate_two' }),
      matchingKbRow({ id: 'kb-three', semantics_name: 'candidate_three' }),
    ]
    const { handler, querySql } = createHarness({
      targetFunctions: [matchingTarget],
      kbRows: rows,
    })

    const result = await handler(
      KbFunctionMatchInputSchema.parse({
        sample_id: 'sha256:target',
        max_reference_functions: 2,
      })
    )

    expect(result.ok).toBe(true)
    const limitCall = querySql.mock.calls.find(([sql]) =>
      /JOIN\s+function_kb\s+AS\s+f/i.test(String(sql))
    )
    expect(limitCall).toBeDefined()
    expect(String(limitCall?.[0])).toMatch(/LIMIT\s+\?/i)
    expect(limitCall?.[1]?.at(-1)).toBe(3)
    expect(String(limitCall?.[0])).toMatch(/length\s*\(/i)

    const data = result.data as any
    expect(data.reference_function_count).toBe(2)
    const limitDiagnostics = data.analysis_limits ?? data.diagnostics
    expect(limitDiagnostics).toBeDefined()
    const diagnosticText = JSON.stringify(limitDiagnostics)
    expect(diagnosticText).toMatch(/reference/i)
    expect(diagnosticText).toMatch(/truncat/i)
    expect(diagnosticText).toContain('true')
    expect(result.warnings?.join(' ')).toMatch(/truncat/i)
  })

  test('matches complete API, string, and CFG views without crypto constants at the default threshold', async () => {
    const targetWithoutConstants = { ...matchingTarget }
    delete targetWithoutConstants.crypto_constants
    const { handler } = createHarness({
      targetFunctions: [targetWithoutConstants],
      kbRows: [
        matchingKbRow({
          features_crypto_constants_json: '[]',
          semantics_confidence: 0.96,
          samples_json: '["sha256:reference"]',
        }),
      ],
    })

    const result = await handler(KbFunctionMatchInputSchema.parse({ sample_id: 'sha256:target' }))

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.match_count).toBe(1)
    expect(data.matches[0]).toEqual(
      expect.objectContaining({
        matched_function: 'read_settings',
        confidence: expect.any(Number),
        match_basis: expect.arrayContaining(['api_calls', 'strings', 'cfg_shape']),
      })
    )
    expect(data.matches[0].confidence).toBeGreaterThanOrEqual(0.7)
    expect(data.matches[0].match_basis).not.toContain('crypto_constants')
  })

  test('keeps the newest evidence for one stable reference address without creating ambiguity', async () => {
    const stableReference = {
      address: '0x501300',
      size: 112,
      api_calls: ['CreateFileW', 'ReadFile'],
      strings: ['settings.bin'],
      cfg_shape: 'blocks:4;edges:5;loops:1',
    }
    const newestEvidence = functionEvidence([
      {
        ...stableReference,
        name: 'newest_reference_name',
        hash: 'a'.repeat(64),
      },
    ])[0]
    const olderEvidence = functionEvidence([
      {
        ...stableReference,
        name: 'older_reference_name',
        hash: 'b'.repeat(64),
      },
    ])[0]
    const { handler } = createHarness({
      targetFunctions: [
        {
          address: '0x401300',
          name: 'target_fn',
          size: stableReference.size,
          api_calls: stableReference.api_calls,
          strings: stableReference.strings,
          cfg_shape: stableReference.cfg_shape,
        },
      ],
      referenceEvidence: [newestEvidence, olderEvidence],
    })

    const result = await handler(
      KbFunctionMatchInputSchema.parse({
        sample_id: 'sha256:target',
        match_against: ['sha256:reference'],
      })
    )

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.reference_function_count).toBe(1)
    expect(data.match_count).toBe(1)
    expect(data.ambiguous_matches).toBe(0)
    expect(data.matches[0]).toEqual(
      expect.objectContaining({
        matched_function: 'newest_reference_name',
        matched_address: stableReference.address,
        ambiguous: false,
        alternative_count: 0,
      })
    )
  })

  test('validates a real hardened handler result against its public output schema', async () => {
    const digest = `sha256:${'c'.repeat(64)}`
    const { handler } = createHarness({
      targetFunctions: [{ address: '0x401400', name: 'target_fn', hash: digest }],
      referenceFunctions: [{ address: '0x501400', name: 'reference_fn', hash: digest }],
    })

    const result = await handler(
      KbFunctionMatchInputSchema.parse({
        sample_id: 'sha256:target',
        match_against: ['sha256:reference'],
      })
    )
    const parsed = KbFunctionMatchOutputSchema.safeParse(result)

    expect(result.ok).toBe(true)
    expect(parsed.success ? [] : parsed.error.issues).toEqual([])
    expect(parsed.success).toBe(true)
  })

  test('does not claim feature-level explanations when there are no matches', () => {
    const data = enrichKbFunctionMatchResultData({
      sample_id: 'sha256:target',
      target_function_count: 1,
      reference_function_count: 1,
      match_count: 0,
      exact_matches: 0,
      high_confidence_matches: 0,
      matches: [],
    })

    expect((data.quality_gates as any).feature_level_explanations_present).toBe(false)
  })
})
