import type { DatabaseManager } from '../../../database.js'
import type { DecompiledFunc } from '../vm/vm-detector.js'

export function parseJsonLike(value: unknown): unknown {
  if (typeof value !== 'string') {
    return value
  }
  try {
    return JSON.parse(value)
  } catch {
    return undefined
  }
}

export function normalizeAddress(address: unknown): string {
  if (typeof address !== 'string' && typeof address !== 'number') {
    return ''
  }
  const raw = String(address).trim().toLowerCase()
  if (!raw) {
    return ''
  }
  const withoutPrefix = raw.startsWith('0x') ? raw.slice(2) : raw
  if (!/^[0-9a-f]+$/.test(withoutPrefix)) {
    return raw
  }
  return `0x${withoutPrefix.replace(/^0+(?=[0-9a-f])/, '') || '0'}`
}

export function codeFromFunctionRecord(record: Record<string, unknown>): string {
  return String(
    record.decompiled ??
      record.code ??
      record.decompiled_code ??
      record.pseudocode ??
      record.body ??
      ''
  )
}

export function functionRecordsFromPayload(payload: unknown): Array<Record<string, unknown>> {
  if (!payload || typeof payload !== 'object') {
    return []
  }

  const obj = payload as Record<string, unknown>
  const records: Array<Record<string, unknown>> = []
  for (const key of ['functions', 'decompiled_functions', 'items', 'results']) {
    const value = obj[key]
    if (Array.isArray(value)) {
      records.push(
        ...value.filter((item): item is Record<string, unknown> =>
          Boolean(item && typeof item === 'object')
        )
      )
    }
  }

  if (obj.function && typeof obj.function === 'object') {
    records.push(obj.function as Record<string, unknown>)
  }
  if (codeFromFunctionRecord(obj)) {
    records.push(obj)
  }

  return records
}

export function extractDecompiledFunctions(
  database: DatabaseManager,
  sampleId: string
): DecompiledFunc[] {
  const functions: DecompiledFunc[] = []
  const evidence = database.findAnalysisEvidenceBySample(sampleId)
  if (!Array.isArray(evidence)) return functions

  for (const entry of evidence) {
    const family = entry.evidence_family ?? ''
    if (
      family !== 'function_map' &&
      family !== 'decompilation' &&
      family !== 'functions' &&
      family !== 'function_decompile'
    ) {
      continue
    }

    for (const obj of functionRecordsFromPayload(parseJsonLike(entry.result_json))) {
      const code = codeFromFunctionRecord(obj)
      if (!code) {
        continue
      }
      functions.push({
        name: String(obj.name ?? obj.function_name ?? obj.function ?? 'unknown'),
        address: normalizeAddress(obj.address ?? obj.offset ?? obj.addr) || '0x0',
        decompiled_code: code,
      })
    }
  }

  return functions
}
