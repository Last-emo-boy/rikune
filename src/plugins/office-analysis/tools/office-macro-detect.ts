/**
 * office.macro.detect — Detect and classify malicious macros using mraptor.
 */

import { z } from 'zod'
import type { WorkerResult, ToolDefinition, ToolArgs } from '../../../types.js'
import type { WorkspaceManager } from '../../../workspace-manager.js'
import type { DatabaseManager } from '../../../database.js'
import {
  SharedMetricsSchema,
  ensureSampleExists, normalizeError, runPythonJson,
  buildMetrics, resolveSampleFile, resolvePythonModuleBackend,
  buildStaticSetupRequired,
} from '../../docker-shared.js'

const TOOL_NAME = 'office.macro.detect'

export const officeMacroDetectInputSchema = z.object({
  sample_id: z.string().describe('Target Office document sample identifier.'),
  timeout_sec: z.number().int().min(5).max(60).default(15).describe('Detection timeout.'),
})

export const officeMacroDetectOutputSchema = z.object({
  ok: z.boolean(),
  data: z.object({
    sample_id: z.string().optional(),
    has_macros: z.boolean().optional(),
    is_suspicious: z.boolean().optional(),
    flags: z.object({
      auto_exec: z.boolean().optional(),
      suspicious: z.boolean().optional(),
      ioc: z.boolean().optional(),
      hex_strings: z.boolean().optional(),
      base64_strings: z.boolean().optional(),
      dridex_strings: z.boolean().optional(),
      vba_stomping: z.boolean().optional(),
    }).optional(),
    risk_level: z.enum(['safe', 'low', 'medium', 'high']).optional(),
    summary: z.string(),
    recommended_next_tools: z.array(z.string()),
    next_actions: z.array(z.string()),
  }).optional(),
  errors: z.array(z.string()).optional(),
  metrics: SharedMetricsSchema.optional(),
})

export const officeMacroDetectToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Detect and classify malicious macros in Office documents. Returns risk level and specific threat indicators.',
  inputSchema: officeMacroDetectInputSchema,
  outputSchema: officeMacroDetectOutputSchema,
}

const MACRO_DETECT_SCRIPT = `
import json, sys
payload = json.loads(sys.stdin.read())
file_path = payload["sample_path"]

from oletools.olevba import VBA_Parser

vba_parser = VBA_Parser(file_path)
has_macros = vba_parser.detect_vba_macros()

flags = {
    "auto_exec": False,
    "suspicious": False,
    "ioc": False,
    "hex_strings": False,
    "base64_strings": False,
    "dridex_strings": False,
    "vba_stomping": False,
}

if has_macros:
    for kw_type, keyword, description in vba_parser.analyze_macros():
        if kw_type == "AutoExec":
            flags["auto_exec"] = True
        elif kw_type == "Suspicious":
            flags["suspicious"] = True
        elif kw_type == "IOC":
            flags["ioc"] = True
        elif kw_type == "Hex String":
            flags["hex_strings"] = True
        elif kw_type == "Base64 String":
            flags["base64_strings"] = True
        elif kw_type == "Dridex String":
            flags["dridex_strings"] = True
        elif kw_type == "VBA Stomping":
            flags["vba_stomping"] = True

vba_parser.close()

risk_count = sum(1 for v in flags.values() if v)
if risk_count == 0:
    risk = "safe" if not has_macros else "low"
elif risk_count <= 2:
    risk = "medium"
else:
    risk = "high"

print(json.dumps({
    "has_macros": has_macros,
    "is_suspicious": flags["suspicious"] or flags["auto_exec"],
    "flags": flags,
    "risk_level": risk,
}, ensure_ascii=False))
`.trim()

export function createOfficeMacroDetectHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
) {
  return async (args: ToolArgs): Promise<WorkerResult> => {
    const startTime = Date.now()
    try {
      const input = officeMacroDetectInputSchema.parse(args)
      ensureSampleExists(database, input.sample_id)
      const samplePath = await resolveSampleFile(workspaceManager, database, input.sample_id)
      const backend = resolvePythonModuleBackend({ envPythonPath: process.env.OLETOOLS_PYTHON, moduleNames: ['oletools'], distributionNames: ['oletools'] })
      if (!backend?.available || !backend?.path) {
        return buildStaticSetupRequired(backend || { name: 'oletools', available: false, error: 'oletools Python module not available' } as any, startTime, TOOL_NAME)
      }

      const result = await runPythonJson(backend.path, MACRO_DETECT_SCRIPT, { sample_path: samplePath }, input.timeout_sec * 1000)

      const risk = result.parsed?.risk_level || 'safe'
      const hasMacros = result.parsed?.has_macros || false

      return {
        ok: true,
        data: {
          sample_id: input.sample_id,
          has_macros: hasMacros,
          is_suspicious: result.parsed?.is_suspicious || false,
          flags: result.parsed?.flags,
          risk_level: risk,
          summary: hasMacros ? `Macros detected — risk: ${risk.toUpperCase()}. ${result.parsed?.is_suspicious ? 'SUSPICIOUS indicators found.' : 'No suspicious patterns.'}` : 'No macros detected.',
          recommended_next_tools: hasMacros ? ['office.vba.extract', 'yara.scan', 'sandbox.execute'] : ['pe.structure.analyze'],
          next_actions: hasMacros
            ? ['Extract macro source with office.vba.extract for manual review.', 'Scan with YARA rules for known malware patterns.']
            : ['Document appears safe from macro-based threats.'],
        },
        metrics: buildMetrics(startTime, TOOL_NAME),
      }
    } catch (error) {
      return { ok: false, errors: [normalizeError(error)], metrics: buildMetrics(startTime, TOOL_NAME) }
    }
  }
}
