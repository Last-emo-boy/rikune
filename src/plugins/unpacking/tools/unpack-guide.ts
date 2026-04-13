/**
 * unpack.guide tool implementation
 * Provide intelligent unpacking guidance based on detected protector/packer.
 */

import { z } from 'zod'
import type { ToolDefinition, ToolArgs, WorkerResult } from '../../../types.js'
import type { WorkspaceManager } from '../../../workspace-manager.js'
import type { DatabaseManager } from '../../../database.js'
import { persistStaticAnalysisJsonArtifact } from '../../../artifacts/static-analysis-artifacts.js'

const TOOL_NAME = 'unpack.guide'

export const UnpackGuideInputSchema = z.object({
  sample_id: z.string().describe('Sample identifier (sha256:<hex>)'),
  packer_name: z
    .string()
    .optional()
    .describe('Override packer name (if not auto-detected)'),
})

export type UnpackGuideInput = z.infer<typeof UnpackGuideInputSchema>

export const UnpackGuideOutputSchema = z.object({
  ok: z.boolean(),
  data: z
    .object({
      packer_name: z.string(),
      packer_family: z.string(),
      difficulty: z.enum(['trivial', 'easy', 'moderate', 'hard', 'extreme']),
      automated_support: z.boolean(),
      steps: z.array(
        z.object({
          step: z.number(),
          title: z.string(),
          description: z.string(),
          tools: z.array(z.string()),
        })
      ),
      tips: z.array(z.string()),
      references: z.array(z.string()),
      recommended_next_tools: z.array(z.string()),
    })
    .optional(),
  warnings: z.array(z.string()).optional(),
  errors: z.array(z.string()).optional(),
  metrics: z.object({ elapsed_ms: z.number(), tool: z.string() }).optional(),
})

export const unpackGuideToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Provide step-by-step unpacking guidance for a packed binary. Uses packer detection results to identify ' +
    'the protector and generates tailored instructions, tool recommendations, and references. ' +
    'Covers UPX, Themida, VMProtect, .NET Reactor, ConfuserEx, ASPack, PECompact, and more.',
  inputSchema: UnpackGuideInputSchema,
  outputSchema: UnpackGuideOutputSchema,
}

// --------------------------------------------------------------------------
// Packer knowledge base
// --------------------------------------------------------------------------

interface PackerGuide {
  family: string
  difficulty: 'trivial' | 'easy' | 'moderate' | 'hard' | 'extreme'
  automated: boolean
  steps: Array<{ step: number; title: string; description: string; tools: string[] }>
  tips: string[]
  references: string[]
}

const PACKER_GUIDES: Record<string, PackerGuide> = {
  upx: {
    family: 'UPX',
    difficulty: 'trivial',
    automated: true,
    steps: [
      { step: 1, title: 'Run UPX decompress', description: 'Execute `upx -d <file>` to decompress the binary in-place.', tools: ['upx.inspect'] },
      { step: 2, title: 'Verify unpacked binary', description: 'Run packer.detect again to confirm the binary is no longer packed.', tools: ['packer.detect'] },
      { step: 3, title: 'Analyze unpacked sample', description: 'Proceed with full static/dynamic analysis on the unpacked binary.', tools: ['workflow.analyze.start'] },
    ],
    tips: [
      'UPX is fully reversible unless the binary has been modified post-pack (e.g., section name changes, header corruption).',
      'If `upx -d` fails, try manually fixing the section headers or use unpack.auto with force_backend=upx_cli.',
      'Some malware modifies UPX headers to break automatic decompression — check section names for UPX0/UPX1.',
    ],
    references: ['https://github.com/upx/upx', 'https://upx.github.io/'],
  },
  themida: {
    family: 'Themida / WinLicense',
    difficulty: 'extreme',
    automated: false,
    steps: [
      { step: 1, title: 'Identify Themida version', description: 'Check the Themida version from PE overlay or specific markers. Older versions (< 2.x) have known OEP finding techniques.', tools: ['pe.fingerprint', 'strings.extract'] },
      { step: 2, title: 'Bypass anti-debug', description: 'Use Frida or x64dbg anti-debug plugins to bypass Themida\'s anti-debug checks (NtQueryInformationProcess, timing checks, hardware breakpoint detection).', tools: ['frida.script.generate', 'dynamic.trace'] },
      { step: 3, title: 'Find OEP via hardware breakpoints', description: 'Set hardware breakpoints on the stack to catch the final jump to OEP. Themida typically uses VirtualAlloc for unpacking code.', tools: ['dynamic.trace'] },
      { step: 4, title: 'Dump and fix IAT', description: 'Once at OEP, dump the process memory and fix the Import Address Table using Scylla or ImpRec.', tools: ['unpack.auto'] },
      { step: 5, title: 'Validate unpacked binary', description: 'Run packer.detect and pe.imports.extract to verify the unpacked binary is functional.', tools: ['packer.detect', 'pe.imports.extract'] },
    ],
    tips: [
      'Themida uses VM-based protection — full deobfuscation of virtualized code is often impractical.',
      'Focus on dumping and fixing IAT rather than devirtualizing all code.',
      'Newer Themida versions detect VMs — may need to run on bare metal.',
      'Consider using Speakeasy emulation as an alternative to live debugging.',
    ],
    references: ['https://www.oreans.com/Themida.php'],
  },
  vmprotect: {
    family: 'VMProtect',
    difficulty: 'extreme',
    automated: false,
    steps: [
      { step: 1, title: 'Identify VMProtect version', description: 'Check for .vmp sections and VMProtect-specific signatures. Version affects deobfuscation approaches.', tools: ['pe.fingerprint', 'pe.sections'] },
      { step: 2, title: 'Bypass anti-debug', description: 'Patch or hook anti-debug APIs. VMProtect checks IsDebuggerPresent, NtQueryInformationProcess, and uses timing-based checks.', tools: ['frida.script.generate'] },
      { step: 3, title: 'Trace API calls', description: 'Use API monitoring to understand behavior without full unpacking. VMProtect VM bytecode is extremely difficult to devirtualize.', tools: ['dynamic.trace', 'frida.script.generate'] },
      { step: 4, title: 'Dump at OEP (if possible)', description: 'For partially protected binaries, find and dump at Original Entry Point. Fully VM-protected binaries cannot be traditionally unpacked.', tools: ['unpack.auto'] },
    ],
    tips: [
      'VMProtect uses custom VM bytecode — devirtualization requires specialized tools like VMProtect devirtualizers (if available for the version).',
      'For analysis, focus on behavioral analysis (API calls, network traffic) rather than code-level analysis.',
      'Check if only specific functions are VM-protected while the rest is just packed.',
    ],
    references: ['https://vmpsoft.com/'],
  },
  dotnet_reactor: {
    family: '.NET Reactor',
    difficulty: 'moderate',
    automated: false,
    steps: [
      { step: 1, title: 'Identify .NET Reactor features', description: 'Determine which protection features are used: native stub, string encryption, control flow obfuscation, anti-tampering.', tools: ['obfuscation.detect', 'pe.fingerprint'] },
      { step: 2, title: 'Remove native stub', description: 'Use de4dot or similar .NET deobfuscator to remove the native unpacking stub and restore the managed assembly.', tools: ['unpack.auto'] },
      { step: 3, title: 'Deobfuscate strings', description: 'Run string decryption using de4dot\'s built-in .NET Reactor deobfuscation module.', tools: ['strings.extract'] },
      { step: 4, title: 'Fix control flow', description: 'Use de4dot to remove control flow obfuscation and restore readable IL code.', tools: ['obfuscation.detect'] },
      { step: 5, title: 'Decompile cleaned assembly', description: 'Use ILSpy or dnSpy to decompile the cleaned assembly.', tools: ['dotnet.analyze'] },
    ],
    tips: [
      'de4dot (https://github.com/de4dot/de4dot) handles most .NET Reactor versions well.',
      'If de4dot fails, try running the assembly and dumping from memory using MegaDumper or ExtremeDumper.',
      'Check for anti-tamper protection that may crash the process when debugging.',
    ],
    references: ['https://github.com/de4dot/de4dot', 'https://www.eziriz.com/dotnet_reactor.htm'],
  },
  confuserex: {
    family: 'ConfuserEx',
    difficulty: 'moderate',
    automated: false,
    steps: [
      { step: 1, title: 'Identify ConfuserEx version', description: 'Check for ConfuserEx markers in metadata or resources. Look for "ConfuserEx" string or packer stub patterns.', tools: ['obfuscation.detect', 'strings.extract'] },
      { step: 2, title: 'Run de4dot', description: 'Use de4dot with ConfuserEx deobfuscation mode to remove obfuscation layers.', tools: ['unpack.auto'] },
      { step: 3, title: 'Decrypt strings', description: 'ConfuserEx often uses delegate-based string encryption. de4dot can handle standard variants.', tools: ['strings.extract'] },
      { step: 4, title: 'Restore control flow', description: 'Remove switch-based control flow flattening and restore original method bodies.', tools: ['obfuscation.detect'] },
      { step: 5, title: 'Decompile', description: 'Use ILSpy or dnSpy on the cleaned assembly.', tools: ['dotnet.analyze'] },
    ],
    tips: [
      'Custom ConfuserEx forks (e.g., ConfuserEx2, ModifiedConfuserEx) may not be handled by de4dot.',
      'For custom forks, try manual analysis of the string decryption delegates.',
      'Resource encryption is common — check for encrypted resources that de4dot may miss.',
    ],
    references: ['https://github.com/de4dot/de4dot', 'https://github.com/yck1509/ConfuserEx'],
  },
  aspack: {
    family: 'ASPack',
    difficulty: 'easy',
    automated: true,
    steps: [
      { step: 1, title: 'Find OEP', description: 'ASPack jumps to OEP via a RETN instruction. Set breakpoint on the stack push before RETN.', tools: ['dynamic.trace'] },
      { step: 2, title: 'Try automated unpack', description: 'Use unpack.auto which may handle ASPack via Speakeasy or Qiling OEP dumping.', tools: ['unpack.auto'] },
      { step: 3, title: 'Dump and fix', description: 'If automated fails, manually dump at OEP and fix IAT with Scylla.', tools: ['pe.fingerprint'] },
    ],
    tips: [
      'ASPack is a relatively simple packer — most versions can be unpacked with standard OEP finding techniques.',
      'The unpacking stub is short and uses pushad/popad — hardware BP on ESP after pushad works well.',
    ],
    references: ['http://www.aspack.com/'],
  },
  pecompact: {
    family: 'PECompact',
    difficulty: 'easy',
    automated: true,
    steps: [
      { step: 1, title: 'Automated unpack attempt', description: 'Try unpack.auto first — PECompact is well-supported by emulation-based unpackers.', tools: ['unpack.auto'] },
      { step: 2, title: 'Manual OEP finding', description: 'If automated fails, PECompact uses a loader DLL injected into the process. Break on the final jump to code section.', tools: ['dynamic.trace'] },
      { step: 3, title: 'Fix sections', description: 'After dumping, fix section characteristics and IAT.', tools: ['pe.fingerprint', 'pe.sections'] },
    ],
    tips: [
      'PECompact modifies section names — section may be named .pec or similar.',
      'Some versions use anti-dump techniques — may need to use process hollowing approach.',
    ],
    references: [],
  },
}

const DEFAULT_GUIDE: PackerGuide = {
  family: 'Unknown',
  difficulty: 'hard',
  automated: false,
  steps: [
    { step: 1, title: 'Identify the packer', description: 'Run packer.detect and entropy.analyze to gather more information about the protection.', tools: ['packer.detect', 'entropy.analyze'] },
    { step: 2, title: 'Check entropy distribution', description: 'High entropy sections suggest compression/encryption. Use entropy analysis to identify which sections are protected.', tools: ['entropy.analyze'] },
    { step: 3, title: 'Try automated unpack', description: 'Attempt unpack.auto with different backends (UPX CLI, Speakeasy dump, Qiling OEP dump).', tools: ['unpack.auto'] },
    { step: 4, title: 'Dynamic analysis', description: 'If automated unpacking fails, use dynamic analysis to trace execution and find the OEP.', tools: ['dynamic.trace', 'frida.script.generate'] },
    { step: 5, title: 'Memory dump', description: 'Dump the process memory after the unpacking stub has run. Fix IAT with Scylla or ImpRec.', tools: ['unpack.auto'] },
  ],
  tips: [
    'Start with entropy analysis to understand the packing structure.',
    'Look for common OEP patterns: pushad/popad sequences, tail jumps to .text section.',
    'If the packer is custom, focus on behavioral analysis rather than full unpacking.',
  ],
  references: [],
}

function normalizePackerName(name: string): string {
  return name.toLowerCase().replace(/[^a-z0-9]/g, '')
}

function lookupGuide(packerName: string): { key: string; guide: PackerGuide } {
  const normalized = normalizePackerName(packerName)
  for (const [key, guide] of Object.entries(PACKER_GUIDES)) {
    if (normalized.includes(key) || normalizePackerName(guide.family).includes(normalized)) {
      return { key, guide }
    }
  }
  return { key: 'unknown', guide: { ...DEFAULT_GUIDE, family: packerName || 'Unknown' } }
}

function extractPackerName(database: DatabaseManager, sampleId: string): string | null {
  try {
    const evidenceRows = database.findAnalysisEvidenceBySample(sampleId, 'packer_detect')
    if (evidenceRows.length > 0) {
      const latest = evidenceRows[0]
      const result =
        typeof latest.result_json === 'string' ? JSON.parse(latest.result_json) : latest.result_json
      if (result?.detections && Array.isArray(result.detections) && result.detections.length > 0) {
        return result.detections[0].name || null
      }
    }
  } catch { /* ignore */ }

  try {
    const runs = database.findAnalysisRunsBySample(sampleId)
    if (runs.length > 0) {
      const stage = database.findAnalysisRunStage(runs[0].id, 'fast_profile')
      if (stage?.result_json) {
        const result = JSON.parse(stage.result_json)
        const detections = result?.raw_results?.packer?.detections
        if (Array.isArray(detections) && detections.length > 0) {
          return detections[0].name || null
        }
      }
    }
  } catch { /* ignore */ }

  return null
}

export function createUnpackGuideHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager
) {
  return async (args: ToolArgs): Promise<WorkerResult> => {
    const input = UnpackGuideInputSchema.parse(args)
    const startTime = Date.now()

    try {
      const sample = database.findSample(input.sample_id)
      if (!sample) {
        return { ok: false, errors: [`Sample not found: ${input.sample_id}`] }
      }

      const packerName = input.packer_name || extractPackerName(database, input.sample_id)
      if (!packerName) {
        return {
          ok: false,
          errors: ['No packer detected for this sample. Run packer.detect first or specify packer_name manually.'],
          metrics: { elapsed_ms: Date.now() - startTime, tool: TOOL_NAME },
        }
      }

      const { guide } = lookupGuide(packerName)

      const data = {
        packer_name: packerName,
        packer_family: guide.family,
        difficulty: guide.difficulty,
        automated_support: guide.automated,
        steps: guide.steps,
        tips: guide.tips,
        references: guide.references,
        recommended_next_tools: guide.automated
          ? ['unpack.auto']
          : ['dynamic.trace', 'frida.script.generate', 'obfuscation.detect'],
      }

      try {
        await persistStaticAnalysisJsonArtifact(
          workspaceManager, database, input.sample_id, 'unpack_guide', 'unpack_guide', { tool: TOOL_NAME, data }
        )
      } catch { /* best effort */ }

      return {
        ok: true,
        data,
        metrics: { elapsed_ms: Date.now() - startTime, tool: TOOL_NAME },
      }
    } catch (error) {
      return {
        ok: false,
        errors: [(error as Error).message],
        metrics: { elapsed_ms: Date.now() - startTime, tool: TOOL_NAME },
      }
    }
  }
}
