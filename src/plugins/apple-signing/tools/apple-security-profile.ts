import { z } from 'zod'
import { type ToolDefinition, type WorkerResult } from '../../sdk.js'

const TOOL_NAME = 'apple.security.profile'

export const AppleSecurityProfileInputSchema = z
  .object({
    sample_id: z.string().optional(),
    container_inventory: z.any().optional(),
    signing_inventory: z.any().optional(),
    macho_structure: z.any().optional(),
    static_findings: z.array(z.string()).optional().default([]),
  })
  .passthrough()

export const AppleSecurityProfileOutputSchema = z.object({
  ok: z.boolean(),
  data: z.record(z.any()).optional(),
  errors: z.array(z.string()).optional(),
  metrics: z.object({ elapsed_ms: z.number(), tool: z.string() }).optional(),
})

export const appleSecurityProfileToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Correlate Apple container, signing, entitlement, provisioning, and Mach-O hints into a passive macOS/iOS security profile. It recommends runtime plans without mounting DMG files, installing IPA/PKG payloads, calling codesign, or attaching to devices.',
  inputSchema: AppleSecurityProfileInputSchema,
  outputSchema: AppleSecurityProfileOutputSchema,
  aspects: {
    formats: ['ipa', 'dmg', 'pkg', 'app-bundle', 'macho', 'entitlements', 'mobileprovision'],
    platforms: ['macos', 'ios'],
    execution: ['static', 'correlation'],
    safety: ['passive', 'no_auto_mount', 'no_installer_execution', 'no_live_sample_by_default'],
    capabilities: ['security-profile', 'entitlement-risk', 'runtime-plan', 'workflow-plan'],
    evidence: [
      'manifest',
      'certificates',
      'package-metadata',
      'behavior',
      'workflow',
      'provenance',
    ],
  },
  artifacts: [
    {
      type: 'apple_security_profile',
      description: 'Passive Apple signing, entitlement, provisioning, and runtime-plan profile',
    },
  ],
  evidence: [
    { category: 'manifest', artifactTypes: ['apple_security_profile'] },
    { category: 'certificates', artifactTypes: ['apple_security_profile'] },
    { category: 'package-metadata', artifactTypes: ['apple_security_profile'] },
    { category: 'provenance', artifactTypes: ['apple_security_profile'] },
  ],
  workflowRecipes: [
    {
      id: 'apple.security.runtime-profile',
      title: 'Apple static security and runtime planning profile',
      startsWith: ['apple.container.inventory', 'apple.signing.inspect', 'apple.security.profile'],
      nextTools: ['macho.structure.analyze', 'macos.runtime.plan', 'ios.runtime.plan'],
      requiredArtifacts: [
        'apple_container_inventory',
        'apple_signing_inventory',
        'macho_structure',
      ],
      producesArtifacts: ['apple_security_profile'],
      evidence: ['manifest', 'certificates', 'package-metadata', 'workflow', 'provenance'],
      safety: ['passive', 'no_auto_mount', 'no_installer_execution', 'no_live_sample_by_default'],
    },
  ],
}

function stringify(value: unknown): string {
  if (typeof value === 'string') return value
  if (Array.isArray(value)) return value.map(stringify).join('\n')
  if (value && typeof value === 'object') return JSON.stringify(value)
  return ''
}

function uniqueMatches(text: string, pattern: RegExp): string[] {
  return Array.from(new Set(Array.from(text.matchAll(pattern)).map((match) => match[0]))).sort()
}

function riskForEntitlement(entitlement: string): {
  entitlement: string
  severity: string
  reason: string
} {
  if (/get-task-allow/.test(entitlement)) {
    return {
      entitlement,
      severity: 'high',
      reason: 'Debug entitlement can permit debugger attach.',
    }
  }
  if (/keychain-access-groups/.test(entitlement)) {
    return { entitlement, severity: 'medium', reason: 'Keychain access scope should be reviewed.' }
  }
  if (/network|aps-environment/.test(entitlement)) {
    return {
      entitlement,
      severity: 'medium',
      reason: 'Network or push capability affects runtime plan scope.',
    }
  }
  if (/com\.apple\.security\.app-sandbox/.test(entitlement)) {
    return {
      entitlement,
      severity: 'info',
      reason: 'Sandbox entitlement constrains runtime behavior.',
    }
  }
  return {
    entitlement,
    severity: 'info',
    reason: 'Entitlement should be recorded as runtime context.',
  }
}

export function buildAppleSecurityProfile(rawInput: unknown) {
  const input = AppleSecurityProfileInputSchema.parse(rawInput)
  const text = [
    stringify(input.container_inventory),
    stringify(input.signing_inventory),
    stringify(input.macho_structure),
    input.static_findings.join('\n'),
  ].join('\n')
  const entitlements = uniqueMatches(
    text,
    /(?:application-identifier|com\.apple\.developer\.[A-Za-z0-9_.-]+|keychain-access-groups|get-task-allow|aps-environment|com\.apple\.security\.[A-Za-z0-9_.-]+)/g
  )
  const provisioning = uniqueMatches(text, /[A-Za-z0-9_./ -]+\.mobileprovision/g)
  const plist = uniqueMatches(text, /[A-Za-z0-9_./ -]+Info\.plist/g)
  const signingBlobHints = uniqueMatches(
    text,
    /(?:LC_CODE_SIGNATURE|_CodeSignature|CodeResources)/g
  )
  const machoCandidates = uniqueMatches(
    text,
    /[A-Za-z0-9_./ -]+\.(?:dylib|framework|appex|xpc|dsym)/g
  )
  const entitlementRisks = entitlements.map(riskForEntitlement)
  const platform = /Payload\/|mobileprovision|ios|iphone/i.test(text) ? 'ios' : 'macos'

  return {
    result_mode: 'apple_security_profile',
    sample_id: input.sample_id ?? null,
    platform_hint: platform,
    signing_summary: {
      entitlement_count: entitlements.length,
      provisioning_count: provisioning.length,
      plist_count: plist.length,
      signing_blob_count: signingBlobHints.length,
      nested_macho_count: machoCandidates.length,
    },
    entitlement_risks: entitlementRisks,
    runtime_constraints: {
      debugger_attach_sensitive: entitlementRisks.some(
        (risk) => risk.entitlement === 'get-task-allow'
      ),
      device_or_simulator_opt_in_required: platform === 'ios',
      macos_host_required: platform === 'macos',
      no_online_certificate_verification: true,
    },
    graph: {
      nodes: [
        ...entitlements.map((item) => ({
          id: `entitlement:${item}`,
          type: 'entitlement',
          label: item,
        })),
        ...provisioning.map((item) => ({
          id: `provisioning:${item}`,
          type: 'provisioning',
          label: item,
        })),
        ...machoCandidates.map((item) => ({ id: `macho:${item}`, type: 'macho', label: item })),
      ],
      edges: entitlementRisks.map((risk) => ({
        source: `entitlement:${risk.entitlement}`,
        target: `${platform}.runtime.plan`,
        relation: 'constrains_runtime_plan',
        severity: risk.severity,
      })),
    },
    recommended_next_tools: [
      'apple.container.inventory',
      'apple.signing.inspect',
      'macho.structure.analyze',
      platform === 'ios' ? 'ios.runtime.plan' : 'macos.runtime.plan',
    ],
    safety_notes: [
      'No DMG mount, PKG install, IPA install, codesign invocation, keychain access, network certificate lookup, or device attach is performed.',
    ],
  }
}

export function createAppleSecurityProfileHandler() {
  return async (args: unknown): Promise<WorkerResult> => ({
    ok: true,
    data: buildAppleSecurityProfile(args),
    metrics: { elapsed_ms: 0, tool: TOOL_NAME },
  })
}
