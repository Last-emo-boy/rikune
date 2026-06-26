/**
 * windows.interface.surface.inventory - passive Windows interface inventory.
 *
 * This tool reads bounded bytes and summarizes Windows userland interface
 * evidence: COM/DCOM CLSID/IID strings, RPC interface UUIDs and endpoints,
 * ALPC/named-pipe IPC, ETW provider hints, WMI namespaces/classes, service
 * control references, and static workflow handoff. It never executes the
 * sample, activates COM, calls RPC, connects to IPC endpoints, queries WMI,
 * starts services, registers ETW providers, invokes external tools, uses the
 * network, or mutates samples.
 */

import fs from 'fs/promises'
import path from 'path'
import { z } from 'zod'
import type { ArtifactRef, PluginToolDeps, ToolDefinition, WorkerResult } from '../../sdk.js'

const TOOL_NAME = 'windows.interface.surface.inventory'
export const WINDOWS_INTERFACE_SURFACE_ARTIFACT_TYPE = 'windows_interface_surface_inventory'

const DEFAULT_MAX_READ_BYTES = 8 * 1024 * 1024
const MAX_PREVIEW_BYTES = 32 * 1024 * 1024
const MAX_STRINGS = 12000
const MAX_STRING_EVIDENCE = 520
const MAX_GUID_EVIDENCE = 320

const WINDOWS_INTERFACE_EVIDENCE = [
  'structure',
  'strings',
  'imports',
  'registry',
  'ipc',
  'interfaces',
  'guid',
  'com',
  'rpc',
  'etw',
  'wmi',
  'services',
  'risk',
  'workflow',
  'provenance',
]

const WINDOWS_INTERFACE_SAFETY = [
  'passive',
  'no_execute',
  'no_com_activation',
  'no_rpc_call',
  'no_alpc_connect',
  'no_named_pipe_connect',
  'no_wmi_query',
  'no_service_start',
  'no_etw_registration',
  'no_debugger',
  'no_external_tool',
  'no_network_by_default',
  'no_mutation',
]

const WINDOWS_INTERFACE_FOLLOW_UP_TOOLS = [
  'artifact.read',
  'metadata.extract',
  'strings.extract',
  'pe.imports.extract',
  'pe.structure.analyze',
  'static.resource.graph',
  'pe.security.profile',
  'windows.debug.metadata.inspect',
  'code.xrefs.analyze',
  'vuln.pattern.scan',
  'host.correlate',
  'analysis.evidence.graph',
  'report.generate',
  'workflow.search',
]

const WINDOWS_INTERFACE_RUNTIME_HANDOFF_TOOLS = [
  'windows.runtime.plan',
  'debug.session.plan',
  'frida.script.generate',
]

type Confidence = 'low' | 'medium' | 'high'
type StringEncoding = 'ascii' | 'utf16le'
type InterfaceFamily =
  | 'com'
  | 'rpc'
  | 'alpc'
  | 'named-pipe'
  | 'etw'
  | 'wmi'
  | 'service'
  | 'winrt'
  | 'registry'
  | 'security'

interface BinaryString {
  value: string
  offset: number
  encoding: StringEncoding
}

interface StringRule {
  pattern: RegExp
  id: string
  kind: string
  family: InterfaceFamily
  confidence: Confidence
  flags?: string[]
}

interface StringEvidence {
  id: string
  kind: string
  family: InterfaceFamily
  value: string
  offset: number
  encoding: StringEncoding
  confidence: Confidence
  flags: string[]
}

interface GuidEvidence {
  value: string
  normalized: string
  offset: number
  encoding: StringEncoding
  context: string[]
  families: InterfaceFamily[]
  confidence: Confidence
  flags: string[]
}

interface BuildOptions {
  filename?: string
  sampleId?: string
  maxReadBytes?: number
  size?: number
}

export const windowsInterfaceSurfaceInventoryAspects = {
  formats: [
    'windows-interface',
    'com',
    'dcom',
    'ole',
    'rpc',
    'alpc',
    'etw',
    'wmi',
    'named-pipe',
    'service-control',
    'winrt',
    'typelib',
    'tlb',
    'idl',
    'winmd',
    'pe',
  ],
  platforms: ['windows'],
  architectures: ['x86', 'x64', 'arm64'],
  execution: ['static', 'triage', 'correlation'],
  safety: WINDOWS_INTERFACE_SAFETY,
  capabilities: [
    'windows-interface-surface-inventory',
    'com-clsid-iid-inventory',
    'rpc-interface-endpoint-hints',
    'alpc-named-pipe-ipc-hints',
    'etw-provider-hints',
    'wmi-namespace-class-hints',
    'service-control-surface-hints',
    'interface-risk-routing',
  ],
  evidence: WINDOWS_INTERFACE_EVIDENCE,
  route_terms: [
    'windows interface',
    'com',
    'dcom',
    'clsid',
    'iid',
    'rpc uuid',
    'rpc endpoint',
    'alpc',
    'named pipe',
    'etw provider',
    'wmi',
    'service control',
    'winrt',
  ],
  search: [
    'Windows COM RPC ALPC ETW WMI interface inventory',
    'CLSID IID RPC UUID named pipe static surface',
    'Windows userland IPC and interface boundary triage',
  ],
}

const PolicySchema = z.object({
  passive: z.literal(true),
  no_execute: z.literal(true),
  no_com_activation: z.literal(true),
  no_rpc_call: z.literal(true),
  no_alpc_connect: z.literal(true),
  no_named_pipe_connect: z.literal(true),
  no_wmi_query: z.literal(true),
  no_service_start: z.literal(true),
  no_etw_registration: z.literal(true),
  no_debugger: z.literal(true),
  no_external_tool: z.literal(true),
  no_network: z.literal(true),
  no_mutation: z.literal(true),
})

const InventorySchema = z.object({
  sample_id: z.string().optional(),
  filename: z.string().optional(),
  format: z.string(),
  platforms: z.array(z.string()),
  detected_by: z.array(z.string()),
  confidence: z.enum(['low', 'medium', 'high']),
  size: z.number().optional(),
  preview_size: z.number(),
  container: z.record(z.any()),
  guid_evidence: z.array(z.record(z.any())),
  string_evidence: z.array(z.record(z.any())),
  com_surface: z.record(z.any()),
  rpc_surface: z.record(z.any()),
  ipc_surface: z.record(z.any()),
  etw_surface: z.record(z.any()),
  wmi_surface: z.record(z.any()),
  service_surface: z.record(z.any()),
  risk_flags: z.array(z.record(z.any())),
  risk_summary: z.record(z.any()),
  policy: PolicySchema,
  summary: z.string(),
  recommended_next_tools: z.array(z.string()),
  next_actions: z.array(z.string()),
  evidence_summary: z.record(z.any()),
  workflow_handoff: z.record(z.any()),
  quality_gates: z.record(z.any()),
})

export const WindowsInterfaceSurfaceInventoryInputSchema = z.object({
  sample_id: z.string().describe('Target sample identifier.'),
  max_read_bytes: z
    .number()
    .int()
    .min(1024)
    .max(MAX_PREVIEW_BYTES)
    .default(DEFAULT_MAX_READ_BYTES)
    .describe('Maximum bytes to read for passive Windows interface inventory.'),
  persist_artifact: z
    .boolean()
    .default(true)
    .describe('Persist Windows interface inventory JSON as artifact.'),
  session_tag: z.string().optional().describe('Optional artifact session tag.'),
})

export const WindowsInterfaceSurfaceInventoryOutputSchema = z.object({
  ok: z.boolean(),
  data: InventorySchema.optional(),
  artifacts: z.array(z.any()).optional(),
  errors: z.array(z.string()).optional(),
  metrics: z.object({ elapsed_ms: z.number(), tool: z.string() }).optional(),
})

export const windowsInterfaceSurfaceInventoryToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Passively inventory Windows userland interface evidence including COM/DCOM CLSID/IID strings, RPC UUID/endpoints, ALPC and named-pipe IPC, ETW provider hints, WMI namespaces/classes, service-control references, and risk handoff without executing the sample or contacting any interface.',
  inputSchema: WindowsInterfaceSurfaceInventoryInputSchema,
  outputSchema: WindowsInterfaceSurfaceInventoryOutputSchema,
  aspects: windowsInterfaceSurfaceInventoryAspects,
  artifacts: [
    {
      type: WINDOWS_INTERFACE_SURFACE_ARTIFACT_TYPE,
      description: 'Passive Windows userland interface surface inventory',
      mime: 'application/json',
      mimeTypes: ['application/json'],
    },
  ],
  evidence: WINDOWS_INTERFACE_EVIDENCE.map((category) => ({
    category,
    artifactTypes: [WINDOWS_INTERFACE_SURFACE_ARTIFACT_TYPE],
  })),
  workflowRecipes: [
    {
      id: 'windows.interface-surface-static-inventory',
      title: 'Passive Windows interface surface inventory',
      description:
        'Inventory static COM/RPC/ALPC/named-pipe/ETW/WMI/service evidence before routing to imports, resources, xrefs, host correlation, evidence graph, reporting, or explicit Windows runtime planning.',
      startsWith: [TOOL_NAME],
      nextTools: WINDOWS_INTERFACE_FOLLOW_UP_TOOLS,
      requiredArtifacts: ['sample'],
      producesArtifacts: [WINDOWS_INTERFACE_SURFACE_ARTIFACT_TYPE],
      evidence: WINDOWS_INTERFACE_EVIDENCE,
      safety: WINDOWS_INTERFACE_SAFETY,
    },
  ],
}

export type WindowsInterfaceSurfaceInventory = z.infer<typeof InventorySchema>

const STRING_RULES: StringRule[] = [
  {
    pattern: /\b(?:CLSID|IID|LIBID|APPID|ProgID|InprocServer32|LocalServer32)\b/i,
    id: 'com.registry-or-type-library',
    kind: 'com-registry-metadata',
    family: 'com',
    confidence: 'medium',
    flags: ['com-metadata'],
  },
  {
    pattern: /\b(?:CoCreateInstance|CoGetClassObject|CoInitializeEx|CoInitializeSecurity)\b/,
    id: 'com.activation-api',
    kind: 'com-activation-api',
    family: 'com',
    confidence: 'high',
    flags: ['activation-surface'],
  },
  {
    pattern: /\b(?:DllRegisterServer|DllUnregisterServer|DllGetClassObject|RegisterTypeLib)\b/,
    id: 'com-server-export',
    kind: 'com-server-export',
    family: 'com',
    confidence: 'high',
    flags: ['registration-surface'],
  },
  {
    pattern: /\b(?:DCOM|CoCreateInstanceEx|COSERVERINFO|CoSetProxyBlanket)\b/i,
    id: 'com.dcom-remote',
    kind: 'dcom-or-proxy',
    family: 'com',
    confidence: 'medium',
    flags: ['remote-interface-risk'],
  },
  {
    pattern:
      /\b(?:RpcServerRegisterIf(?:Ex|2)?|RpcServerUseProtseq|RpcBinding|NdrClientCall|MIDL_user_allocate)\b/,
    id: 'rpc.runtime-api',
    kind: 'rpc-runtime-api',
    family: 'rpc',
    confidence: 'high',
    flags: ['rpc-interface'],
  },
  {
    pattern: /\b(?:ncalrpc|ncacn_np|ncacn_ip_tcp|ncacn_http|endpoint mapper|epmapper)\b/i,
    id: 'rpc.protocol-sequence',
    kind: 'rpc-protocol-sequence',
    family: 'rpc',
    confidence: 'high',
    flags: ['rpc-endpoint'],
  },
  {
    pattern: /\\\\\.\\pipe\\[A-Za-z0-9_.\\/\-$]+|\\pipe\\[A-Za-z0-9_.\\/\-$]+/i,
    id: 'ipc.named-pipe-path',
    kind: 'named-pipe-path',
    family: 'named-pipe',
    confidence: 'high',
    flags: ['ipc-endpoint'],
  },
  {
    pattern:
      /\b(?:CreateNamedPipeW?|ConnectNamedPipe|WaitNamedPipeW?|TransactNamedPipe|ImpersonateNamedPipeClient)\b/,
    id: 'ipc.named-pipe-api',
    kind: 'named-pipe-api',
    family: 'named-pipe',
    confidence: 'high',
    flags: ['ipc-api'],
  },
  {
    pattern:
      /\\RPC Control\\[A-Za-z0-9_.\\/\-$]+|\b(?:NtAlpc|ZwAlpc|AlpcConnectPort|AlpcSendWaitReceivePort)\w*\b/i,
    id: 'ipc.alpc-evidence',
    kind: 'alpc-endpoint-or-api',
    family: 'alpc',
    confidence: 'high',
    flags: ['ipc-endpoint'],
  },
  {
    pattern:
      /\b(?:EventRegister|EventWrite|TraceLoggingProvider|TraceLoggingWrite|EtwEventWrite|RegisterTraceGuids)\b/,
    id: 'etw.provider-api',
    kind: 'etw-provider-api',
    family: 'etw',
    confidence: 'high',
    flags: ['telemetry-provider'],
  },
  {
    pattern:
      /\b(?:IWbemServices|IWbemLocator|WMI|WbemScripting|root\\(?:cimv2|subscription|default|securitycenter2))\b/i,
    id: 'wmi.namespace-or-api',
    kind: 'wmi-namespace-api',
    family: 'wmi',
    confidence: 'high',
    flags: ['wmi-interface'],
  },
  {
    pattern:
      /\b(?:__EventFilter|CommandLineEventConsumer|ActiveScriptEventConsumer|Win32_Process|Win32_Service|Win32_ScheduledJob)\b/,
    id: 'wmi-class-or-persistence',
    kind: 'wmi-class',
    family: 'wmi',
    confidence: 'medium',
    flags: ['persistence-risk'],
  },
  {
    pattern:
      /\b(?:OpenSCManagerW?|CreateServiceW?|OpenServiceW?|StartServiceW?|ChangeServiceConfigW?|RegisterServiceCtrlHandlerW?)\b/,
    id: 'service-control.api',
    kind: 'service-control-api',
    family: 'service',
    confidence: 'high',
    flags: ['service-control'],
  },
  {
    pattern:
      /\b(?:HKEY_CLASSES_ROOT|HKCR|Software\\Classes|AppID\\|CLSID\\|Interface\\|TypeLib\\)/i,
    id: 'registry.interface-registration',
    kind: 'registry-interface-registration',
    family: 'registry',
    confidence: 'medium',
    flags: ['registry-registration'],
  },
  {
    pattern:
      /\b(?:Windows\.Foundation|Windows\.ApplicationModel|IInspectable|RoGetActivationFactory|winmd)\b/i,
    id: 'winrt.metadata-or-api',
    kind: 'winrt-metadata-api',
    family: 'winrt',
    confidence: 'medium',
    flags: ['winrt-interface'],
  },
  {
    pattern:
      /\b(?:Impersonate(?:NamedPipeClient|LoggedOnUser)|RpcImpersonateClient|CoImpersonateClient|SeImpersonatePrivilege)\b/,
    id: 'security.impersonation-interface',
    kind: 'impersonation-api',
    family: 'security',
    confidence: 'high',
    flags: ['impersonation-risk'],
  },
]

const GUID_RE = /\{?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}?/g

function clampMaxReadBytes(value: number | undefined): number {
  if (!Number.isFinite(value ?? DEFAULT_MAX_READ_BYTES)) return DEFAULT_MAX_READ_BYTES
  return Math.max(1024, Math.min(MAX_PREVIEW_BYTES, Math.floor(value ?? DEFAULT_MAX_READ_BYTES)))
}

function normalizeGuid(value: string): string {
  return value.replace(/[{}]/g, '').toLowerCase()
}

function uniqueStrings(values: Array<string | null | undefined>): string[] {
  return Array.from(new Set(values.filter((item): item is string => Boolean(item))))
}

function extractAsciiStrings(data: Buffer): BinaryString[] {
  const out: BinaryString[] = []
  let start = -1
  for (let i = 0; i <= data.length; i += 1) {
    const b = i < data.length ? data[i] : 0
    const printable = b >= 0x20 && b <= 0x7e
    if (printable) {
      if (start === -1) start = i
    } else if (start !== -1) {
      if (i - start >= 4) {
        out.push({ value: data.toString('ascii', start, i), offset: start, encoding: 'ascii' })
        if (out.length >= MAX_STRINGS) return out
      }
      start = -1
    }
  }
  return out
}

function extractUtf16Strings(data: Buffer, existingCount: number): BinaryString[] {
  const out: BinaryString[] = []
  let start = -1
  let chars = 0
  for (let i = 0; i + 1 <= data.length; i += 2) {
    const lo = data[i]
    const hi = data[i + 1]
    const printable = hi === 0 && lo >= 0x20 && lo <= 0x7e
    if (printable) {
      if (start === -1) start = i
      chars += 1
    } else if (start !== -1) {
      if (chars >= 4) {
        out.push({ value: data.toString('utf16le', start, i), offset: start, encoding: 'utf16le' })
        if (existingCount + out.length >= MAX_STRINGS) return out
      }
      start = -1
      chars = 0
    }
  }
  return out
}

function extractBinaryStrings(data: Buffer): BinaryString[] {
  const ascii = extractAsciiStrings(data)
  const utf16 = extractUtf16Strings(data, ascii.length)
  return [...ascii, ...utf16].sort((a, b) => a.offset - b.offset).slice(0, MAX_STRINGS)
}

function detectContainer(preview: Buffer, maxReadBytes: number, options: BuildOptions) {
  const filename = (options.filename ?? '').toLowerCase()
  const extension = filename.includes('.') ? filename.slice(filename.lastIndexOf('.') + 1) : ''
  return {
    magic_hex: preview.subarray(0, Math.min(preview.length, 16)).toString('hex'),
    extension,
    bounded_read: true,
    max_read_bytes: maxReadBytes,
    truncated: typeof options.size === 'number' ? options.size > preview.length : false,
    pe: preview.length >= 2 && preview[0] === 0x4d && preview[1] === 0x5a,
    typelib: ['tlb', 'olb', 'idl'].includes(extension),
    winmd: extension === 'winmd',
  }
}

function collectStringEvidence(strings: BinaryString[]): StringEvidence[] {
  const evidence: StringEvidence[] = []
  for (const item of strings) {
    for (const rule of STRING_RULES) {
      rule.pattern.lastIndex = 0
      if (rule.pattern.test(item.value)) {
        evidence.push({
          id: rule.id,
          kind: rule.kind,
          family: rule.family,
          value: item.value,
          offset: item.offset,
          encoding: item.encoding,
          confidence: rule.confidence,
          flags: rule.flags ?? [],
        })
        if (evidence.length >= MAX_STRING_EVIDENCE) return evidence
      }
    }
  }
  return evidence
}

function stringsNearOffset(strings: BinaryString[], offset: number): string[] {
  return strings
    .filter((item) => Math.abs(item.offset - offset) <= 384)
    .map((item) => item.value)
    .slice(0, 10)
}

function inferGuidFamilies(context: string[]): {
  families: InterfaceFamily[]
  confidence: Confidence
  flags: string[]
} {
  const text = context.join(' ').toLowerCase()
  const families = new Set<InterfaceFamily>()
  const flags: string[] = []
  let confidence: Confidence = 'low'

  if (/\b(clsid|iid|interface|typelib|progid|cocreate|dllregisterserver)\b/.test(text)) {
    families.add('com')
    flags.push('com-guid')
    confidence = 'high'
  }
  if (/\b(rpc|midl|uuid|ncalrpc|ncacn_|epmapper|ndr)\b/.test(text)) {
    families.add('rpc')
    flags.push('rpc-interface-uuid')
    confidence = 'high'
  }
  if (/\b(eventregister|tracelogging|etw|provider|manifest)\b/.test(text)) {
    families.add('etw')
    flags.push('etw-provider-guid')
    confidence = confidence === 'high' ? 'high' : 'medium'
  }
  if (/\b(wmi|wbem|root\\|win32_)\b/.test(text)) {
    families.add('wmi')
    flags.push('wmi-context-guid')
    confidence = confidence === 'high' ? 'high' : 'medium'
  }
  if (/\b(windows\.|winrt|iinspectable|winmd)\b/.test(text)) {
    families.add('winrt')
    flags.push('winrt-guid')
    confidence = confidence === 'high' ? 'high' : 'medium'
  }

  return { families: Array.from(families), confidence, flags }
}

function collectGuidEvidence(strings: BinaryString[]): GuidEvidence[] {
  const seen = new Set<string>()
  const evidence: GuidEvidence[] = []
  for (const item of strings) {
    GUID_RE.lastIndex = 0
    let match: RegExpExecArray | null
    while ((match = GUID_RE.exec(item.value)) && evidence.length < MAX_GUID_EVIDENCE) {
      const raw = match[0]
      const normalized = normalizeGuid(raw)
      const key = `${normalized}:${item.offset + match.index}`
      if (seen.has(key)) continue
      seen.add(key)
      const context = stringsNearOffset(strings, item.offset)
      const inferred = inferGuidFamilies([...context, item.value])
      evidence.push({
        value: raw,
        normalized,
        offset: item.offset + match.index * (item.encoding === 'utf16le' ? 2 : 1),
        encoding: item.encoding,
        context,
        families: inferred.families,
        confidence: inferred.confidence,
        flags: inferred.flags,
      })
    }
  }
  return evidence
}

function valuesForFamily(evidence: StringEvidence[], family: InterfaceFamily): string[] {
  return uniqueStrings(evidence.filter((item) => item.family === family).map((item) => item.value))
}

function guidsForFamily(evidence: GuidEvidence[], family: InterfaceFamily): string[] {
  return uniqueStrings(
    evidence.filter((item) => item.families.includes(family)).map((item) => item.normalized)
  )
}

function buildComSurface(strings: StringEvidence[], guids: GuidEvidence[]) {
  const refs = strings.filter((item) => item.family === 'com' || item.family === 'registry')
  return {
    present: refs.length > 0 || guids.some((item) => item.families.includes('com')),
    reference_count: refs.length,
    clsid_iid_candidates: guidsForFamily(guids, 'com').slice(0, 80),
    activation_api_count: refs.filter((item) => item.flags.includes('activation-surface')).length,
    registration_hint: refs.some((item) => item.flags.includes('registration-surface')),
    dcom_hint: refs.some((item) => item.flags.includes('remote-interface-risk')),
    registry_registration_hint: refs.some((item) => item.family === 'registry'),
    references: valuesForFamily(strings, 'com').slice(0, 80),
  }
}

function buildRpcSurface(strings: StringEvidence[], guids: GuidEvidence[]) {
  const refs = strings.filter((item) => item.family === 'rpc')
  const endpoints = refs.filter((item) => item.flags.includes('rpc-endpoint'))
  return {
    present: refs.length > 0 || guids.some((item) => item.families.includes('rpc')),
    reference_count: refs.length,
    interface_uuid_candidates: guidsForFamily(guids, 'rpc').slice(0, 80),
    endpoint_hints: uniqueStrings(endpoints.map((item) => item.value)).slice(0, 80),
    has_remote_protocol_hint: endpoints.some((item) => /ncacn_ip_tcp|ncacn_http/i.test(item.value)),
    references: valuesForFamily(strings, 'rpc').slice(0, 80),
  }
}

function buildIpcSurface(strings: StringEvidence[]) {
  const pipeRefs = strings.filter((item) => item.family === 'named-pipe')
  const alpcRefs = strings.filter((item) => item.family === 'alpc')
  return {
    present: pipeRefs.length > 0 || alpcRefs.length > 0,
    named_pipe_reference_count: pipeRefs.length,
    alpc_reference_count: alpcRefs.length,
    named_pipe_hints: valuesForFamily(strings, 'named-pipe').slice(0, 80),
    alpc_hints: valuesForFamily(strings, 'alpc').slice(0, 80),
    impersonation_hint: strings.some((item) => item.family === 'security'),
  }
}

function buildEtwSurface(strings: StringEvidence[], guids: GuidEvidence[]) {
  const refs = strings.filter((item) => item.family === 'etw')
  return {
    present: refs.length > 0 || guids.some((item) => item.families.includes('etw')),
    reference_count: refs.length,
    provider_guid_candidates: guidsForFamily(guids, 'etw').slice(0, 80),
    references: valuesForFamily(strings, 'etw').slice(0, 80),
  }
}

function buildWmiSurface(strings: StringEvidence[], guids: GuidEvidence[]) {
  const refs = strings.filter((item) => item.family === 'wmi')
  return {
    present: refs.length > 0 || guids.some((item) => item.families.includes('wmi')),
    reference_count: refs.length,
    namespace_or_class_hints: valuesForFamily(strings, 'wmi').slice(0, 80),
    guid_candidates: guidsForFamily(guids, 'wmi').slice(0, 40),
    persistence_hint: refs.some((item) => item.flags.includes('persistence-risk')),
  }
}

function buildServiceSurface(strings: StringEvidence[]) {
  const refs = strings.filter((item) => item.family === 'service')
  return {
    present: refs.length > 0,
    reference_count: refs.length,
    service_control_api_count: refs.filter((item) => item.flags.includes('service-control')).length,
    references: valuesForFamily(strings, 'service').slice(0, 80),
  }
}

function buildRiskFlags(args: {
  com: Record<string, any>
  rpc: Record<string, any>
  ipc: Record<string, any>
  wmi: Record<string, any>
  service: Record<string, any>
  strings: StringEvidence[]
}) {
  const flags: Array<Record<string, any>> = []
  if (args.com.dcom_hint) {
    flags.push({
      id: 'windows.dcom-remote-interface',
      severity: 'medium',
      confidence: 'medium',
      detail: 'COM evidence includes DCOM or proxy blanket hints.',
    })
  }
  if (args.rpc.has_remote_protocol_hint) {
    flags.push({
      id: 'windows.rpc-remote-protocol',
      severity: 'medium',
      confidence: 'medium',
      detail: 'RPC protocol sequence strings include remote protocol hints.',
    })
  }
  if (args.ipc.impersonation_hint) {
    flags.push({
      id: 'windows.ipc-impersonation-surface',
      severity: 'high',
      confidence: 'high',
      detail: 'IPC evidence includes impersonation APIs or privileges.',
    })
  }
  if (args.wmi.persistence_hint) {
    flags.push({
      id: 'windows.wmi-persistence-surface',
      severity: 'high',
      confidence: 'medium',
      detail: 'WMI evidence includes event filter or consumer persistence classes.',
    })
  }
  if (args.service.present) {
    flags.push({
      id: 'windows.service-control-surface',
      severity: 'medium',
      confidence: 'medium',
      detail: 'Service-control API references are present.',
    })
  }
  const families = new Set(args.strings.map((item) => item.family))
  if (families.size >= 4) {
    flags.push({
      id: 'windows.multi-interface-orchestration',
      severity: 'medium',
      confidence: 'medium',
      families: Array.from(families).sort(),
      detail: 'Multiple Windows interface families appear in the same sample preview.',
    })
  }
  return flags
}

function buildRiskSummary(riskFlags: Array<Record<string, any>>) {
  const bySeverity = riskFlags.reduce<Record<string, number>>((acc, item) => {
    const severity = String(item.severity ?? 'unknown')
    acc[severity] = (acc[severity] ?? 0) + 1
    return acc
  }, {})
  return {
    total: riskFlags.length,
    by_severity: bySeverity,
    highest:
      riskFlags.find((item) => item.severity === 'high')?.severity ??
      riskFlags.find((item) => item.severity === 'medium')?.severity ??
      (riskFlags.length > 0 ? 'low' : 'none'),
  }
}

function detectFormat(
  container: Record<string, any>,
  strings: StringEvidence[],
  guids: GuidEvidence[]
): { format: string; detectedBy: string[]; confidence: Confidence } {
  const detectedBy: string[] = []
  const families = new Set<InterfaceFamily>([
    ...strings.map((item) => item.family),
    ...guids.flatMap((item) => item.families),
  ])
  if (container.pe) detectedBy.push('pe-magic')
  if (container.typelib) detectedBy.push('typelib-extension')
  if (container.winmd) detectedBy.push('winmd-extension')
  if (families.size > 0) detectedBy.push('interface-string-or-guid-evidence')

  if (families.has('rpc'))
    return { format: 'windows-rpc-interface-surface', detectedBy, confidence: 'high' }
  if (families.has('com'))
    return { format: 'windows-com-interface-surface', detectedBy, confidence: 'high' }
  if (families.has('named-pipe') || families.has('alpc')) {
    return { format: 'windows-ipc-interface-surface', detectedBy, confidence: 'high' }
  }
  if (families.has('etw'))
    return { format: 'windows-etw-interface-surface', detectedBy, confidence: 'medium' }
  if (families.has('wmi'))
    return { format: 'windows-wmi-interface-surface', detectedBy, confidence: 'medium' }
  if (container.winmd)
    return { format: 'windows-winmd-interface-metadata', detectedBy, confidence: 'medium' }
  if (container.typelib)
    return { format: 'windows-typelib-interface-metadata', detectedBy, confidence: 'medium' }
  return {
    format: container.pe
      ? 'pe-windows-interface-surface-preview'
      : 'windows-interface-surface-preview',
    detectedBy,
    confidence: 'low',
  }
}

function buildEvidenceSummary(args: {
  guid_evidence: GuidEvidence[]
  string_evidence: StringEvidence[]
  risk_flags: Array<Record<string, any>>
}) {
  return {
    guid_evidence_count: args.guid_evidence.length,
    string_evidence_count: args.string_evidence.length,
    risk_flag_count: args.risk_flags.length,
    evidence_kinds: WINDOWS_INTERFACE_EVIDENCE,
    source: TOOL_NAME,
  }
}

function buildWorkflowHandoff(inventory: WindowsInterfaceSurfaceInventory) {
  return {
    schema: 'rikune.windows_interface_surface.workflow_handoff.v1',
    source_tool: TOOL_NAME,
    artifact_type: WINDOWS_INTERFACE_SURFACE_ARTIFACT_TYPE,
    produces: [WINDOWS_INTERFACE_SURFACE_ARTIFACT_TYPE],
    consumes: ['sample'],
    recommended_static_next_tools: WINDOWS_INTERFACE_FOLLOW_UP_TOOLS,
    opt_in_runtime_next_tools: WINDOWS_INTERFACE_RUNTIME_HANDOFF_TOOLS,
    runtime_policy: {
      runtime_not_started_by_tool: true,
      runtime_requires_explicit_opt_in: true,
      reason:
        'COM activation, RPC calls, IPC connection, WMI queries, service operations, and ETW registration are outside this passive inventory.',
    },
    routes: [
      {
        when: 'COM/RPC GUIDs or exports are present',
        next_tools: ['pe.imports.extract', 'static.resource.graph', 'code.xrefs.analyze'],
      },
      {
        when: 'IPC, WMI, service, or impersonation risk evidence is present',
        next_tools: ['host.correlate', 'analysis.evidence.graph', 'vuln.pattern.scan'],
      },
      {
        when: 'runtime confirmation is explicitly requested',
        next_tools: WINDOWS_INTERFACE_RUNTIME_HANDOFF_TOOLS,
        opt_in_required: true,
      },
    ],
    policy: inventory.policy,
    evidence_summary: inventory.evidence_summary,
  }
}

function buildSummary(
  inventory: Omit<WindowsInterfaceSurfaceInventory, 'summary' | 'workflow_handoff'>
): string {
  return `${inventory.format}: ${inventory.guid_evidence.length} GUID candidate(s), ${inventory.string_evidence.length} interface string evidence item(s), ${inventory.risk_flags.length} risk flag(s).`
}

export function buildWindowsInterfaceSurfaceInventoryFromBuffer(
  data: Buffer,
  options: BuildOptions = {}
): WindowsInterfaceSurfaceInventory {
  const maxReadBytes = clampMaxReadBytes(options.maxReadBytes)
  const preview = data.subarray(0, Math.min(data.length, maxReadBytes))
  const container = detectContainer(preview, maxReadBytes, options)
  const binaryStrings = extractBinaryStrings(preview)
  const stringEvidence = collectStringEvidence(binaryStrings)
  const guidEvidence = collectGuidEvidence(binaryStrings)
  const comSurface = buildComSurface(stringEvidence, guidEvidence)
  const rpcSurface = buildRpcSurface(stringEvidence, guidEvidence)
  const ipcSurface = buildIpcSurface(stringEvidence)
  const etwSurface = buildEtwSurface(stringEvidence, guidEvidence)
  const wmiSurface = buildWmiSurface(stringEvidence, guidEvidence)
  const serviceSurface = buildServiceSurface(stringEvidence)
  const riskFlags = buildRiskFlags({
    com: comSurface,
    rpc: rpcSurface,
    ipc: ipcSurface,
    wmi: wmiSurface,
    service: serviceSurface,
    strings: stringEvidence,
  })
  const riskSummary = buildRiskSummary(riskFlags)
  const detected = detectFormat(container, stringEvidence, guidEvidence)

  const base = {
    sample_id: options.sampleId,
    filename: options.filename,
    format: detected.format,
    platforms: ['windows'],
    detected_by: detected.detectedBy,
    confidence: detected.confidence,
    size: options.size ?? data.length,
    preview_size: preview.length,
    container,
    guid_evidence: guidEvidence,
    string_evidence: stringEvidence,
    com_surface: comSurface,
    rpc_surface: rpcSurface,
    ipc_surface: ipcSurface,
    etw_surface: etwSurface,
    wmi_surface: wmiSurface,
    service_surface: serviceSurface,
    risk_flags: riskFlags,
    risk_summary: riskSummary,
    policy: {
      passive: true,
      no_execute: true,
      no_com_activation: true,
      no_rpc_call: true,
      no_alpc_connect: true,
      no_named_pipe_connect: true,
      no_wmi_query: true,
      no_service_start: true,
      no_etw_registration: true,
      no_debugger: true,
      no_external_tool: true,
      no_network: true,
      no_mutation: true,
    },
    recommended_next_tools: WINDOWS_INTERFACE_FOLLOW_UP_TOOLS,
    next_actions: [
      'Use pe.imports.extract and static.resource.graph to correlate interface strings with imports, resources, manifests, and type-library hints.',
      'Use code.xrefs.analyze to map CLSID/IID/RPC/IPC/WMI/service evidence to callsites.',
      'Use runtime planning tools only after explicit opt-in; this passive inventory must not activate or contact Windows interfaces.',
    ],
    quality_gates: {
      passive_static_inventory: true,
      sample_executed_by_tool: false,
      com_activated_by_tool: false,
      rpc_called_by_tool: false,
      alpc_connected_by_tool: false,
      named_pipe_connected_by_tool: false,
      wmi_queried_by_tool: false,
      service_started_by_tool: false,
      etw_registered_by_tool: false,
      debugger_started_by_tool: false,
      external_tool_invoked_by_tool: false,
      network_used_by_tool: false,
      mutation_performed: false,
    },
  } satisfies Omit<
    WindowsInterfaceSurfaceInventory,
    'summary' | 'workflow_handoff' | 'evidence_summary'
  >

  const withEvidence = {
    ...base,
    evidence_summary: buildEvidenceSummary(base),
  } satisfies Omit<WindowsInterfaceSurfaceInventory, 'summary' | 'workflow_handoff'>

  const inventory: WindowsInterfaceSurfaceInventory = {
    ...withEvidence,
    summary: buildSummary(withEvidence),
    workflow_handoff: {},
  }
  inventory.workflow_handoff = buildWorkflowHandoff(inventory)
  return inventory
}

export function createWindowsInterfaceSurfaceInventoryHandler(deps: Partial<PluginToolDeps> = {}) {
  return async (args: unknown): Promise<WorkerResult> => {
    const started = Date.now()
    try {
      const input = WindowsInterfaceSurfaceInventoryInputSchema.parse(args)
      const resolver = deps.resolvePrimarySamplePath
      if (!resolver) {
        return { ok: false, errors: ['resolvePrimarySamplePath dependency is unavailable'] }
      }

      const resolved = await resolver(deps.workspaceManager, input.sample_id)
      const stat = await fs.stat(resolved.samplePath)
      const maxReadBytes = clampMaxReadBytes(input.max_read_bytes)
      const handle = await fs.open(resolved.samplePath, 'r')
      try {
        const buffer = Buffer.alloc(Math.min(stat.size, maxReadBytes))
        await handle.read(buffer, 0, buffer.length, 0)
        const inventory = buildWindowsInterfaceSurfaceInventoryFromBuffer(buffer, {
          filename: path.basename(resolved.samplePath),
          sampleId: input.sample_id,
          maxReadBytes,
          size: stat.size,
        })

        const artifacts: ArtifactRef[] = []
        if (input.persist_artifact !== false) {
          const persist = deps.persistStaticAnalysisJsonArtifact
          if (persist) {
            artifacts.push(
              await persist(
                deps.workspaceManager,
                deps.database,
                input.sample_id,
                WINDOWS_INTERFACE_SURFACE_ARTIFACT_TYPE,
                'windows-interface-surface',
                inventory,
                input.session_tag ?? null
              )
            )
          }
        }

        return {
          ok: true,
          data: inventory,
          artifacts,
          metrics: { elapsed_ms: Date.now() - started, tool: TOOL_NAME },
        }
      } finally {
        await handle.close()
      }
    } catch (error) {
      return {
        ok: false,
        errors: [error instanceof Error ? error.message : String(error)],
        metrics: { elapsed_ms: Date.now() - started, tool: TOOL_NAME },
      }
    }
  }
}
