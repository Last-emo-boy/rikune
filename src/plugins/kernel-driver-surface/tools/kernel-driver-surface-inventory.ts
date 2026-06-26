/**
 * kernel.driver.surface.inventory — passive kernel driver surface inventory.
 *
 * This tool reads bounded bytes and summarizes Windows/Linux kernel driver
 * entry surfaces such as IOCTL constants, device interface strings, dispatch
 * routine hints, Linux module metadata, file_operations/ioctl hints, and risky
 * kernel primitives. It never loads drivers or modules, opens devices, sends
 * IOCTLs, calls kernel syscalls, starts telemetry, invokes external tools, or
 * mutates samples.
 */

import fs from 'fs/promises'
import path from 'path'
import { z } from 'zod'
import type { ArtifactRef, PluginToolDeps, ToolDefinition, WorkerResult } from '../../sdk.js'

const TOOL_NAME = 'kernel.driver.surface.inventory'
export const KERNEL_DRIVER_SURFACE_ARTIFACT_TYPE = 'kernel_driver_surface_inventory'

const DEFAULT_MAX_READ_BYTES = 8 * 1024 * 1024
const MAX_PREVIEW_BYTES = 32 * 1024 * 1024
const MAX_STRINGS = 8000
const MAX_EVIDENCE = 360
const MAX_INTERFACES = 160
const MAX_IOCTL_CANDIDATES = 96

const KERNEL_DRIVER_EVIDENCE = [
  'structure',
  'symbols',
  'imports',
  'strings',
  'device-interfaces',
  'ioctl',
  'dispatch',
  'module-metadata',
  'risk',
  'workflow',
]

const KERNEL_DRIVER_SAFETY = [
  'passive',
  'no_execute',
  'no_driver_load',
  'no_kernel_module_load',
  'no_device_open',
  'no_ioctl_send',
  'no_syscall',
  'no_kernel_probe',
  'no_debugger',
  'no_external_tool',
  'no_network_by_default',
  'no_mutation',
]

const KERNEL_DRIVER_FOLLOW_UP_TOOLS = [
  'artifact.read',
  'pe.structure.analyze',
  'pe.imports.extract',
  'pe.security.profile',
  'linux.binary.inventory',
  'native.object.inventory',
  'native.debug.types.inventory',
  'cpp.abi.layout.inventory',
  'strings.extract',
  'code.xrefs.analyze',
  'vuln.pattern.scan',
  'analysis.evidence.graph',
  'linux.runtime.plan',
  'windows.runtime.plan',
  'report.generate',
  'workflow.search',
]

const WINDOWS_DEVICE_TYPES: Record<number, string> = {
  0x0001: 'FILE_DEVICE_BEEP',
  0x0002: 'FILE_DEVICE_CD_ROM',
  0x0003: 'FILE_DEVICE_CD_ROM_FILE_SYSTEM',
  0x0004: 'FILE_DEVICE_CONTROLLER',
  0x0005: 'FILE_DEVICE_DATALINK',
  0x0006: 'FILE_DEVICE_DFS',
  0x0007: 'FILE_DEVICE_DISK',
  0x0008: 'FILE_DEVICE_DISK_FILE_SYSTEM',
  0x0009: 'FILE_DEVICE_FILE_SYSTEM',
  0x000a: 'FILE_DEVICE_INPORT_PORT',
  0x000b: 'FILE_DEVICE_KEYBOARD',
  0x000c: 'FILE_DEVICE_MAILSLOT',
  0x000d: 'FILE_DEVICE_MIDI_IN',
  0x000e: 'FILE_DEVICE_MIDI_OUT',
  0x000f: 'FILE_DEVICE_MOUSE',
  0x0010: 'FILE_DEVICE_MULTI_UNC_PROVIDER',
  0x0011: 'FILE_DEVICE_NAMED_PIPE',
  0x0012: 'FILE_DEVICE_NETWORK',
  0x0013: 'FILE_DEVICE_NETWORK_BROWSER',
  0x0014: 'FILE_DEVICE_NETWORK_FILE_SYSTEM',
  0x0015: 'FILE_DEVICE_NULL',
  0x0016: 'FILE_DEVICE_PARALLEL_PORT',
  0x0017: 'FILE_DEVICE_PHYSICAL_NETCARD',
  0x0018: 'FILE_DEVICE_PRINTER',
  0x0019: 'FILE_DEVICE_SCANNER',
  0x001a: 'FILE_DEVICE_SERIAL_MOUSE_PORT',
  0x001b: 'FILE_DEVICE_SERIAL_PORT',
  0x001c: 'FILE_DEVICE_SCREEN',
  0x001d: 'FILE_DEVICE_SOUND',
  0x001e: 'FILE_DEVICE_STREAMS',
  0x001f: 'FILE_DEVICE_TAPE',
  0x0020: 'FILE_DEVICE_TAPE_FILE_SYSTEM',
  0x0021: 'FILE_DEVICE_TRANSPORT',
  0x0022: 'FILE_DEVICE_UNKNOWN',
  0x0023: 'FILE_DEVICE_VIDEO',
  0x0024: 'FILE_DEVICE_VIRTUAL_DISK',
  0x0025: 'FILE_DEVICE_WAVE_IN',
  0x0026: 'FILE_DEVICE_WAVE_OUT',
  0x0027: 'FILE_DEVICE_8042_PORT',
  0x0028: 'FILE_DEVICE_NETWORK_REDIRECTOR',
  0x0029: 'FILE_DEVICE_BATTERY',
  0x002a: 'FILE_DEVICE_BUS_EXTENDER',
  0x002b: 'FILE_DEVICE_MODEM',
  0x002c: 'FILE_DEVICE_VDM',
  0x002d: 'FILE_DEVICE_MASS_STORAGE',
  0x002e: 'FILE_DEVICE_SMB',
  0x002f: 'FILE_DEVICE_KS',
  0x0030: 'FILE_DEVICE_CHANGER',
  0x0031: 'FILE_DEVICE_SMARTCARD',
  0x0032: 'FILE_DEVICE_ACPI',
  0x0033: 'FILE_DEVICE_DVD',
  0x0034: 'FILE_DEVICE_FULLSCREEN_VIDEO',
  0x0035: 'FILE_DEVICE_DFS_FILE_SYSTEM',
  0x0036: 'FILE_DEVICE_DFS_VOLUME',
  0x0037: 'FILE_DEVICE_SERENUM',
  0x0038: 'FILE_DEVICE_TERMSRV',
  0x0039: 'FILE_DEVICE_KSEC',
  0x003a: 'FILE_DEVICE_FIPS',
  0x003b: 'FILE_DEVICE_INFINIBAND',
  0x003e: 'FILE_DEVICE_VMBUS',
  0x003f: 'FILE_DEVICE_CRYPT_PROVIDER',
  0x0041: 'FILE_DEVICE_BLUETOOTH',
  0x0042: 'FILE_DEVICE_MT_COMPOSITE',
  0x0043: 'FILE_DEVICE_MT_TRANSPORT',
  0x0044: 'FILE_DEVICE_BIOMETRIC',
  0x0045: 'FILE_DEVICE_PMI',
  0x0046: 'FILE_DEVICE_EHSTOR',
  0x0047: 'FILE_DEVICE_DEVAPI',
  0x0048: 'FILE_DEVICE_GPIO',
  0x0049: 'FILE_DEVICE_USBEX',
  0x0050: 'FILE_DEVICE_CONSOLE',
  0x0051: 'FILE_DEVICE_NFP',
  0x0052: 'FILE_DEVICE_SYSENV',
  0x0053: 'FILE_DEVICE_VIRTUAL_BLOCK',
  0x0054: 'FILE_DEVICE_POINT_OF_SERVICE',
}

const IOCTL_METHODS = ['METHOD_BUFFERED', 'METHOD_IN_DIRECT', 'METHOD_OUT_DIRECT', 'METHOD_NEITHER']
const IOCTL_ACCESS = [
  'FILE_ANY_ACCESS',
  'FILE_READ_ACCESS',
  'FILE_WRITE_ACCESS',
  'FILE_READ_WRITE_ACCESS',
]

const WINDOWS_DRIVER_PATTERNS: Array<{
  pattern: RegExp
  kind: string
  family: string
  confidence: 'low' | 'medium' | 'high'
}> = [
  { pattern: /\bDriverEntry\b/i, kind: 'entrypoint', family: 'wdm', confidence: 'medium' },
  { pattern: /\bDriverUnload\b/i, kind: 'unload', family: 'wdm', confidence: 'medium' },
  {
    pattern: /\bIRP_MJ_DEVICE_CONTROL\b/i,
    kind: 'dispatch-major',
    family: 'wdm',
    confidence: 'high',
  },
  { pattern: /\bDeviceControl\b/i, kind: 'dispatch-name', family: 'wdm', confidence: 'medium' },
  {
    pattern: /\bIoCreateDevice(?:Secure)?\b/i,
    kind: 'device-create',
    family: 'wdm',
    confidence: 'high',
  },
  {
    pattern: /\bIoCreateSymbolicLink\b/i,
    kind: 'dos-device-link',
    family: 'wdm',
    confidence: 'high',
  },
  {
    pattern: /\bIoRegisterDeviceInterface\b/i,
    kind: 'device-interface',
    family: 'wdm',
    confidence: 'high',
  },
  { pattern: /\bWdfDriverCreate\b/i, kind: 'framework', family: 'kmdf', confidence: 'high' },
  { pattern: /\bWdfDeviceCreate\b/i, kind: 'device-create', family: 'kmdf', confidence: 'high' },
  { pattern: /\bWdfIoQueueCreate\b/i, kind: 'io-queue', family: 'kmdf', confidence: 'high' },
  { pattern: /\bEvtIoDeviceControl\b/i, kind: 'dispatch-name', family: 'kmdf', confidence: 'high' },
  {
    pattern: /\bNdis(?:M|F|Register|Deregister)/i,
    kind: 'network-driver',
    family: 'ndis',
    confidence: 'medium',
  },
  {
    pattern: /\bFltRegisterFilter\b/i,
    kind: 'filesystem-filter',
    family: 'minifilter',
    confidence: 'high',
  },
  {
    pattern: /\bPsSet(?:CreateProcess|CreateThread|LoadImage)NotifyRoutine\b/i,
    kind: 'kernel-callback',
    family: 'callback',
    confidence: 'medium',
  },
  {
    pattern: /\bObRegisterCallbacks\b/i,
    kind: 'kernel-callback',
    family: 'callback',
    confidence: 'medium',
  },
]

const WINDOWS_RISK_PRIMITIVES: Array<{ pattern: RegExp; id: string; severity: string }> = [
  { pattern: /\bMmMapIoSpace(?:Ex)?\b/i, id: 'windows.mmio.mapping', severity: 'high' },
  {
    pattern: /\bMmMapLockedPagesSpecifyCache\b/i,
    id: 'windows.locked-pages-mapping',
    severity: 'medium',
  },
  { pattern: /\bZwMapViewOfSection\b/i, id: 'windows.section-mapping', severity: 'medium' },
  { pattern: /\bZwOpenProcess\b/i, id: 'windows.process-handle', severity: 'medium' },
  { pattern: /\bObReferenceObjectByHandle\b/i, id: 'windows.object-handle', severity: 'medium' },
  { pattern: /\bProbeFor(?:Read|Write)\b/i, id: 'windows.user-buffer-probe', severity: 'info' },
  { pattern: /\bRtlCopyMemory\b|\bmemcpy\b/i, id: 'windows.raw-copy', severity: 'medium' },
]

const LINUX_DRIVER_PATTERNS: Array<{
  pattern: RegExp
  kind: string
  family: string
  confidence: 'low' | 'medium' | 'high'
}> = [
  {
    pattern: /\b(?:init_module|module_init|cleanup_module|module_exit)\b/i,
    kind: 'module-entry',
    family: 'module',
    confidence: 'medium',
  },
  {
    pattern: /\bfile_operations\b/i,
    kind: 'file-operations',
    family: 'char-device',
    confidence: 'medium',
  },
  {
    pattern: /\b(?:unlocked_ioctl|compat_ioctl|ioctl)\b/i,
    kind: 'ioctl-handler',
    family: 'char-device',
    confidence: 'high',
  },
  {
    pattern: /\b(?:misc_register|misc_deregister)\b/i,
    kind: 'misc-device',
    family: 'char-device',
    confidence: 'high',
  },
  {
    pattern: /\b(?:cdev_init|cdev_add|register_chrdev(?:_region)?)\b/i,
    kind: 'char-device',
    family: 'char-device',
    confidence: 'high',
  },
  {
    pattern: /\b(?:proc_create|proc_create_data|debugfs_create_file|sysfs_create_file)\b/i,
    kind: 'virtual-filesystem-interface',
    family: 'fs-interface',
    confidence: 'medium',
  },
  {
    pattern: /\b(?:net_device_ops|register_netdev|alloc_netdev)\b/i,
    kind: 'network-driver',
    family: 'netdev',
    confidence: 'medium',
  },
  {
    pattern: /\b(?:platform_driver_register|pci_register_driver|usb_register_driver)\b/i,
    kind: 'bus-driver',
    family: 'bus',
    confidence: 'medium',
  },
]

const LINUX_RISK_PRIMITIVES: Array<{ pattern: RegExp; id: string; severity: string }> = [
  { pattern: /\bcopy_from_user\b/i, id: 'linux.copy-from-user', severity: 'high' },
  { pattern: /\bcopy_to_user\b/i, id: 'linux.copy-to-user', severity: 'medium' },
  { pattern: /\b(?:get_user|put_user)\b/i, id: 'linux.user-access', severity: 'medium' },
  {
    pattern: /\b(?:ioremap|devm_ioremap_resource|io_remap_pfn_range)\b/i,
    id: 'linux.mmio-mapping',
    severity: 'high',
  },
  { pattern: /\brequest_irq\b/i, id: 'linux.interrupt-handler', severity: 'medium' },
  {
    pattern: /\b(?:debugfs_create_file|proc_create)\b/i,
    id: 'linux.debug-proc-interface',
    severity: 'medium',
  },
  { pattern: /\b(?:memcpy|memmove|strcpy|strncpy)\b/i, id: 'linux.raw-copy', severity: 'medium' },
]

export const kernelDriverSurfaceInventoryAspects = {
  formats: [
    'kernel-driver',
    'driver',
    'driver-surface',
    'ioctl',
    'windows-driver',
    'windows-kernel-driver',
    'linux-driver',
    'linux-kernel-module',
    'sys',
    'pe',
    'elf',
    'elf-object',
  ],
  platforms: ['windows', 'linux', 'embedded', 'cross-platform'],
  architectures: ['x86', 'x64', 'arm', 'arm64', 'mips', 'mipsel', 'ppc', 'riscv'],
  execution: ['static', 'triage', 'attack-surface', 'workflow-plan'],
  safety: KERNEL_DRIVER_SAFETY,
  capabilities: [
    'driver-surface-inventory',
    'windows-ioctl-candidate-decode',
    'windows-device-interface-inventory',
    'windows-dispatch-hints',
    'linux-module-metadata-inventory',
    'linux-ioctl-handler-hints',
    'kernel-risk-primitive-inventory',
    'driver-workflow-routing',
  ],
  evidence: KERNEL_DRIVER_EVIDENCE,
  route_terms: [
    'kernel driver',
    'driver surface',
    'windows driver',
    'linux kernel module',
    'ioctl',
    'irp mj device control',
    'device object',
    'wdf',
    'wdm',
    'kmdf',
    'unlocked_ioctl',
    'copy_from_user',
    'vermagic',
  ],
  search: [
    'kernel driver attack surface',
    'Windows IOCTL inventory',
    'Linux kernel module metadata',
    'driver dispatch and risky primitive inventory',
  ],
}

const KernelDriverPolicySchema = z.object({
  passive: z.literal(true),
  no_execute: z.literal(true),
  no_driver_load: z.literal(true),
  no_kernel_module_load: z.literal(true),
  no_device_open: z.literal(true),
  no_ioctl_send: z.literal(true),
  no_syscall: z.literal(true),
  no_kernel_probe: z.literal(true),
  no_debugger: z.literal(true),
  no_external_tool: z.literal(true),
  no_network: z.literal(true),
  no_mutation: z.literal(true),
})

const KernelDriverSurfaceInventorySchema = z.object({
  sample_id: z.string().optional(),
  filename: z.string().optional(),
  format: z.string(),
  platform: z.string(),
  detected_by: z.array(z.string()),
  confidence: z.enum(['low', 'medium', 'high']),
  size: z.number().optional(),
  preview_size: z.number(),
  container: z.record(z.any()),
  evidence: z.array(z.record(z.any())),
  windows_surface: z.record(z.any()),
  linux_surface: z.record(z.any()),
  ioctl_candidates: z.array(z.record(z.any())),
  device_interfaces: z.array(z.record(z.any())),
  dispatch_hints: z.array(z.record(z.any())),
  module_metadata: z.array(z.record(z.any())),
  risky_primitives: z.array(z.record(z.any())),
  risk_flags: z.array(z.record(z.any())),
  risk_summary: z.record(z.any()),
  policy: KernelDriverPolicySchema,
  summary: z.string(),
  recommended_next_tools: z.array(z.string()),
  next_actions: z.array(z.string()),
  evidence_summary: z.record(z.any()),
  workflow_handoff: z.record(z.any()),
  quality_gates: z.record(z.any()),
})

export const KernelDriverSurfaceInventoryInputSchema = z.object({
  sample_id: z.string().describe('Target driver or kernel module sample identifier.'),
  max_read_bytes: z
    .number()
    .int()
    .min(1024)
    .max(MAX_PREVIEW_BYTES)
    .default(DEFAULT_MAX_READ_BYTES)
    .describe('Maximum bytes to read for passive kernel driver surface inventory.'),
  persist_artifact: z
    .boolean()
    .default(true)
    .describe('Persist kernel driver surface inventory JSON as artifact.'),
  session_tag: z.string().optional().describe('Optional artifact session tag.'),
})

export const KernelDriverSurfaceInventoryOutputSchema = z.object({
  ok: z.boolean(),
  data: KernelDriverSurfaceInventorySchema.optional(),
  artifacts: z.array(z.any()).optional(),
  errors: z.array(z.string()).optional(),
  metrics: z.object({ elapsed_ms: z.number(), tool: z.string() }).optional(),
})

export const kernelDriverSurfaceInventoryToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Passively inventory Windows/Linux kernel driver attack-surface evidence, including IOCTL constants, device interface strings, dispatch hints, Linux module metadata, and risky primitives without loading drivers, inserting modules, opening devices, sending IOCTLs, or invoking external tools.',
  inputSchema: KernelDriverSurfaceInventoryInputSchema,
  outputSchema: KernelDriverSurfaceInventoryOutputSchema,
  aspects: kernelDriverSurfaceInventoryAspects,
  artifacts: [
    {
      type: KERNEL_DRIVER_SURFACE_ARTIFACT_TYPE,
      description: 'Passive kernel driver IOCTL/device/module/risky primitive surface inventory',
      mime: 'application/json',
      mimeTypes: ['application/json'],
    },
  ],
  evidence: KERNEL_DRIVER_EVIDENCE.map((category) => ({
    category,
    artifactTypes: [KERNEL_DRIVER_SURFACE_ARTIFACT_TYPE],
  })),
  workflowRecipes: [
    {
      id: 'kernel.driver-surface-static-inventory',
      title: 'Passive kernel driver surface inventory',
      description:
        'Inventory driver-facing IOCTL, device interface, dispatch, Linux module metadata, and risky primitive evidence before routing to PE/ELF/object, xref, vulnerability, runtime-plan, evidence graph, and reporting tools.',
      startsWith: [TOOL_NAME],
      nextTools: KERNEL_DRIVER_FOLLOW_UP_TOOLS,
      requiredArtifacts: ['sample'],
      producesArtifacts: [KERNEL_DRIVER_SURFACE_ARTIFACT_TYPE],
      evidence: KERNEL_DRIVER_EVIDENCE,
      safety: KERNEL_DRIVER_SAFETY,
    },
  ],
}

export type KernelDriverSurfaceInventory = z.infer<typeof KernelDriverSurfaceInventorySchema>

type Confidence = 'low' | 'medium' | 'high'
type Platform = 'windows-driver' | 'linux-kernel-module' | 'mixed-driver' | 'unknown-driver'

interface BinaryString {
  value: string
  offset: number
  encoding: 'ascii' | 'utf16le'
}

interface BuildOptions {
  filename?: string
  sampleId?: string
  maxReadBytes?: number
  size?: number
}

interface EvidenceItem {
  id: string
  platform: 'windows' | 'linux' | 'generic'
  kind: string
  value: string
  offset: number
  source: string
  confidence: Confidence
}

function clampMaxReadBytes(value: number | undefined): number {
  if (!Number.isFinite(value ?? DEFAULT_MAX_READ_BYTES)) return DEFAULT_MAX_READ_BYTES
  return Math.max(1024, Math.min(MAX_PREVIEW_BYTES, Math.trunc(value ?? DEFAULT_MAX_READ_BYTES)))
}

function sanitizeString(value: string): string {
  return value.replace(/[\u0000-\u001f\u007f]+/g, ' ').trim()
}

function unique<T>(items: T[]): T[] {
  return Array.from(new Set(items))
}

function uniqueBy<T>(items: T[], keyer: (item: T) => string): T[] {
  const seen = new Set<string>()
  const output: T[] = []
  for (const item of items) {
    const key = keyer(item)
    if (seen.has(key)) continue
    seen.add(key)
    output.push(item)
  }
  return output
}

function extractAsciiStrings(data: Buffer): BinaryString[] {
  const strings: BinaryString[] = []
  let start = -1
  for (let i = 0; i < data.length; i += 1) {
    const byte = data[i]
    const printable = byte >= 0x20 && byte <= 0x7e
    if (printable) {
      if (start < 0) start = i
      continue
    }
    if (start >= 0 && i - start >= 4) {
      strings.push({ value: data.toString('ascii', start, i), offset: start, encoding: 'ascii' })
      if (strings.length >= MAX_STRINGS) return strings
    }
    start = -1
  }
  if (start >= 0 && data.length - start >= 4 && strings.length < MAX_STRINGS) {
    strings.push({
      value: data.toString('ascii', start, data.length),
      offset: start,
      encoding: 'ascii',
    })
  }
  return strings
}

function extractUtf16LeStrings(data: Buffer): BinaryString[] {
  const strings: BinaryString[] = []
  let start = -1
  let chars = 0
  for (let i = 0; i + 1 < data.length; i += 2) {
    const code = data.readUInt16LE(i)
    const printable = code >= 0x20 && code <= 0x7e
    if (printable) {
      if (start < 0) start = i
      chars += 1
      continue
    }
    if (start >= 0 && chars >= 4) {
      strings.push({
        value: data.toString('utf16le', start, i),
        offset: start,
        encoding: 'utf16le',
      })
      if (strings.length >= Math.floor(MAX_STRINGS / 2)) return strings
    }
    start = -1
    chars = 0
  }
  if (start >= 0 && chars >= 4 && strings.length < Math.floor(MAX_STRINGS / 2)) {
    strings.push({
      value: data.toString('utf16le', start, start + chars * 2),
      offset: start,
      encoding: 'utf16le',
    })
  }
  return strings
}

function extractBinaryStrings(data: Buffer): BinaryString[] {
  return uniqueBy([...extractAsciiStrings(data), ...extractUtf16LeStrings(data)], (item) => {
    return `${item.offset}:${item.encoding}:${item.value}`
  }).slice(0, MAX_STRINGS)
}

function detectContainer(data: Buffer, maxReadBytes: number, options: BuildOptions) {
  const lower = options.filename?.toLowerCase() ?? ''
  const text = data.toString('latin1', 0, Math.min(data.length, 128 * 1024))
  const isPe = data.length >= 2 && data[0] === 0x4d && data[1] === 0x5a
  const isElf =
    data.length >= 4 && data[0] === 0x7f && data[1] === 0x45 && data[2] === 0x4c && data[3] === 0x46
  const isWindowsDriver =
    lower.endsWith('.sys') ||
    /\b(?:DriverEntry|IoCreateDevice|IRP_MJ_DEVICE_CONTROL|WdfDriverCreate)\b/i.test(text)
  const isLinuxModule =
    lower.endsWith('.ko') || /\bvermagic=|\bdepends=|\bmodule_layout\b/i.test(text)

  const kind = isPe
    ? isWindowsDriver
      ? 'pe-windows-kernel-driver'
      : 'pe-preview'
    : isElf
      ? isLinuxModule
        ? 'elf-linux-kernel-module'
        : 'elf-preview'
      : isWindowsDriver
        ? 'raw-windows-driver-preview'
        : isLinuxModule
          ? 'raw-linux-kernel-module-preview'
          : 'raw-driver-preview'

  return {
    kind,
    magic: isPe ? 'MZ' : isElf ? 'ELF' : 'unknown',
    filename_hint: lower || null,
    bounded_preview: {
      bytes_read: data.length,
      max_read_bytes: maxReadBytes,
      truncated: (options.size ?? data.length) > data.length,
    },
  }
}

function makeEvidence(
  platform: EvidenceItem['platform'],
  kind: string,
  value: string,
  offset: number,
  source: string,
  confidence: Confidence
): EvidenceItem {
  return {
    id: `${platform}.${kind}.${offset}.${sanitizeString(value).slice(0, 48)}`,
    platform,
    kind,
    value: sanitizeString(value).slice(0, 240),
    offset,
    source,
    confidence,
  }
}

function collectPatternEvidence(strings: BinaryString[]): EvidenceItem[] {
  const evidence: EvidenceItem[] = []
  for (const item of strings) {
    const value = item.value
    for (const rule of WINDOWS_DRIVER_PATTERNS) {
      if (!rule.pattern.test(value)) continue
      evidence.push(
        makeEvidence('windows', rule.kind, value, item.offset, rule.family, rule.confidence)
      )
    }
    for (const rule of LINUX_DRIVER_PATTERNS) {
      if (!rule.pattern.test(value)) continue
      evidence.push(
        makeEvidence('linux', rule.kind, value, item.offset, rule.family, rule.confidence)
      )
    }
    if (evidence.length >= MAX_EVIDENCE) break
  }
  return uniqueBy(evidence, (entry) => entry.id).slice(0, MAX_EVIDENCE)
}

function collectDeviceInterfaces(strings: BinaryString[]): Array<Record<string, unknown>> {
  const interfaces: Array<Record<string, unknown>> = []
  const windowsPattern =
    /(?:\\(?:Device|DosDevices|GLOBAL\?\?)\\[A-Za-z0-9_.:$#{}-]{2,120}|\\\\\.\\[A-Za-z0-9_.:$#{}-]{2,120})/g
  const linuxPattern =
    /(?:\/dev\/[A-Za-z0-9_.-]{2,120}|\/proc\/[A-Za-z0-9_./-]{2,120}|\/sys\/[A-Za-z0-9_./-]{2,160})/g
  for (const item of strings) {
    for (const match of item.value.matchAll(windowsPattern)) {
      interfaces.push({
        platform: 'windows',
        kind: match[0].startsWith('\\\\.\\') ? 'win32-device-path' : 'kernel-device-path',
        value: sanitizeString(match[0]),
        offset: item.offset + (match.index ?? 0),
        confidence: 'high',
      })
    }
    for (const match of item.value.matchAll(linuxPattern)) {
      interfaces.push({
        platform: 'linux',
        kind: match[0].startsWith('/dev/') ? 'device-node' : 'virtual-filesystem-path',
        value: sanitizeString(match[0]),
        offset: item.offset + (match.index ?? 0),
        confidence: 'medium',
      })
    }
    if (interfaces.length >= MAX_INTERFACES) break
  }
  return uniqueBy(interfaces, (item) => `${item.platform}:${item.value}`).slice(0, MAX_INTERFACES)
}

function collectDispatchHints(strings: BinaryString[], evidence: EvidenceItem[]) {
  const hints: Array<Record<string, unknown>> = []
  const dispatchTerms = [
    'IRP_MJ_CREATE',
    'IRP_MJ_CLOSE',
    'IRP_MJ_READ',
    'IRP_MJ_WRITE',
    'IRP_MJ_DEVICE_CONTROL',
    'IRP_MJ_INTERNAL_DEVICE_CONTROL',
    'IRP_MJ_PNP',
    'DriverEntry',
    'DriverUnload',
    'EvtIoDeviceControl',
    'unlocked_ioctl',
    'compat_ioctl',
    'file_operations',
    'module_init',
    'module_exit',
  ]
  for (const item of strings) {
    for (const term of dispatchTerms) {
      if (!item.value.includes(term)) continue
      hints.push({
        platform:
          term.startsWith('IRP_') || term.startsWith('Driver') || term.startsWith('Evt')
            ? 'windows'
            : 'linux',
        kind: term,
        value: sanitizeString(item.value).slice(0, 160),
        offset: item.offset,
        confidence: term.includes('DEVICE_CONTROL') || term.includes('ioctl') ? 'high' : 'medium',
      })
    }
  }
  for (const entry of evidence.filter((item) => /dispatch|entry|unload|ioctl/.test(item.kind))) {
    hints.push({
      platform: entry.platform,
      kind: entry.kind,
      value: entry.value,
      offset: entry.offset,
      confidence: entry.confidence,
    })
  }
  return uniqueBy(hints, (item) => `${item.platform}:${item.kind}:${item.offset}`).slice(0, 160)
}

function decodeIoctlCandidates(data: Buffer): Array<Record<string, unknown>> {
  const candidates: Array<Record<string, unknown>> = []
  const seen = new Set<number>()
  for (let offset = 0; offset + 4 <= data.length; offset += 1) {
    const code = data.readUInt32LE(offset)
    if (seen.has(code) || code < 0x10000 || code === 0xffffffff) continue
    const method = code & 0x3
    const functionCode = (code >>> 2) & 0xfff
    const access = (code >>> 14) & 0x3
    const deviceType = (code >>> 16) & 0xffff
    const knownDevice = WINDOWS_DEVICE_TYPES[deviceType]
    const customDeviceType = deviceType >= 0x8000
    const customFunction = functionCode >= 0x800
    if (!knownDevice && !customDeviceType) continue
    if (!customFunction && !knownDevice) continue
    if (functionCode === 0 && !customDeviceType) continue
    seen.add(code)
    candidates.push({
      platform: 'windows',
      code: `0x${code.toString(16).padStart(8, '0')}`,
      offset,
      device_type: knownDevice ?? `CUSTOM_DEVICE_TYPE_0x${deviceType.toString(16)}`,
      device_type_raw: `0x${deviceType.toString(16).padStart(4, '0')}`,
      function: `0x${functionCode.toString(16).padStart(3, '0')}`,
      function_raw: functionCode,
      custom_function: customFunction,
      method: IOCTL_METHODS[method],
      access: IOCTL_ACCESS[access],
      risk_flags: [
        ...(method === 3 ? ['method_neither'] : []),
        ...(access === 0 ? ['file_any_access'] : []),
        ...(customFunction ? ['custom_function_range'] : []),
        ...(customDeviceType ? ['custom_device_type'] : []),
      ],
      confidence: knownDevice && customFunction ? 'medium' : customDeviceType ? 'low' : 'low',
    })
    if (candidates.length >= MAX_IOCTL_CANDIDATES) break
  }
  return candidates
}

function collectModuleMetadata(strings: BinaryString[]): Array<Record<string, unknown>> {
  const keys = new Set([
    'alias',
    'author',
    'depends',
    'description',
    'firmware',
    'intree',
    'license',
    'name',
    'parm',
    'retpoline',
    'srcversion',
    'vermagic',
  ])
  const entries: Array<Record<string, unknown>> = []
  for (const item of strings) {
    const parts = item.value.split(/\u0000|\n|\r/)
    for (const part of parts) {
      const match = /^([A-Za-z_][A-Za-z0-9_]*)=(.{0,240})$/.exec(part.trim())
      if (!match || !keys.has(match[1])) continue
      entries.push({
        key: match[1],
        value: sanitizeString(match[2]).slice(0, 240),
        offset: item.offset,
        platform: 'linux',
        confidence: match[1] === 'vermagic' || match[1] === 'license' ? 'high' : 'medium',
      })
    }
  }
  return uniqueBy(entries, (item) => `${item.key}:${item.value}`).slice(0, 180)
}

function collectRiskyPrimitives(strings: BinaryString[]): Array<Record<string, unknown>> {
  const primitives: Array<Record<string, unknown>> = []
  for (const item of strings) {
    for (const rule of WINDOWS_RISK_PRIMITIVES) {
      if (!rule.pattern.test(item.value)) continue
      primitives.push({
        platform: 'windows',
        id: rule.id,
        severity: rule.severity,
        value: sanitizeString(item.value).slice(0, 180),
        offset: item.offset,
      })
    }
    for (const rule of LINUX_RISK_PRIMITIVES) {
      if (!rule.pattern.test(item.value)) continue
      primitives.push({
        platform: 'linux',
        id: rule.id,
        severity: rule.severity,
        value: sanitizeString(item.value).slice(0, 180),
        offset: item.offset,
      })
    }
  }
  return uniqueBy(primitives, (item) => `${item.platform}:${item.id}:${item.offset}`).slice(0, 160)
}

function determinePlatform(
  container: Record<string, any>,
  evidence: EvidenceItem[],
  moduleMetadata: Array<Record<string, unknown>>,
  ioctlCandidates: Array<Record<string, unknown>>
): Platform {
  const kind = String(container.kind ?? '')
  const windowsEvidenceCount = evidence.filter((item) => item.platform === 'windows').length
  const linuxEvidenceCount = evidence.filter((item) => item.platform === 'linux').length
  if (kind.includes('linux') && moduleMetadata.length > 0 && windowsEvidenceCount === 0) {
    return 'linux-kernel-module'
  }
  if (kind.includes('windows') && (moduleMetadata.length > 0 || linuxEvidenceCount > 0)) {
    return 'mixed-driver'
  }
  if (kind.includes('linux') && windowsEvidenceCount > 0 && ioctlCandidates.length > 0) {
    return 'mixed-driver'
  }
  if (kind.includes('windows') || ioctlCandidates.length > 0 || windowsEvidenceCount > 0) {
    return 'windows-driver'
  }
  if (kind.includes('linux') || moduleMetadata.length > 0 || linuxEvidenceCount > 0) {
    return 'linux-kernel-module'
  }
  return 'unknown-driver'
}

function detectFormat(
  platform: Platform,
  container: Record<string, any>,
  evidence: EvidenceItem[],
  ioctlCandidates: Array<Record<string, unknown>>,
  moduleMetadata: Array<Record<string, unknown>>
): { format: string; detectedBy: string[]; confidence: Confidence } {
  const detectedBy = new Set<string>()
  detectedBy.add(String(container.kind ?? 'raw-driver-preview'))
  if (ioctlCandidates.length > 0) detectedBy.add('windows-ioctl-candidates')
  if (moduleMetadata.some((item) => item.key === 'vermagic')) detectedBy.add('linux-vermagic')
  for (const item of evidence) detectedBy.add(`${item.platform}:${item.kind}`)
  const highCount = evidence.filter((item) => item.confidence === 'high').length
  const confidence: Confidence =
    highCount >= 2 ||
    ioctlCandidates.length >= 2 ||
    moduleMetadata.some((item) => item.key === 'vermagic')
      ? 'high'
      : evidence.length + ioctlCandidates.length + moduleMetadata.length >= 2
        ? 'medium'
        : detectedBy.size > 1
          ? 'low'
          : 'low'
  const format =
    platform === 'windows-driver'
      ? 'windows-kernel-driver-surface'
      : platform === 'linux-kernel-module'
        ? 'linux-kernel-module-surface'
        : platform === 'mixed-driver'
          ? 'mixed-kernel-driver-surface'
          : 'kernel-driver-surface-preview'
  return { format, detectedBy: Array.from(detectedBy).slice(0, 80), confidence }
}

function buildWindowsSurface(
  evidence: EvidenceItem[],
  ioctlCandidates: Array<Record<string, unknown>>,
  deviceInterfaces: Array<Record<string, unknown>>,
  riskyPrimitives: Array<Record<string, unknown>>
) {
  const windowsEvidence = evidence.filter((item) => item.platform === 'windows')
  const families = unique(windowsEvidence.map((item) => item.source))
  return {
    present: windowsEvidence.length > 0 || ioctlCandidates.length > 0,
    framework_hints: families,
    ioctl_candidate_count: ioctlCandidates.length,
    device_interface_count: deviceInterfaces.filter((item) => item.platform === 'windows').length,
    risky_primitive_count: riskyPrimitives.filter((item) => item.platform === 'windows').length,
    likely_framework:
      families.find((item) => ['kmdf', 'wdm', 'ndis', 'minifilter'].includes(item)) ?? null,
  }
}

function buildLinuxSurface(
  evidence: EvidenceItem[],
  moduleMetadata: Array<Record<string, unknown>>,
  deviceInterfaces: Array<Record<string, unknown>>,
  riskyPrimitives: Array<Record<string, unknown>>
) {
  const linuxEvidence = evidence.filter((item) => item.platform === 'linux')
  const metadata = new Map<string, string[]>()
  for (const entry of moduleMetadata) {
    const key = String(entry.key)
    const value = String(entry.value)
    metadata.set(key, [...(metadata.get(key) ?? []), value])
  }
  return {
    present: linuxEvidence.length > 0 || moduleMetadata.length > 0,
    module_name: metadata.get('name')?.[0] ?? null,
    vermagic: metadata.get('vermagic')?.[0] ?? null,
    license: metadata.get('license')?.[0] ?? null,
    depends: metadata.get('depends')?.[0] ?? null,
    parameter_count: moduleMetadata.filter((item) => item.key === 'parm').length,
    interface_count: deviceInterfaces.filter((item) => item.platform === 'linux').length,
    risky_primitive_count: riskyPrimitives.filter((item) => item.platform === 'linux').length,
    surface_families: unique(linuxEvidence.map((item) => item.source)),
  }
}

function buildRiskFlags(
  preview: Buffer,
  maxReadBytes: number,
  ioctlCandidates: Array<Record<string, any>>,
  moduleMetadata: Array<Record<string, any>>,
  riskyPrimitives: Array<Record<string, any>>,
  deviceInterfaces: Array<Record<string, any>>
) {
  const flags: Array<Record<string, unknown>> = []
  if (preview.length >= maxReadBytes) {
    flags.push({
      id: 'bounded_preview.truncated',
      severity: 'info',
      message:
        'Input was scanned only up to max_read_bytes; driver surface evidence may exist later.',
    })
  }
  for (const candidate of ioctlCandidates) {
    const riskFlags = (candidate.risk_flags ?? []) as string[]
    if (riskFlags.includes('method_neither')) {
      flags.push({
        id: 'windows.ioctl.method_neither',
        severity: 'high',
        evidence: candidate.code,
        message:
          'Candidate IOCTL uses METHOD_NEITHER; downstream review should validate user-buffer probing and length checks.',
      })
    }
    if (riskFlags.includes('file_any_access')) {
      flags.push({
        id: 'windows.ioctl.file_any_access',
        severity: 'medium',
        evidence: candidate.code,
        message:
          'Candidate IOCTL is accessible with FILE_ANY_ACCESS; validate ACLs, symbolic links, and dispatch authorization.',
      })
    }
  }
  if (deviceInterfaces.some((item) => item.platform === 'windows')) {
    flags.push({
      id: 'windows.device_interface.exposed',
      severity: 'medium',
      message:
        'Windows device path or DOS-device link strings were found; confirm the intended access boundary.',
    })
  }
  for (const primitive of riskyPrimitives.filter((item) => item.severity === 'high')) {
    flags.push({
      id: primitive.id,
      severity: primitive.severity,
      evidence: primitive.value,
      message:
        'High-risk kernel primitive was found in static evidence; downstream xref review should bound its callers.',
    })
  }
  const license = moduleMetadata.find((item) => item.key === 'license')?.value
  if (license && !/\bGPL\b/i.test(String(license))) {
    flags.push({
      id: 'linux.module.license.non_gpl',
      severity: 'info',
      evidence: license,
      message:
        'Linux module license is not obviously GPL; kernel taint and symbol restrictions may affect runtime triage.',
    })
  }
  return uniqueBy(flags, (item) => `${item.id}:${item.evidence ?? ''}`).slice(0, 160)
}

function buildRiskSummary(
  riskFlags: Array<Record<string, any>>,
  riskyPrimitives: Array<Record<string, unknown>>
) {
  const severityRank: Record<string, number> = { info: 1, low: 2, medium: 3, high: 4, critical: 5 }
  const highest = riskFlags.reduce((current, item) => {
    return (severityRank[String(item.severity)] ?? 0) > (severityRank[current] ?? 0)
      ? String(item.severity)
      : current
  }, 'info')
  return {
    highest_severity: highest,
    risk_flag_count: riskFlags.length,
    high_risk_primitive_count: riskyPrimitives.filter((item) => item.severity === 'high').length,
    candidate_only: true,
    needs_xref_correlation: riskFlags.length > 0 || riskyPrimitives.length > 0,
  }
}

function buildEvidenceSummary(
  inventory: Omit<KernelDriverSurfaceInventory, 'evidence_summary' | 'workflow_handoff' | 'summary'>
) {
  return {
    schema: 'rikune.kernel_driver_surface.evidence_summary.v1',
    format: inventory.format,
    platform: inventory.platform,
    confidence: inventory.confidence,
    evidence_count: inventory.evidence.length,
    ioctl_candidate_count: inventory.ioctl_candidates.length,
    device_interface_count: inventory.device_interfaces.length,
    module_metadata_count: inventory.module_metadata.length,
    risky_primitive_count: inventory.risky_primitives.length,
    risk_flag_count: inventory.risk_flags.length,
    artifact_type: KERNEL_DRIVER_SURFACE_ARTIFACT_TYPE,
  }
}

function buildWorkflowHandoff(inventory: KernelDriverSurfaceInventory): Record<string, unknown> {
  return {
    schema: 'rikune.kernel_driver_surface.workflow_handoff.v1',
    handoff_mode: 'driver_surface_inventory_to_xref_and_runtime_plan',
    artifact_contract: {
      consumes: ['sample'],
      produces: [KERNEL_DRIVER_SURFACE_ARTIFACT_TYPE],
      mime: 'application/json',
      expected_consumers: KERNEL_DRIVER_FOLLOW_UP_TOOLS,
    },
    routing: [
      {
        goal: 'correlate IOCTL constants, dispatch names, and risky primitives with callsites',
        next_tools: ['code.xrefs.analyze', 'analysis.evidence.graph', 'artifact.read'],
      },
      {
        goal: 'review PE driver imports, load config, and mitigation metadata',
        next_tools: ['pe.structure.analyze', 'pe.imports.extract', 'pe.security.profile'],
      },
      {
        goal: 'review Linux module metadata, ELF symbols, and native object layout',
        next_tools: [
          'linux.binary.inventory',
          'native.object.inventory',
          'native.debug.types.inventory',
        ],
      },
      {
        goal: 'prepare opt-in runtime plan without loading driver/module by default',
        next_tools: ['windows.runtime.plan', 'linux.runtime.plan'],
      },
    ],
    dynamic_boundary: {
      activation_boundary: 'result-scoped',
      sample_execution_allowed: false,
      driver_load_allowed: false,
      kernel_module_load_allowed: false,
      device_open_allowed: false,
      ioctl_send_allowed: false,
      syscall_allowed: false,
      kernel_probe_allowed: false,
      debugger_allowed: false,
      external_tool_allowed: false,
      network_allowed: false,
      mutation_allowed: false,
      driver_loaded_by_tool: false,
      kernel_module_inserted_by_tool: false,
      device_opened_by_tool: false,
      ioctl_sent_by_tool: false,
    },
    evidence_summary: inventory.evidence_summary,
  }
}

function buildSummary(
  inventory: Omit<KernelDriverSurfaceInventory, 'summary' | 'workflow_handoff'>
): string {
  return `${inventory.format}: ${inventory.ioctl_candidates.length} IOCTL candidate(s), ${inventory.device_interfaces.length} interface hint(s), ${inventory.dispatch_hints.length} dispatch hint(s), ${inventory.module_metadata.length} module metadata item(s), ${inventory.risky_primitives.length} risky primitive hint(s).`
}

export function buildKernelDriverSurfaceInventoryFromBuffer(
  data: Buffer,
  options: BuildOptions = {}
): KernelDriverSurfaceInventory {
  const maxReadBytes = clampMaxReadBytes(options.maxReadBytes)
  const preview = data.subarray(0, Math.min(data.length, maxReadBytes))
  const container = detectContainer(preview, maxReadBytes, options)
  const strings = extractBinaryStrings(preview)
  const evidence = collectPatternEvidence(strings)
  const ioctlCandidates = decodeIoctlCandidates(preview)
  const deviceInterfaces = collectDeviceInterfaces(strings)
  const dispatchHints = collectDispatchHints(strings, evidence)
  const moduleMetadata = collectModuleMetadata(strings)
  const riskyPrimitives = collectRiskyPrimitives(strings)
  const platform = determinePlatform(container, evidence, moduleMetadata, ioctlCandidates)
  const detected = detectFormat(platform, container, evidence, ioctlCandidates, moduleMetadata)
  const riskFlags = buildRiskFlags(
    preview,
    maxReadBytes,
    ioctlCandidates,
    moduleMetadata,
    riskyPrimitives,
    deviceInterfaces
  )
  const riskSummary = buildRiskSummary(riskFlags, riskyPrimitives)

  const base = {
    sample_id: options.sampleId,
    filename: options.filename,
    format: detected.format,
    platform,
    detected_by: detected.detectedBy,
    confidence: detected.confidence,
    size: options.size ?? data.length,
    preview_size: preview.length,
    container,
    evidence,
    windows_surface: buildWindowsSurface(
      evidence,
      ioctlCandidates,
      deviceInterfaces,
      riskyPrimitives
    ),
    linux_surface: buildLinuxSurface(evidence, moduleMetadata, deviceInterfaces, riskyPrimitives),
    ioctl_candidates: ioctlCandidates,
    device_interfaces: deviceInterfaces,
    dispatch_hints: dispatchHints,
    module_metadata: moduleMetadata,
    risky_primitives: riskyPrimitives,
    risk_flags: riskFlags,
    risk_summary: riskSummary,
    policy: {
      passive: true,
      no_execute: true,
      no_driver_load: true,
      no_kernel_module_load: true,
      no_device_open: true,
      no_ioctl_send: true,
      no_syscall: true,
      no_kernel_probe: true,
      no_debugger: true,
      no_external_tool: true,
      no_network: true,
      no_mutation: true,
    },
    recommended_next_tools: KERNEL_DRIVER_FOLLOW_UP_TOOLS,
    next_actions: [
      'Use code.xrefs.analyze to map IOCTL constants and risky primitives to dispatch paths.',
      'Use PE/Linux/object inventory tools for section, import, symbol, and module metadata correlation.',
      'Keep any runtime driver/module loading or IOCTL probing behind explicit isolated runtime planning.',
    ],
    quality_gates: {
      passive_static_inventory: true,
      sample_executed_by_tool: false,
      driver_loaded_by_tool: false,
      kernel_module_inserted_by_tool: false,
      device_opened_by_tool: false,
      ioctl_sent_by_tool: false,
      syscall_invoked_by_tool: false,
      kernel_probe_started_by_tool: false,
      debugger_started_by_tool: false,
      external_tool_invoked_by_tool: false,
      network_used_by_tool: false,
      mutation_performed: false,
    },
  } satisfies Omit<
    KernelDriverSurfaceInventory,
    'summary' | 'workflow_handoff' | 'evidence_summary'
  >

  const withEvidence = {
    ...base,
    evidence_summary: buildEvidenceSummary(base),
  } satisfies Omit<KernelDriverSurfaceInventory, 'summary' | 'workflow_handoff'>

  const inventory: KernelDriverSurfaceInventory = {
    ...withEvidence,
    summary: buildSummary(withEvidence),
    workflow_handoff: {},
  }
  inventory.workflow_handoff = buildWorkflowHandoff(inventory)
  return inventory
}

export function createKernelDriverSurfaceInventoryHandler(deps: Partial<PluginToolDeps> = {}) {
  return async (args: unknown): Promise<WorkerResult> => {
    const started = Date.now()
    try {
      const input = KernelDriverSurfaceInventoryInputSchema.parse(args)
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
        const inventory = buildKernelDriverSurfaceInventoryFromBuffer(buffer, {
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
                KERNEL_DRIVER_SURFACE_ARTIFACT_TYPE,
                'kernel-driver-surface',
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
