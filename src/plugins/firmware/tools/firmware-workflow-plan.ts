import { z } from 'zod'
import type { ToolDefinition, WorkerResult } from '../../../types.js'

const TOOL_NAME = 'firmware.workflow.plan'

export const FirmwareWorkflowPlanInputSchema = z
  .object({
    sample_id: z.string().optional(),
    signatures: z.array(z.record(z.string(), z.any())).optional().default([]),
    firmware_scan: z.any().optional(),
    container_inventory: z.any().optional(),
    package_inventory: z.any().optional(),
    architecture_hint: z.string().optional(),
    goals: z.array(z.string()).optional().default([]),
  })
  .passthrough()

export const FirmwareWorkflowPlanOutputSchema = z.object({
  ok: z.boolean(),
  data: z.record(z.string(), z.any()).optional(),
  errors: z.array(z.string()).optional(),
  metrics: z.object({ elapsed_ms: z.number(), tool: z.string() }).optional(),
})

export const firmwareWorkflowPlanToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Build a passive firmware/IoT workflow plan from firmware signatures, filesystem hints, package inventory, and architecture hints. It recommends SBOM and Qiling handoffs without extracting, mounting, or emulating firmware by default.',
  inputSchema: FirmwareWorkflowPlanInputSchema,
  outputSchema: FirmwareWorkflowPlanOutputSchema,
  aspects: {
    formats: ['firmware', 'uimage', 'fit', 'dtb', 'itb', 'initramfs', 'squashfs', 'jffs2', 'ubi'],
    platforms: ['embedded', 'linux'],
    architectures: ['arm', 'arm64', 'mips', 'mipsel', 'ppc', 'riscv', 'x86', 'x64'],
    execution: ['static', 'triage', 'correlation'],
    safety: ['passive', 'no_installer_execution', 'no_auto_mount', 'no_live_sample_by_default'],
    capabilities: ['firmware-workflow', 'filesystem-plan', 'sbom-handoff', 'emulation-handoff'],
    evidence: [
      'signatures',
      'filesystem',
      'nested-binaries',
      'package-metadata',
      'workflow',
      'provenance',
    ],
  },
  artifacts: [
    {
      type: 'firmware_workflow_plan',
      description: 'Passive firmware filesystem, SBOM, and emulation handoff workflow plan',
    },
  ],
  evidence: [
    { category: 'signatures', artifactTypes: ['firmware_workflow_plan'] },
    { category: 'filesystem', artifactTypes: ['firmware_workflow_plan'] },
    { category: 'provenance', artifactTypes: ['firmware_workflow_plan'] },
  ],
  workflowRecipes: [
    {
      id: 'firmware.iot.passive-workflow',
      title: 'Firmware IoT passive workflow',
      startsWith: ['firmware.scan', 'container.structure.analyze', 'firmware.workflow.plan'],
      nextTools: [
        'firmware.entropy',
        'linux.package.inventory',
        'sbom.provenance.graph',
        'qiling.inspect',
      ],
      requiredArtifacts: ['firmware_scan', 'container_structure', 'linux_package_inventory'],
      producesArtifacts: ['firmware_workflow_plan'],
      evidence: ['signatures', 'filesystem', 'package-metadata', 'workflow', 'provenance'],
      safety: ['passive', 'no_installer_execution', 'no_auto_mount', 'no_live_sample_by_default'],
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

export function buildFirmwareWorkflowPlan(rawInput: unknown) {
  const input = FirmwareWorkflowPlanInputSchema.parse(rawInput)
  const text = [
    stringify(input.signatures),
    stringify(input.firmware_scan),
    stringify(input.container_inventory),
    stringify(input.package_inventory),
    input.goals.join('\n'),
  ].join('\n')
  const filesystemHints = uniqueMatches(
    text,
    /\b(?:squashfs|cramfs|jffs2|ubifs|ubi|romfs|cpio|initramfs|rootfs|filesystem)\b/gi
  )
  const kernelHints = uniqueMatches(text, /\b(?:uImage|zImage|vmlinuz|kernel|\.ko|module)\b/gi)
  const initScriptHints = uniqueMatches(
    text,
    /(?:\/?etc\/init\.d\/[A-Za-z0-9_.-]+|rcS|inittab|systemd|busybox)/gi
  )
  const packageHints = uniqueMatches(text, /\b(?:opkg|dpkg|rpm|apk|ipk|deb|package)\b/gi)
  const architecture =
    input.architecture_hint ??
    uniqueMatches(text, /\b(?:arm64|aarch64|arm|mipsel|mips|riscv|ppc|x86_64|x64|x86)\b/gi)[0] ??
    null

  return {
    result_mode: 'firmware_workflow_plan',
    sample_id: input.sample_id ?? null,
    architecture_hint: architecture,
    passive_findings: {
      filesystem_hints: filesystemHints,
      kernel_hints: kernelHints,
      init_script_hints: initScriptHints,
      package_hints: packageHints,
    },
    workflow_steps: [
      {
        tool: 'firmware.scan',
        purpose: 'Identify embedded firmware signatures and filesystem offsets.',
        mode: 'passive',
      },
      {
        tool: 'firmware.entropy',
        purpose: 'Review packed or compressed regions before any extraction.',
        mode: 'passive',
      },
      {
        tool: 'container.structure.analyze',
        purpose: 'Inventory carved or provided archives without mounting or executing them.',
        mode: 'passive',
      },
      {
        tool: 'linux.package.inventory',
        purpose: 'Inventory firmware package metadata and maintainer scripts without installing.',
        mode: 'passive',
      },
      {
        tool: 'sbom.provenance.graph',
        purpose: 'Merge firmware package, filesystem, and binary hints into SBOM provenance.',
        mode: 'passive',
      },
      {
        tool: 'qiling.inspect',
        purpose: 'Check optional Qiling readiness only after analyst opt-in and rootfs selection.',
        mode: 'readiness_only',
      },
    ],
    qiling_handoff: {
      status: 'plan_only',
      recommended_backend: 'qiling',
      requires_rootfs: true,
      requires_explicit_opt_in: true,
      architecture,
    },
    sbom_handoff: {
      tool: 'sbom.provenance.graph',
      evidence_sources: ['firmware_scan', 'container_structure', 'linux_package_inventory'],
    },
    recommended_next_tools: [
      'firmware.scan',
      'firmware.entropy',
      'container.structure.analyze',
      'linux.package.inventory',
      'sbom.provenance.graph',
      'qiling.inspect',
    ],
    safety_notes: [
      'No extraction, mount, package install, kernel/module load, Qiling emulation, or network access is performed.',
    ],
  }
}

export function createFirmwareWorkflowPlanHandler() {
  return async (args: unknown): Promise<WorkerResult> => ({
    ok: true,
    data: buildFirmwareWorkflowPlan(args),
    metrics: { elapsed_ms: 0, tool: TOOL_NAME },
  })
}
