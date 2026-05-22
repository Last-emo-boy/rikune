import { definePlugin, defineTool } from '../sdk.js'
import {
  buildBackendPlanAspects,
  createBackendPlanHandler,
  createBackendPlanToolDefinition,
  type BackendPlanSpec,
} from '../backend-plan.js'

const spec: BackendPlanSpec = {
  pluginId: 'remill',
  toolName: 'remill.lift.plan',
  title: 'Remill LLVM lifting plan',
  description:
    'Build a passive Remill integration plan for lifting machine code to LLVM bitcode without running Remill, decoding a live target, or executing the sample.',
  backendName: 'Remill',
  formats: ['pe', 'elf', 'macho', 'firmware', 'shellcode', 'object', 'static-lib'],
  platforms: ['windows', 'linux', 'macos', 'embedded', 'cross-platform'],
  architectures: ['x86', 'x64', 'arm', 'arm64', 'sparc', 'aarch64'],
  capabilities: [
    'llvm-bitcode-lifting',
    'instruction-semantics',
    'cross-backend-comparison',
    'decompiler-preprocessing',
    'workflow-routing',
  ],
  evidence: ['structure', 'symbols', 'behavior', 'artifact'],
  artifactType: 'remill_lift_plan',
  category: 'reverse-engineering',
  recipe: {
    id: 'remill.llvm.lift-plan',
    title: 'Remill LLVM lifting planning',
    description:
      'Plan a Remill-backed lift-to-LLVM workflow from existing function, architecture, and CFG evidence before optional comparison with rev.ng, Ghidra, and GTIRB.',
    startsWith: ['remill.lift.plan', 'code.function.disassemble', 'pe.structure.analyze'],
    nextTools: [
      'revng.pipeline.plan',
      'gtirb.ir.plan',
      'ghidra.analyze',
      'analysis.evidence.graph',
    ],
    requiredArtifacts: ['function_disassembly', 'code_cfg', 'pe_structure', 'elf_structure'],
    producesArtifacts: ['remill_lift_plan', 'llvm_bitcode_lift_plan', 'instruction_semantics_plan'],
    evidence: ['structure', 'symbols', 'behavior', 'workflow', 'provenance'],
    safety: ['passive', 'no_live_sample_by_default', 'no_network_by_default'],
  },
  defaultStages: [
    {
      id: 'lift-scope',
      title: 'Lift scope selection',
      purpose:
        'Select bounded functions, shellcode windows, architecture tags, and memory-map assumptions from existing artifacts.',
      inputs: ['function_disassembly', 'code_cfg', 'pe_structure', 'elf_structure'],
      outputs: ['remill_scope_plan'],
      safety: ['metadata_only'],
    },
    {
      id: 'semantics-plan',
      title: 'Instruction semantics plan',
      purpose:
        'Prepare architecture, ABI, calling convention, and unsupported-instruction expectations for future Remill lifting.',
      inputs: ['remill_scope_plan'],
      outputs: ['instruction_semantics_plan'],
      safety: ['plan_only'],
    },
    {
      id: 'llvm-handoff',
      title: 'LLVM bitcode handoff plan',
      purpose: 'Plan comparison and downstream analysis for future lifted LLVM bitcode artifacts.',
      inputs: ['instruction_semantics_plan'],
      outputs: ['llvm_bitcode_lift_plan', 'cross_backend_lift_diff'],
      safety: ['requires_bounded_worker_before_execution'],
    },
  ],
  optionalToolCandidates: [
    {
      id: 'lifting-bits-remill',
      name: 'lifting-bits/remill',
      source: 'https://github.com/lifting-bits/remill',
      role: 'Machine-code-to-LLVM-bitcode lifting backend for bounded static reverse-engineering workflows.',
      readiness: 'optional_external',
      notes: [
        'Pin the Remill build and supported architecture matrix before adding an execution worker.',
        'Use existing disassembly ranges and local artifacts only; do not run from readiness paths.',
      ],
    },
  ],
  recommendedNextTools: [
    'code.function.disassemble',
    'revng.pipeline.plan',
    'gtirb.ir.plan',
    'analysis.evidence.graph',
  ],
  safetyNotes: [
    'Remill planning does not start a lifter, loader, emulator, solver, debugger, or network operation.',
    'Future workers must require bounded ranges and deterministic lift-output fixtures.',
  ],
}

const remillPlugin = definePlugin({
  id: 'remill',
  name: 'Remill Lift Plan',
  executionDomain: 'static',
  aspects: buildBackendPlanAspects(spec),
  surfaceRules: {
    tier: 3,
    activateOn: {
      fileTypes: ['pe', 'elf', 'macho', 'firmware', 'shellcode', 'object', 'static-lib'],
      findings: ['binary-lifting', 'instruction-semantics', 'low-decompiler-confidence'],
    },
    category: 'reverse-engineering',
  },
  description: 'Passive Remill LLVM bitcode lifting and instruction semantics planning.',
  version: '1.0.0',
  configSchema: [
    {
      envVar: 'REMILL_PATH',
      description: 'Optional Remill binary or wrapper path for a future bounded worker',
      required: false,
    },
  ],
  systemDeps: [
    {
      type: 'file',
      name: 'remill',
      target: '$REMILL_PATH',
      envVar: 'REMILL_PATH',
      required: false,
      description: 'Optional Remill lifter or wrapper',
      dockerInstall: 'Provide a pinned Remill build; not installed by default',
      dockerFeature: 'remill',
    },
  ],
  tools: [
    defineTool({
      ...createBackendPlanToolDefinition(spec),
      handler: createBackendPlanHandler(spec),
    }),
  ],
})

export default remillPlugin
