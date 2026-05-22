import { definePlugin, defineTool } from '../sdk.js'
import {
  buildBackendPlanAspects,
  createBackendPlanHandler,
  createBackendPlanToolDefinition,
  type BackendPlanSpec,
} from '../backend-plan.js'

const spec: BackendPlanSpec = {
  pluginId: 'lief',
  toolName: 'lief.binary.plan',
  title: 'LIEF binary structure and transformation plan',
  description:
    'Build a passive LIEF integration plan for binary structure, signatures, relocation, import/export, and safe transformation workflows without parsing or modifying the sample through LIEF.',
  backendName: 'LIEF',
  formats: ['pe', 'elf', 'macho', 'coff', 'object', 'static-lib', 'firmware'],
  platforms: ['windows', 'linux', 'macos', 'ios', 'embedded', 'cross-platform'],
  architectures: ['x86', 'x64', 'arm', 'arm64', 'mips', 'ppc', 'riscv'],
  capabilities: [
    'binary-format-abstraction',
    'import-export-correlation',
    'signature-and-header-review',
    'relocation-review',
    'patch-plan',
    'workflow-routing',
  ],
  evidence: ['structure', 'symbols', 'imports', 'exports', 'certificates', 'artifact'],
  artifactType: 'lief_binary_plan',
  category: 'reverse-engineering',
  recipe: {
    id: 'lief.binary.structure-plan',
    title: 'LIEF binary structure and transformation planning',
    description:
      'Plan LIEF-backed cross-format structure review and bounded transformation workflows from existing PE/ELF/Mach-O evidence without starting LIEF by default.',
    startsWith: ['lief.binary.plan', 'pe.structure.analyze', 'elf.structure.analyze'],
    nextTools: ['pe.signature.verify', 'native.object.inventory', 'sbom.provenance.graph'],
    requiredArtifacts: ['pe_structure', 'elf_structure', 'macho_structure'],
    producesArtifacts: ['lief_binary_plan', 'binary_transformation_plan'],
    evidence: [
      'structure',
      'symbols',
      'imports',
      'exports',
      'certificates',
      'workflow',
      'provenance',
    ],
    safety: ['passive', 'no_live_sample_by_default', 'no_network_by_default'],
  },
  defaultStages: [
    {
      id: 'format-inventory',
      title: 'Format inventory',
      purpose:
        'Correlate existing PE, ELF, Mach-O, object, certificate, and package evidence before selecting a LIEF-backed worker.',
      inputs: ['pe_structure', 'elf_structure', 'macho_structure', 'native_object_inventory'],
      outputs: ['lief_format_inventory'],
      safety: ['metadata_only'],
    },
    {
      id: 'mutation-boundary',
      title: 'Mutation boundary plan',
      purpose:
        'Separate read-only parsing, header normalization, import/export review, and any future transformation request.',
      inputs: ['lief_format_inventory'],
      outputs: ['binary_transformation_plan'],
      safety: ['plan_only'],
    },
    {
      id: 'cross-format-check',
      title: 'Cross-format consistency plan',
      purpose:
        'Plan comparison between LIEF, native structure analyzers, Rizin/Ghidra, and signing metadata.',
      inputs: ['lief_format_inventory', 'binary_transformation_plan'],
      outputs: ['lief_cross_format_diff'],
      safety: ['requires_bounded_worker_before_execution'],
    },
  ],
  optionalToolCandidates: [
    {
      id: 'lief-project-lief',
      name: 'lief-project/LIEF',
      source: 'https://github.com/lief-project/LIEF',
      role: 'Cross-format executable parsing, abstraction, and transformation backend.',
      readiness: 'optional_external',
      notes: [
        'Start with read-only parsing workers; treat mutation workflows as a separate explicit opt-in.',
        'Pin the Python wheel or container image before enabling backend invocation.',
      ],
    },
  ],
  recommendedNextTools: [
    'pe.structure.analyze',
    'elf.structure.analyze',
    'macho.structure.analyze',
    'pe.signature.verify',
  ],
  safetyNotes: [
    'This planner does not modify binaries or invoke LIEF.',
    'Future mutation workers must require explicit patch intent, output paths, and fixture-based validation.',
  ],
}

const liefPlugin = definePlugin({
  id: 'lief',
  name: 'LIEF Binary Plan',
  executionDomain: 'static',
  aspects: buildBackendPlanAspects(spec),
  surfaceRules: {
    tier: 3,
    activateOn: {
      fileTypes: ['pe', 'elf', 'macho', 'coff', 'object', 'static-lib', 'firmware'],
      findings: ['cross-format-check', 'patch-plan', 'signature', 'relocation'],
    },
    category: 'reverse-engineering',
  },
  description:
    'Passive LIEF binary structure and transformation planning across PE, ELF, Mach-O, and object formats.',
  version: '1.0.0',
  configSchema: [
    {
      envVar: 'LIEF_PYTHON',
      description: 'Optional Python interpreter with LIEF installed for a future bounded worker',
      required: false,
      defaultValue: 'python3',
    },
  ],
  systemDeps: [
    {
      type: 'python',
      name: 'lief',
      importName: 'lief',
      required: false,
      description: 'LIEF executable format parsing and transformation library',
      dockerInstall: 'pip install lief or provide a pinned wheel',
      dockerFeature: 'dynamic-python',
      extraEnv: { LIEF_PYTHON: 'python3' },
    },
  ],
  tools: [
    defineTool({
      ...createBackendPlanToolDefinition(spec),
      handler: createBackendPlanHandler(spec),
    }),
  ],
})

export default liefPlugin
