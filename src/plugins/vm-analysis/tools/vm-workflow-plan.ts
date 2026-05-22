import { z } from 'zod'
import type { ToolDefinition, WorkerResult } from '../../../types.js'

const TOOL_NAME = 'vm.workflow.plan'

export const vmWorkflowPlanInputSchema = z.object({
  sample_id: z.string().optional().describe('Optional sample ID used to annotate the plan'),
  findings: z.array(z.string()).optional().default([]),
  goals: z.array(z.string()).optional().default([]),
  include_solver_steps: z.boolean().optional().default(true),
})

export const vmWorkflowPlanOutputSchema = z.object({
  ok: z.boolean(),
  data: z.record(z.any()).optional(),
  warnings: z.array(z.string()).optional(),
  errors: z.array(z.string()).optional(),
  metrics: z.object({ elapsed_ms: z.number(), tool: z.string() }).optional(),
})

const workflowRecipe = {
  id: 'vm.symbolic.workflow',
  title: 'VM protection and symbolic solving workflow',
  startsWith: ['vm.detect', 'vm.workflow.plan'],
  nextTools: [
    'vm.pattern.analyze',
    'vm.opcode.extract',
    'vm.disasm.build',
    'vm.emulate',
    'constraint.extract',
    'smt.solve',
    'keygen.synthesize',
    'mba.simplify',
  ],
  requiredArtifacts: ['function_map', 'decompilation'],
  producesArtifacts: ['vm_workflow_plan', 'vm_detection', 'vm_emulation', 'smt_solution'],
  evidence: ['structure', 'behavior', 'workflow', 'provenance'],
  safety: ['passive'],
}

export const vmWorkflowPlanToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Build a passive VM-protection and symbolic-analysis workflow plan. It recommends the VM detection, opcode extraction, emulation, constraint extraction, SMT solving, keygen, and MBA simplification sequence without running solvers or emulators.',
  inputSchema: vmWorkflowPlanInputSchema,
  outputSchema: vmWorkflowPlanOutputSchema,
  aspects: {
    formats: ['pe', 'elf', 'macho', 'dotnet', 'shellcode'],
    platforms: ['windows', 'linux', 'macos', 'cross-platform'],
    execution: ['static', 'triage', 'emulation', 'correlation'],
    safety: ['passive'],
    capabilities: ['vm-detection', 'symbolic-workflow', 'constraint-solving', 'workflow-plan'],
    evidence: ['structure', 'behavior', 'workflow', 'provenance'],
  },
  artifacts: [{ type: 'vm_workflow_plan', description: 'Passive VM/symbolic workflow plan' }],
  evidence: [
    { category: 'workflow', artifactTypes: ['vm_workflow_plan'] },
    { category: 'provenance', artifactTypes: ['vm_workflow_plan'] },
  ],
  workflowRecipes: [workflowRecipe],
}

function includesAny(values: string[], needles: string[]): boolean {
  const normalized = values.map((value) => value.toLowerCase())
  return needles.some((needle) => normalized.some((value) => value.includes(needle)))
}

export function buildVmWorkflowPlan(input: z.infer<typeof vmWorkflowPlanInputSchema>) {
  const findings = input.findings ?? []
  const goals = input.goals ?? []
  const wantsSolver = input.include_solver_steps !== false
  const vmSignal = includesAny([...findings, ...goals], ['vm', 'virtual', 'opcode', 'dispatch'])
  const mbaSignal = includesAny([...findings, ...goals], ['mba', 'mixed boolean', 'arithmetic'])

  const steps = [
    {
      tool: 'vm.detect',
      purpose: 'Score functions for VM dispatcher and handler-table patterns.',
      required: true,
      consumes: ['function_map', 'decompilation'],
      produces: ['vm_detection'],
    },
    {
      tool: 'vm.pattern.analyze',
      purpose:
        'Inspect top candidates and classify dispatcher, handler, bytecode, and state roles.',
      required: vmSignal,
      consumes: ['vm_detection'],
      produces: ['vm_pattern_analysis'],
    },
    {
      tool: 'vm.opcode.extract',
      purpose: 'Extract opcode table and handler semantics from the candidate dispatcher.',
      required: vmSignal,
      consumes: ['vm_pattern_analysis'],
      produces: ['vm_opcode_table'],
    },
    {
      tool: 'vm.disasm.build',
      purpose: 'Build a VM bytecode disassembler from the opcode table.',
      required: false,
      consumes: ['vm_opcode_table'],
      produces: ['vm_disassembler'],
    },
    {
      tool: 'vm.emulate',
      purpose: 'Run bounded local VM-bytecode emulation on analyst-provided bytecode.',
      required: false,
      consumes: ['vm_opcode_table'],
      produces: ['vm_emulation'],
      limits: { max_steps: 100000, live_sample_execution: false },
    },
    {
      tool: 'constraint.extract',
      purpose: 'Extract symbolic constraints from a saved emulation trace.',
      required: wantsSolver,
      consumes: ['vm_emulation'],
      produces: ['constraint_extraction'],
    },
    {
      tool: 'smt.solve',
      purpose: 'Solve bounded Z3 constraints through the worker with timeout limits.',
      required: wantsSolver,
      consumes: ['constraint_extraction'],
      produces: ['smt_solution'],
      limits: { timeout_ms_max: 300000 },
    },
    {
      tool: 'keygen.synthesize',
      purpose: 'Generate a forward keygen candidate from solved or extracted constraints.',
      required: false,
      consumes: ['constraint_extraction'],
      produces: ['keygen_synthesis'],
    },
    {
      tool: 'mba.simplify',
      purpose: 'Simplify MBA expressions discovered in VM handlers or constraint formulas.',
      required: mbaSignal,
      consumes: ['constraint_extraction'],
      produces: ['mba_simplification'],
    },
  ]

  return {
    result_mode: 'vm_workflow_plan',
    sample_id: input.sample_id ?? null,
    findings,
    goals,
    workflow_recipe: workflowRecipe,
    steps,
    recommended_next_tools: steps.map((step) => step.tool),
    safety_notes: [
      'This planner does not execute the sample.',
      'Solver and emulation steps are bounded and require explicit later tool calls.',
      'No heavy solver dependency is loaded by this planning tool.',
    ],
  }
}

export function createVmWorkflowPlanHandler() {
  return async (args: z.infer<typeof vmWorkflowPlanInputSchema>): Promise<WorkerResult> => {
    const input = vmWorkflowPlanInputSchema.parse(args)
    return {
      ok: true,
      data: buildVmWorkflowPlan(input),
      metrics: { elapsed_ms: 0, tool: TOOL_NAME },
    }
  }
}

export const vmSymbolicWorkflowRecipe = workflowRecipe
