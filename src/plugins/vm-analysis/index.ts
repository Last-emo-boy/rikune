/**
 * VM Analysis & Symbolic Plugin
 *
 * Virtual-machine protection analysis (detection, opcode extraction, disassembler
 * building, emulation, semantic diffing) and symbolic/constraint solving
 * (constraint extraction, SMT solving, keygen synthesis, MBA simplification).
 */

import type { Plugin } from '../sdk.js'
import { vmDetectToolDefinition, createVmDetectHandler } from './tools/vm-detect.js'
import { vmPatternAnalyzeToolDefinition, createVmPatternAnalyzeHandler } from './tools/vm-pattern-analyze.js'
import { vmOpcodeExtractToolDefinition, createVmOpcodeExtractHandler } from './tools/vm-opcode-extract.js'
import { vmDisasmBuildToolDefinition, createVmDisasmBuildHandler } from './tools/vm-disasm-build.js'
import { vmEmulateToolDefinition, createVmEmulateHandler } from './tools/vm-emulate.js'
import { vmSemanticDiffToolDefinition, createVmSemanticDiffHandler } from './tools/vm-semantic-diff.js'
import { constraintExtractToolDefinition, createConstraintExtractHandler } from './tools/constraint-extract.js'
import { smtSolveToolDefinition, createSmtSolveHandler } from './tools/smt-solve.js'
import { keygenSynthesizeToolDefinition, createKeygenSynthesizeHandler } from './tools/keygen-synthesize.js'
import { mbaSimplifyToolDefinition, createMbaSimplifyHandler } from './tools/mba-simplify.js'

const vmAnalysisPlugin: Plugin = {
  id: 'vm-analysis',
  name: 'VM Analysis & Symbolic',
  description: 'Virtual-machine protection analysis, constraint extraction, SMT solving, keygen synthesis, and MBA simplification',
  version: '1.0.0',
  resources: { workers: 'workers' },
  register(server, deps) {
    const { workspaceManager: wm, database: db } = deps

    server.registerTool(vmDetectToolDefinition, createVmDetectHandler(wm, db))
    server.registerTool(vmPatternAnalyzeToolDefinition, createVmPatternAnalyzeHandler(wm, db))
    server.registerTool(vmOpcodeExtractToolDefinition, createVmOpcodeExtractHandler(wm, db))
    server.registerTool(vmDisasmBuildToolDefinition, createVmDisasmBuildHandler(wm, db))
    server.registerTool(vmEmulateToolDefinition, createVmEmulateHandler(wm, db))
    server.registerTool(vmSemanticDiffToolDefinition, createVmSemanticDiffHandler(wm, db))
    server.registerTool(constraintExtractToolDefinition, createConstraintExtractHandler(wm, db))
    server.registerTool(smtSolveToolDefinition, createSmtSolveHandler(wm, db))
    server.registerTool(keygenSynthesizeToolDefinition, createKeygenSynthesizeHandler(wm, db))
    server.registerTool(mbaSimplifyToolDefinition, createMbaSimplifyHandler(wm, db))

    return [
      'vm.detect', 'vm.pattern.analyze', 'vm.opcode.extract',
      'vm.disasm.build', 'vm.emulate', 'vm.semantic.diff',
      'constraint.extract', 'smt.solve', 'keygen.synthesize', 'mba.simplify',
    ]
  },
}

export default vmAnalysisPlugin
