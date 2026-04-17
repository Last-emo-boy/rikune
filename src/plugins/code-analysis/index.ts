/**
 * Code Analysis Plugin
 *
 * Function listing, ranking, decompilation, disassembly, CFG, cross-references,
 * reconstruction, renaming, explanation, and module-level review.
 */

import type { Plugin } from '../sdk.js'
import { codeFunctionsListToolDefinition, createCodeFunctionsListHandler } from './tools/code-functions-list.js'
import { codeFunctionsRankToolDefinition, createCodeFunctionsRankHandler } from './tools/code-functions-rank.js'
import { codeFunctionsSmartRecoverToolDefinition, createCodeFunctionsSmartRecoverHandler } from './tools/code-functions-smart-recover.js'
import { codeFunctionsDefineToolDefinition, createCodeFunctionsDefineHandler } from './tools/code-functions-define.js'
import { codeFunctionsSearchToolDefinition, createCodeFunctionsSearchHandler } from './tools/code-functions-search.js'
import { codeXrefsAnalyzeToolDefinition, createCodeXrefsAnalyzeHandler } from './tools/code-xrefs-analyze.js'
import { codeFunctionDecompileToolDefinition, createCodeFunctionDecompileHandler } from './tools/code-function-decompile.js'
import { codeFunctionDisassembleToolDefinition, createCodeFunctionDisassembleHandler } from './tools/code-function-disassemble.js'
import { codeFunctionCFGToolDefinition, createCodeFunctionCFGHandler } from './tools/code-function-cfg.js'
import { codeFunctionsReconstructToolDefinition, createCodeFunctionsReconstructHandler } from './tools/code-functions-reconstruct.js'
import { codeFunctionRenamePrepareToolDefinition, createCodeFunctionRenamePrepareHandler } from './tools/code-function-rename-prepare.js'
import { codeFunctionExplainPrepareToolDefinition, createCodeFunctionExplainPrepareHandler } from './tools/code-function-explain-prepare.js'
import { codeFunctionExplainApplyToolDefinition, createCodeFunctionExplainApplyHandler } from './tools/code-function-explain-apply.js'
import { codeFunctionRenameApplyToolDefinition, createCodeFunctionRenameApplyHandler } from './tools/code-function-rename-apply.js'
import { codeReconstructExportToolDefinition, createCodeReconstructExportHandler } from './tools/code-reconstruct-export.js'
import { dotNetReconstructExportToolDefinition, createDotNetReconstructExportHandler } from './tools/dotnet-reconstruct-export.js'
import { codeReconstructPlanToolDefinition, createCodeReconstructPlanHandler } from './tools/code-reconstruct-plan.js'
import { codeModuleReviewPrepareToolDefinition, createCodeModuleReviewPrepareHandler } from './tools/code-module-review-prepare.js'
import { codeModuleReviewApplyToolDefinition, createCodeModuleReviewApplyHandler } from './tools/code-module-review-apply.js'

const codeAnalysisPlugin: Plugin = {
  id: 'code-analysis',
  name: 'Code Analysis',
  executionDomain: 'static',
  surfaceRules: { tier: 0, category: 'reverse-engineering' },
  description: 'Function listing, decompilation, disassembly, CFG, cross-references, reconstruction, renaming, explanation, and module review',
  version: '1.0.0',
  register(server, deps) {
    const { workspaceManager: wm, database: db, cacheManager: cm, jobQueue: jq } = deps

    server.registerTool(codeFunctionsListToolDefinition, createCodeFunctionsListHandler(wm, db))
    server.registerTool(codeFunctionsRankToolDefinition, createCodeFunctionsRankHandler(wm, db))
    server.registerTool(codeFunctionsSmartRecoverToolDefinition, createCodeFunctionsSmartRecoverHandler(wm, db, cm))
    server.registerTool(codeFunctionsDefineToolDefinition, createCodeFunctionsDefineHandler(wm, db))
    server.registerTool(codeFunctionsSearchToolDefinition, createCodeFunctionsSearchHandler(wm, db))
    server.registerTool(codeXrefsAnalyzeToolDefinition, createCodeXrefsAnalyzeHandler(wm, db, cm))
    server.registerTool(codeFunctionDecompileToolDefinition, createCodeFunctionDecompileHandler(wm, db))
    server.registerTool(codeFunctionDisassembleToolDefinition, createCodeFunctionDisassembleHandler(wm, db))
    server.registerTool(codeFunctionCFGToolDefinition, createCodeFunctionCFGHandler(wm, db))
    server.registerTool(codeFunctionsReconstructToolDefinition, createCodeFunctionsReconstructHandler(wm, db, cm))
    server.registerTool(codeFunctionRenamePrepareToolDefinition, createCodeFunctionRenamePrepareHandler(wm, db, cm))
    server.registerTool(codeFunctionExplainPrepareToolDefinition, createCodeFunctionExplainPrepareHandler(wm, db, cm))
    server.registerTool(codeFunctionExplainApplyToolDefinition, createCodeFunctionExplainApplyHandler(wm, db))
    server.registerTool(codeModuleReviewPrepareToolDefinition, createCodeModuleReviewPrepareHandler(wm, db, cm))
    server.registerTool(codeModuleReviewApplyToolDefinition, createCodeModuleReviewApplyHandler(wm, db))
    server.registerTool(codeFunctionRenameApplyToolDefinition, createCodeFunctionRenameApplyHandler(wm, db))
    server.registerTool(codeReconstructExportToolDefinition, createCodeReconstructExportHandler(wm, db, cm))
    server.registerTool(dotNetReconstructExportToolDefinition, createDotNetReconstructExportHandler(wm, db, cm))
    server.registerTool(codeReconstructPlanToolDefinition, createCodeReconstructPlanHandler(wm, db, cm))

    return [
      'code.functions.list', 'code.functions.rank', 'code.functions.smart.recover',
      'code.functions.define', 'code.functions.search', 'code.xrefs.analyze',
      'code.function.decompile', 'code.function.disassemble', 'code.function.cfg',
      'code.functions.reconstruct',
      'code.function.rename.prepare', 'code.function.rename.apply',
      'code.function.explain.prepare', 'code.function.explain.apply',
      'code.module.review.prepare', 'code.module.review.apply',
      'code.reconstruct.export', 'dotnet.reconstruct.export', 'code.reconstruct.plan',
    ]
  },
}

export default codeAnalysisPlugin
