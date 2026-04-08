/**
 * Static Triage Plugin
 *
 * First-pass static analysis: runtime detection, packer identification,
 * capability triage, binary role profiling, crypto identification, etc.
 */

import type { Plugin } from '../sdk.js'
import { analysisContextLinkToolDefinition, createAnalysisContextLinkHandler } from '../../tools/analysis-context-link.js'
import { runtimeDetectToolDefinition, createRuntimeDetectHandler } from '../../tools/runtime-detect.js'
import { dotNetMetadataExtractToolDefinition, createDotNetMetadataExtractHandler } from '../../tools/dotnet-metadata-extract.js'
import { dotNetTypesListToolDefinition, createDotNetTypesListHandler } from '../../tools/dotnet-types-list.js'
import { packerDetectToolDefinition, createPackerDetectHandler } from '../../tools/packer-detect.js'
import { staticCapabilityTriageToolDefinition, createStaticCapabilityTriageHandler } from '../../tools/static-capability-triage.js'
import { compilerPackerDetectToolDefinition, createCompilerPackerDetectHandler } from '../../tools/compiler-packer-detect.js'
import { binaryRoleProfileToolDefinition, createBinaryRoleProfileHandler } from '../../tools/binary-role-profile.js'
import { cryptoIdentifyToolDefinition, createCryptoIdentifyHandler } from '../../tools/crypto-identify.js'
import { breakpointSmartToolDefinition, createBreakpointSmartHandler } from '../../tools/breakpoint-smart.js'
import { traceConditionToolDefinition, createTraceConditionHandler } from '../../tools/trace-condition.js'
import { dllExportProfileToolDefinition, createDllExportProfileHandler } from '../../tools/dll-export-profile.js'
import { comRoleProfileToolDefinition, createComRoleProfileHandler } from '../../tools/com-role-profile.js'
import { rustBinaryAnalyzeToolDefinition, createRustBinaryAnalyzeHandler } from '../../tools/rust-binary-analyze.js'
import { entropyAnalyzeToolDefinition, createEntropyAnalyzeHandler } from '../../tools/entropy-analyze.js'
import { obfuscationDetectToolDefinition, createObfuscationDetectHandler } from '../../tools/obfuscation-detect.js'
import { taintTrackToolDefinition, createTaintTrackHandler } from '../../tools/taint-track.js'

const staticTriagePlugin: Plugin = {
  id: 'static-triage',
  name: 'Static Triage',
  description: 'First-pass static analysis including runtime detection, packer ID, capability triage, binary profiling, crypto detection, entropy analysis, and obfuscation detection',
  version: '1.0.0',
  register(server, deps) {
    const { workspaceManager: wm, database: db, cacheManager: cm, jobQueue: jq } = deps

    server.registerTool(analysisContextLinkToolDefinition, createAnalysisContextLinkHandler(wm, db, cm, {}, jq))
    server.registerTool(runtimeDetectToolDefinition, createRuntimeDetectHandler(wm, db, cm))
    server.registerTool(dotNetMetadataExtractToolDefinition, createDotNetMetadataExtractHandler(wm, db, cm))
    server.registerTool(dotNetTypesListToolDefinition, createDotNetTypesListHandler(wm, db, cm))
    server.registerTool(packerDetectToolDefinition, createPackerDetectHandler(wm, db, cm))
    server.registerTool(staticCapabilityTriageToolDefinition, createStaticCapabilityTriageHandler(wm, db))
    server.registerTool(compilerPackerDetectToolDefinition, createCompilerPackerDetectHandler(wm, db))
    server.registerTool(binaryRoleProfileToolDefinition, createBinaryRoleProfileHandler(wm, db, cm, undefined, jq))
    server.registerTool(cryptoIdentifyToolDefinition, createCryptoIdentifyHandler(wm, db, cm, {}, jq))
    server.registerTool(breakpointSmartToolDefinition, createBreakpointSmartHandler(wm, db, cm))
    server.registerTool(traceConditionToolDefinition, createTraceConditionHandler(wm, db, cm))
    server.registerTool(dllExportProfileToolDefinition, createDllExportProfileHandler(wm, db, cm))
    server.registerTool(comRoleProfileToolDefinition, createComRoleProfileHandler(wm, db, cm))
    server.registerTool(rustBinaryAnalyzeToolDefinition, createRustBinaryAnalyzeHandler(wm, db, cm))
    server.registerTool(entropyAnalyzeToolDefinition, createEntropyAnalyzeHandler(wm, db, cm))
    server.registerTool(obfuscationDetectToolDefinition, createObfuscationDetectHandler(wm, db, cm))
    server.registerTool(taintTrackToolDefinition, createTaintTrackHandler(wm, db, cm))

    return [
      'analysis.context.link', 'runtime.detect',
      'dotnet.metadata.extract', 'dotnet.types.list',
      'packer.detect', 'static.capability.triage', 'compiler.packer.detect',
      'binary.role.profile', 'crypto.identify',
      'breakpoint.smart', 'trace.condition',
      'dll.export.profile', 'com.role.profile', 'rust.binary.analyze',
      'entropy.analyze', 'obfuscation.detect', 'taint.track',
    ]
  },
}

export default staticTriagePlugin
