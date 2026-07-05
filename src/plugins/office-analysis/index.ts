/**
 * Office Analysis Plugin
 *
 * VBA macro extraction, OLE structure analysis, and malicious document detection
 * using oletools.
 */

import { defineTool, requireDatabase, requireWorkspaceManager, type Plugin } from '../sdk.js'
import {
  officeVbaExtractToolDefinition,
  createOfficeVbaExtractHandler,
} from './tools/office-vba-extract.js'
import {
  officeMacroDetectToolDefinition,
  createOfficeMacroDetectHandler,
} from './tools/office-macro-detect.js'
import {
  officeOleAnalyzeToolDefinition,
  createOfficeOleAnalyzeHandler,
} from './tools/office-ole-analyze.js'
import {
  officeBehaviorProfileToolDefinition,
  createOfficeBehaviorProfileHandler,
} from './tools/office-behavior-profile.js'
import {
  OFFICE_ANALYSIS_PLUGIN_ASPECTS,
  OFFICE_OLETOOLS_RUNTIME_POLICY,
} from './office-analysis-metadata.js'

const officeAnalysisPlugin: Plugin = {
  id: 'office-analysis',
  name: 'Office Analysis',
  executionDomain: 'static',
  aspects: OFFICE_ANALYSIS_PLUGIN_ASPECTS,
  runtimePolicy: OFFICE_OLETOOLS_RUNTIME_POLICY,
  surfaceRules: {
    tier: 1,
    activateOn: {
      fileTypes: [
        'office',
        'doc',
        'docx',
        'docm',
        'xls',
        'xlsx',
        'xlsm',
        'ppt',
        'pptx',
        'pptm',
        'rtf',
        'ole',
        'ooxml',
      ],
    },
    category: 'static-analysis',
    signalMap: {
      has_macros: 'vba_macros',
      has_vba: 'vba_macros',
      macro: 'vba_macros',
      malicious_document: 'vba_macros',
    },
  },
  description:
    'Passive Office, VBA macro, Excel macro, OLE, OOXML, malicious document, and static-only behavior profile analysis via oletools',
  version: '1.0.0',
  systemDeps: [
    {
      type: 'python',
      name: 'oletools',
      importName: 'oletools',
      required: false,
      description: 'oletools — Office document analysis toolkit',
      dockerInstall: 'pip install oletools',
      dockerFeature: 'dynamic-python',
    },
  ],
  tools: [
    defineTool({
      ...officeVbaExtractToolDefinition,
      handler: (args, deps) =>
        createOfficeVbaExtractHandler(
          requireWorkspaceManager(deps, 'office.vba.extract'),
          requireDatabase(deps, 'office.vba.extract')
        )(args),
    }),
    defineTool({
      ...officeMacroDetectToolDefinition,
      handler: (args, deps) =>
        createOfficeMacroDetectHandler(
          requireWorkspaceManager(deps, 'office.macro.detect'),
          requireDatabase(deps, 'office.macro.detect')
        )(args),
    }),
    defineTool({
      ...officeOleAnalyzeToolDefinition,
      handler: (args, deps) =>
        createOfficeOleAnalyzeHandler(
          requireWorkspaceManager(deps, 'office.ole.analyze'),
          requireDatabase(deps, 'office.ole.analyze')
        )(args),
    }),
    defineTool({
      ...officeBehaviorProfileToolDefinition,
      handler: (args) => createOfficeBehaviorProfileHandler()(args),
    }),
  ],
  register(server, deps) {
    const { workspaceManager: wm, database: db } = deps

    server.registerTool(officeVbaExtractToolDefinition, createOfficeVbaExtractHandler(wm, db))
    server.registerTool(officeMacroDetectToolDefinition, createOfficeMacroDetectHandler(wm, db))
    server.registerTool(officeOleAnalyzeToolDefinition, createOfficeOleAnalyzeHandler(wm, db))
    server.registerTool(officeBehaviorProfileToolDefinition, createOfficeBehaviorProfileHandler())

    return [
      'office.vba.extract',
      'office.macro.detect',
      'office.ole.analyze',
      'office.behavior.profile',
    ]
  },
}

export default officeAnalysisPlugin
