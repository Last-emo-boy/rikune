/**
 * Office Analysis Plugin
 *
 * VBA macro extraction, OLE structure analysis, and malicious document detection
 * using oletools.
 */

import type { Plugin } from '../sdk.js'
import { officeVbaExtractToolDefinition, createOfficeVbaExtractHandler } from './tools/office-vba-extract.js'
import { officeMacroDetectToolDefinition, createOfficeMacroDetectHandler } from './tools/office-macro-detect.js'
import { officeOleAnalyzeToolDefinition, createOfficeOleAnalyzeHandler } from './tools/office-ole-analyze.js'

const officeAnalysisPlugin: Plugin = {
  id: 'office-analysis',
  name: 'Office Analysis',
  executionDomain: 'static',
  surfaceRules: {
    tier: 1,
    activateOn: { fileTypes: ['office', 'doc', 'xls'] },
    category: 'static-analysis',
    signalMap: {
      'has_macros': 'vba_macros',
      'has_vba': 'vba_macros',
    },
  },
  description: 'VBA macro extraction, OLE structure analysis, and malicious Office document detection via oletools',
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
  register(server, deps) {
    const { workspaceManager: wm, database: db } = deps

    server.registerTool(officeVbaExtractToolDefinition, createOfficeVbaExtractHandler(wm, db))
    server.registerTool(officeMacroDetectToolDefinition, createOfficeMacroDetectHandler(wm, db))
    server.registerTool(officeOleAnalyzeToolDefinition, createOfficeOleAnalyzeHandler(wm, db))

    return ['office.vba.extract', 'office.macro.detect', 'office.ole.analyze']
  },
}

export default officeAnalysisPlugin
