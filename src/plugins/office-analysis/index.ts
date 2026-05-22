/**
 * Office Analysis Plugin
 *
 * VBA macro extraction, OLE structure analysis, and malicious document detection
 * using oletools.
 */

import type { Plugin } from '../sdk.js'
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

const officeAnalysisPlugin: Plugin = {
  id: 'office-analysis',
  name: 'Office Analysis',
  executionDomain: 'static',
  aspects: {
    formats: ['office', 'doc', 'docm', 'xls', 'xlsm', 'ppt', 'pptm', 'ole', 'ooxml'],
    platforms: ['windows', 'macos', 'cross-platform'],
    execution: ['static', 'triage'],
    safety: ['passive', 'no_live_sample_by_default'],
    capabilities: ['macro-analysis', 'ole-structure', 'vba-extraction', 'ioc-extraction'],
    evidence: ['structure', 'strings', 'behavior', 'network', 'filesystem', 'provenance'],
  },
  surfaceRules: {
    tier: 1,
    activateOn: { fileTypes: ['office', 'doc', 'docm', 'xls', 'xlsm', 'ppt', 'pptm', 'ole'] },
    category: 'static-analysis',
    signalMap: {
      has_macros: 'vba_macros',
      has_vba: 'vba_macros',
    },
  },
  description:
    'VBA macro extraction, OLE structure analysis, and malicious Office document detection via oletools',
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
