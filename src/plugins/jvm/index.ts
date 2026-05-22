/**
 * JVM Bytecode Plugin
 *
 * Passive inventory for JAR, CLASS, WAR, AAR, JMOD, and Kotlin metadata.
 * It does not execute bytecode or launch Java decompilers.
 */

import { definePlugin, defineTool } from '../sdk.js'
import {
  createJvmStructureAnalyzeHandler,
  jvmStructureAnalyzeToolDefinition,
} from './tools/jvm-structure-analyze.js'

const jvmPlugin = definePlugin({
  id: 'jvm',
  name: 'JVM Bytecode Inventory',
  executionDomain: 'static',
  aspects: {
    formats: ['jar', 'class', 'war', 'aar', 'jmod', 'kotlin-metadata'],
    platforms: ['jvm', 'android'],
    execution: ['static', 'triage', 'decompilation'],
    safety: ['passive', 'no_live_sample_by_default'],
    capabilities: ['manifest', 'classes', 'dependencies', 'decompile-plan', 'routing'],
    evidence: ['manifest', 'package-metadata', 'strings', 'provenance'],
  },
  surfaceRules: {
    tier: 1,
    activateOn: {
      fileTypes: ['jar', 'class', 'war', 'aar', 'jmod', 'kotlin-metadata', 'jvm', 'java'],
    },
    category: 'static-analysis',
  },
  description:
    'Passive JVM bytecode and archive inventory for JAR, CLASS, WAR, AAR, JMOD, and Kotlin metadata.',
  version: '1.0.0',
  tools: [
    defineTool({
      ...jvmStructureAnalyzeToolDefinition,
      handler: (args, deps) => createJvmStructureAnalyzeHandler(deps)(args as never),
    }),
  ],
})

export default jvmPlugin
