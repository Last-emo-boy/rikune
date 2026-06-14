/**
 * JVM Bytecode Plugin
 *
 * Passive inventory for JAR, CLASS, WAR, AAR, JMOD, and Kotlin metadata.
 * It does not execute bytecode or launch Java decompilers.
 */

import { definePlugin, defineTool } from '../sdk.js'
import {
  JVM_STRUCTURE_EVIDENCE,
  JVM_STRUCTURE_SAFETY,
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
    safety: JVM_STRUCTURE_SAFETY,
    capabilities: [
      'manifest',
      'classes',
      'dependencies',
      'dependency-hints',
      'nested-archive-routing',
      'decompile-plan',
      'metadata-only-handoff',
      'workflow-plan',
      'workflow-handoff',
      'artifact-handoff',
      'routing',
    ],
    evidence: JVM_STRUCTURE_EVIDENCE,
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
