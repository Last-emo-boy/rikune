/**
 * Unpacking Plugin
 *
 * Automated unpacking and unpacking strategy guidance.
 */

import type { Plugin } from '../sdk.js'
import { unpackAutoToolDefinition, createUnpackAutoHandler } from './tools/unpack-auto.js'
import { unpackGuideToolDefinition, createUnpackGuideHandler } from './tools/unpack-guide.js'
import {
  unpackChildHandoffToolDefinition,
  createUnpackChildHandoffHandler,
} from './tools/unpack-child-handoff.js'
import {
  unpackWorkflowPlanToolDefinition,
  createUnpackWorkflowPlanHandler,
} from './tools/unpack-workflow-plan.js'
import { createSampleFinalizationService } from '../../sample/sample-finalization.js'

const unpackingPlugin: Plugin = {
  id: 'unpacking',
  name: 'Unpacking',
  executionDomain: 'static',
  aspects: {
    formats: ['pe', 'elf', 'dotnet', 'apk', 'macho'],
    platforms: ['windows', 'linux', 'macos', 'android', 'cross-platform'],
    execution: ['static', 'triage'],
    runtimes: ['debugger', 'sandbox', 'speakeasy', 'qiling', 'frida'],
    safety: ['passive', 'opt_in_dynamic', 'requires_isolation', 'no_live_sample_by_default'],
    capabilities: ['unpacking', 'packer', 'reanalysis', 'runtime-routing'],
    evidence: ['signatures', 'structure', 'provenance'],
  },
  surfaceRules: { tier: 2, activateOn: { findings: ['packed'] }, category: 'unpacking' },
  description: 'Automated unpacking, child-sample handoff, and packer-specific unpacking guidance',
  version: '1.0.0',
  register(server, deps) {
    const { workspaceManager: wm, database: db, policyGuard, sampleOperationGate } = deps
    if (!policyGuard || !sampleOperationGate) {
      throw new Error('unpacking plugin requires PolicyGuard and SampleOperationGate')
    }
    const finalizer = createSampleFinalizationService(wm, db, policyGuard, sampleOperationGate)

    server.registerTool(unpackAutoToolDefinition, createUnpackAutoHandler(wm, db, finalizer))
    server.registerTool(unpackGuideToolDefinition, createUnpackGuideHandler(wm, db))
    server.registerTool(
      unpackChildHandoffToolDefinition,
      createUnpackChildHandoffHandler(wm, db, finalizer)
    )
    server.registerTool(unpackWorkflowPlanToolDefinition, createUnpackWorkflowPlanHandler())

    return ['unpack.auto', 'unpack.guide', 'unpack.child.handoff', 'unpack.workflow.plan']
  },
}

export default unpackingPlugin
