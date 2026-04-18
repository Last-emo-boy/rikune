/**
 * api-hash — Shellcode API hash resolution via embedded hash databases.
 */

import type { Plugin } from '../sdk.js'

import { hashResolveToolDefinition, createHashResolveHandler } from './tools/hash-resolve.js'
import { hashIdentifyToolDefinition, createHashIdentifyHandler } from './tools/hash-identify.js'
import { hashResolverPlanToolDefinition, createHashResolverPlanHandler } from './tools/hash-resolver-plan.js'

const apiHashPlugin: Plugin = {
  id: 'api-hash',
  name: 'API Hash Resolution',
  executionDomain: 'static',
  surfaceRules: { tier: 2, activateOn: { findings: ['obfuscated', 'shellcode', 'suspicious_imports'] }, category: 'reverse-engineering' },
  description: 'Resolve shellcode API hashes (ROR13, CRC32, DJB2, etc.) against known hash databases.',
  version: '1.0.0',

  systemDeps: [
    {
      type: 'python',
      name: 'hashlib',
      importName: 'hashlib',
      required: false,
      description: 'Python stdlib hashlib (always available).',
    },
  ],

  register(server, deps) {
    const { workspaceManager: wm, database: db } = deps

    server.registerTool(hashResolveToolDefinition, createHashResolveHandler(wm, db))
    server.registerTool(hashIdentifyToolDefinition, createHashIdentifyHandler(wm, db))
    server.registerTool(hashResolverPlanToolDefinition, createHashResolverPlanHandler(wm, db))

    return ['hash.resolve', 'hash.identify', 'hash.resolver.plan']
  },
}

export default apiHashPlugin
