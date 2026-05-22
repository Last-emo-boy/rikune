/**
 * Similarity Plugin
 *
 * Fuzzy hashing (ssdeep, TLSH) for sample similarity analysis and family clustering.
 */

import type { Plugin } from '../sdk.js'
import {
  sampleSimilarityToolDefinition,
  createSampleSimilarityHandler,
} from './tools/sample-similarity.js'
import {
  sampleClusterFuzzyToolDefinition,
  createSampleClusterFuzzyHandler,
} from './tools/sample-cluster-fuzzy.js'
import {
  sampleFamilyClusterToolDefinition,
  createSampleFamilyClusterHandler,
} from './tools/sample-family-cluster.js'

const similarityPlugin: Plugin = {
  id: 'similarity',
  name: 'Sample Similarity',
  executionDomain: 'static',
  aspects: {
    formats: ['pe', 'elf', 'macho', 'apk', 'dotnet', 'wasm', 'firmware'],
    platforms: ['windows', 'linux', 'macos', 'android', 'embedded', 'cross-platform'],
    execution: ['static'],
    safety: ['passive', 'no_network_by_default'],
    capabilities: ['similarity', 'family-clustering', 'fuzzy-hashing', 'binary-diff'],
    evidence: ['hashes', 'imports', 'strings', 'functions', 'provenance'],
  },
  surfaceRules: {
    tier: 2,
    activateOn: { findings: ['packed', 'obfuscated'] },
    category: 'malware-analysis',
  },
  description:
    'Fuzzy hashing (ssdeep, TLSH) for sample similarity analysis and malware family clustering',
  version: '1.0.0',
  systemDeps: [
    {
      type: 'python',
      name: 'ppdeep',
      importName: 'ppdeep',
      required: false,
      description: 'Pure-Python ssdeep fuzzy hashing',
      dockerInstall: 'pip install ppdeep',
      dockerFeature: 'dynamic-python',
    },
    {
      type: 'python',
      name: 'py-tlsh',
      importName: 'tlsh',
      required: false,
      description: 'Trend Micro TLSH locality-sensitive hashing',
      dockerInstall: 'pip install py-tlsh',
      dockerFeature: 'dynamic-python',
    },
  ],
  register(server, deps) {
    const { workspaceManager: wm, database: db } = deps

    server.registerTool(sampleSimilarityToolDefinition, createSampleSimilarityHandler(wm, db))
    server.registerTool(sampleClusterFuzzyToolDefinition, createSampleClusterFuzzyHandler(wm, db))
    server.registerTool(sampleFamilyClusterToolDefinition, createSampleFamilyClusterHandler())

    return ['sample.similarity', 'sample.cluster.fuzzy', 'sample.family.cluster']
  },
}

export default similarityPlugin
