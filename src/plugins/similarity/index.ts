/**
 * Similarity Plugin
 *
 * Fuzzy hashing (ssdeep, TLSH) for sample similarity analysis and family clustering.
 */

import type { Plugin } from '../sdk.js'
import { sampleSimilarityToolDefinition, createSampleSimilarityHandler } from './tools/sample-similarity.js'
import { sampleClusterFuzzyToolDefinition, createSampleClusterFuzzyHandler } from './tools/sample-cluster-fuzzy.js'

const similarityPlugin: Plugin = {
  id: 'similarity',
  name: 'Sample Similarity',
  surfaceRules: { tier: 2, activateOn: { findings: ['packed', 'obfuscated'] }, category: 'malware-analysis' },
  description: 'Fuzzy hashing (ssdeep, TLSH) for sample similarity analysis and malware family clustering',
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

    return ['sample.similarity', 'sample.cluster.fuzzy']
  },
}

export default similarityPlugin
