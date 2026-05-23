import { definePlugin, defineTool } from '../sdk.js'
import {
  createJavascriptObfuscationProfileHandler,
  javascriptObfuscationProfileToolDefinition,
} from './tools/javascript-obfuscation-profile.js'

const javascriptDeobfuscationPlugin = definePlugin({
  id: 'javascript-deobfuscation',
  name: 'JavaScript Deobfuscation',
  executionDomain: 'static',
  aspects: {
    formats: ['js', 'javascript', 'mjs', 'cjs', 'typescript', 'source-map', 'html', 'v8-cache'],
    platforms: ['node', 'browser', 'cross-platform'],
    execution: ['static', 'triage', 'decompilation', 'correlation'],
    safety: ['passive', 'no_live_sample_by_default', 'no_network_by_default'],
    capabilities: [
      'javascript-deobfuscation',
      'jsvmp-triage',
      'vm-dispatch-detection',
      'jsir-plan',
      'workflow-routing',
    ],
    evidence: ['structure', 'strings', 'behavior', 'workflow', 'provenance'],
  },
  surfaceRules: {
    tier: 2,
    activateOn: {
      fileTypes: ['js', 'javascript', 'mjs', 'cjs', 'typescript', 'source-map', 'html', 'v8-cache'],
      findings: ['obfuscated', 'packed', 'javascript', 'jsvmp', 'eval', 'vm_detect'],
    },
    category: 'reverse-engineering',
  },
  description:
    'Passive JavaScript, JSIR/CASCADE, REstringer, and JSVMP-oriented deobfuscation planning without script execution.',
  version: '1.0.0',
  configSchema: [
    {
      envVar: 'JSIR_PATH',
      description: 'Optional local JSIR/CASCADE checkout or binary path for future bounded workers',
      required: false,
    },
    {
      envVar: 'RESTRINGER_PATH',
      description: 'Optional REstringer CLI path for future bounded workers',
      required: false,
    },
  ],
  systemDeps: [
    {
      type: 'file',
      name: 'jsir',
      target: '$JSIR_PATH',
      envVar: 'JSIR_PATH',
      required: false,
      description: 'Google JSIR / CASCADE JavaScript analysis tooling',
      dockerInstall: 'Provide a pinned local JSIR checkout; not installed by default',
      dockerFeature: 'javascript-deobfuscation',
      dockerInstallRoute: 'validation-only',
      dockerInstallProfile: 'default',
      dockerInstallNotes: [
        'This planner stays metadata-only; installable JSIR/CASCADE workers are declared by the jsir-cascade plugin.',
      ],
    },
    {
      type: 'file',
      name: 'restringer',
      target: '$RESTRINGER_PATH',
      envVar: 'RESTRINGER_PATH',
      required: false,
      description: 'REstringer JavaScript deobfuscator CLI',
      dockerInstall: 'Provide a pinned local REstringer checkout; not installed by default',
      dockerFeature: 'javascript-deobfuscation',
      dockerInstallRoute: 'validation-only',
      dockerInstallProfile: 'default',
      dockerInstallNotes: [
        'This planner stays metadata-only; installable REstringer wrappers are declared by the restringer plugin.',
      ],
    },
  ],
  tools: [
    defineTool({
      ...javascriptObfuscationProfileToolDefinition,
      handler: (_args, deps) => createJavascriptObfuscationProfileHandler(deps)(_args as never),
    }),
  ],
})

export default javascriptDeobfuscationPlugin
