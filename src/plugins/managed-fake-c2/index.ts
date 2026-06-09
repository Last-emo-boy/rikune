/**
 * Managed Fake C2 Plugin
 *
 * Configurable fake C2 server for driving deeper sample logic
 * during sandbox analysis — custom endpoint responses, TLS support,
 * DNS redirection, and request capture.
 */

import { defineTool, type Plugin } from '../sdk.js'
import {
  FAKE_C2_RUNTIME_POLICY,
  fakeC2ToolDefinition,
  createFakeC2Handler,
} from './tools/fake-c2.js'
import { MANAGED_FAKE_C2_TOOL_VERSION, managedFakeC2Aspects } from './managed-fake-c2-metadata.js'

const managedFakeC2Plugin: Plugin = {
  id: 'managed-fake-c2',
  name: 'Managed Fake C2',
  executionDomain: 'dynamic',
  aspects: managedFakeC2Aspects(),
  runtimePolicy: FAKE_C2_RUNTIME_POLICY,
  surfaceRules: {
    tier: 2,
    activateOn: {
      findings: [
        'c2',
        'c2_config',
        'c2-config',
        'network_ioc',
        'network-ioc',
        'domain',
        'url',
        'http_beacon',
        'http-beacon',
        'beaconing',
        'suspicious_network',
        'suspicious-network',
        'sinkhole',
        'fake-c2',
        'fakenet',
      ],
    },
    category: 'dynamic-analysis',
  },
  description:
    'Explicit opt-in isolated Fake C2 / FakeNet-style HTTP sinkhole for endpoint responses, beacon gate validation, request capture, DNS redirect handoff, and no-arbitrary-outbound-network runtime validation planning.',
  version: MANAGED_FAKE_C2_TOOL_VERSION,
  dependencies: ['managed-sandbox'],
  configSchema: [
    {
      envVar: 'FAKE_C2_DEFAULT_PORT',
      description:
        'Readiness/documentation hint for operator defaults; callers must pass listen_port explicitly or use the tool schema default 8443.',
      required: false,
      defaultValue: '8443',
    },
    {
      envVar: 'FAKE_C2_TLS_CERT',
      description:
        'Reserved for future custom TLS certificate support; current worker generates an ephemeral self-signed certificate when use_tls=true and does not read this env var.',
      required: false,
    },
    {
      envVar: 'FAKE_C2_TLS_KEY',
      description:
        'Reserved for future custom TLS private key support; current worker does not read this env var.',
      required: false,
    },
  ],
  systemDeps: [
    {
      type: 'binary',
      name: 'python3',
      versionFlag: '--version',
      dockerDefault: '/usr/local/bin/python3',
      required: true,
      description: 'Python 3 for fake C2 server worker',
      dockerInstall: 'Use the runtime image Python 3 interpreter or install python3.',
      dockerValidation: ['python3 --version >/dev/null 2>&1'],
    },
    {
      type: 'binary',
      name: 'openssl',
      versionFlag: 'version',
      dockerDefault: '/usr/bin/openssl',
      required: false,
      description:
        'OpenSSL is required only when managed.fake_c2 runs with use_tls=true to generate an ephemeral self-signed certificate.',
      dockerInstall: 'apt-get install -y openssl',
      aptPackages: ['openssl'],
      dockerValidation: ['openssl version >/dev/null 2>&1'],
    },
    {
      type: 'binary',
      name: 'dotnet',
      versionFlag: '--version',
      required: false,
      description:
        'Optional .NET runtime used only when auto_run_sample=true is explicitly approved inside an isolated managed sandbox.',
      dockerInstallRoute: 'profile-gated',
      dockerInstallProfile: 'runtime',
      dockerInstallNotes: [
        'Not needed for listener-only Fake C2 sessions.',
        'Keep auto_run_sample=false unless the runtime validation plan explicitly approves live sample execution.',
      ],
    },
    {
      type: 'binary',
      name: 'mono',
      versionFlag: '--version',
      required: false,
      description:
        'Optional Mono fallback used only when auto_run_sample=true is explicitly approved and dotnet is unavailable.',
      dockerInstallRoute: 'profile-gated',
      dockerInstallProfile: 'runtime',
      dockerInstallNotes: [
        'Not needed for listener-only Fake C2 sessions.',
        'Use only in an isolated/sinkholed runtime with no arbitrary outbound network.',
      ],
    },
  ],
  resources: { workers: 'workers' },
  tools: [
    defineTool({
      ...fakeC2ToolDefinition,
      handler: (args, deps) => createFakeC2Handler(deps)(args as never),
    }),
  ],
  register(server, deps) {
    server.registerTool(fakeC2ToolDefinition, createFakeC2Handler(deps))
    return ['managed.fake_c2']
  },
}

export default managedFakeC2Plugin
