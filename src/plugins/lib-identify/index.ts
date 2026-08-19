/**
 * lib-identify Plugin
 *
 * Static library function identification via rizin FLIRT signatures (sigdb).
 * Identifies known library functions (libc, MSVC CRT, OpenSSL, zlib, etc.) so
 * analysts can separate library boilerplate from custom code.
 */

import type { Plugin } from '../sdk.js'
import { libIdentifyToolDefinition, createLibIdentifyHandler } from './tools/lib-identify.js'
import {
  libSignaturesListToolDefinition,
  createLibSignaturesListHandler,
} from './tools/lib-signatures-list.js'

const libIdentifyPlugin: Plugin = {
  id: 'lib-identify',
  name: 'Library Function Identification (FLIRT)',
  executionDomain: 'static',
  aspects: {
    formats: ['pe', 'elf', 'macho', 'firmware', 'object'],
    platforms: ['windows', 'linux', 'macos', 'embedded', 'cross-platform'],
    architectures: ['x86', 'x64', 'arm', 'arm64', 'mips', 'ppc', 'riscv'],
    execution: ['static', 'triage'],
    safety: ['passive', 'read_only', 'no_live_sample_by_default', 'no_network_by_default'],
    capabilities: [
      'library-function-identification',
      'flirt-signature-matching',
      'sigdb-enumeration',
      'function-naming',
      'boilerplate-filtering',
    ],
    evidence: ['symbols', 'functions', 'signatures', 'provenance'],
  },
  surfaceRules: {
    tier: 2,
    activateOn: { findings: ['stripped', 'static-linked', 'library'] },
    category: 'reverse-engineering',
  },
  description:
    'Static library function identification via rizin FLIRT signatures (sigdb). ' +
    'Matches functions against known libraries to separate boilerplate from custom code.',
  version: '0.1.0',
  dependencies: ['rizin'],
  configSchema: [
    {
      envVar: 'RIZIN_PATH',
      description: 'Path to rizin binary (shared with rizin plugin)',
      required: false,
      defaultValue: '/opt/rizin/bin/rizin',
    },
    {
      envVar: 'RZ_SIGDB',
      description:
        'Path to rizin FLIRT sigdb (clone https://github.com/rizinorg/sigdb). ' +
        'Also configurable via rizin flirt.sigdb.path.',
      required: false,
    },
  ],
  systemDeps: [
    {
      type: 'binary',
      name: 'rizin',
      target: '$RIZIN_PATH',
      envVar: 'RIZIN_PATH',
      dockerDefault: '/opt/rizin/bin/rizin',
      versionFlag: '-v',
      required: false,
      description: 'rizin reverse engineering framework (shared backend)',
      dockerInstall: 'Download rizin release to /opt/rizin',
      dockerFeature: 'rizin',
      dockerValidation: ['rizin -v >/dev/null 2>&1'],
      buildArgs: { RIZIN_VERSION: '0.8.2' },
    },
    {
      type: 'directory',
      name: 'rizin-sigdb',
      target: '$RZ_SIGDB',
      envVar: 'RZ_SIGDB',
      required: false,
      description: 'rizin FLIRT signature database (rizinorg/sigdb)',
      dockerInstall: 'git clone https://github.com/rizinorg/sigdb /opt/rizin/share/sigdb',
      dockerFeature: 'sigdb',
      dockerValidation: ['test -d "$RZ_SIGDB" || true'],
      dockerInstallRoute: 'profile-gated',
      dockerInstallProfile: 'optional',
    },
  ],
  resources: { workers: 'shared' },
  check() {
    return true
  },
  register(server, deps) {
    server.registerTool(libIdentifyToolDefinition, createLibIdentifyHandler(deps))
    server.registerTool(libSignaturesListToolDefinition, createLibSignaturesListHandler(deps))
    return ['lib.identify', 'lib.signatures.list']
  },
}

export default libIdentifyPlugin
