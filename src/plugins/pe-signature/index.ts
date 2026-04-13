/**
 * pe-signature — PE Authenticode signature verification and certificate extraction via osslsigncode.
 */

import type { Plugin } from '../sdk.js'

import { peSignatureVerifyToolDefinition, createPeSignatureVerifyHandler } from './tools/pe-signature-verify.js'
import { peCertificateExtractToolDefinition, createPeCertificateExtractHandler } from './tools/pe-certificate-extract.js'

const peSignaturePlugin: Plugin = {
  id: 'pe-signature',
  name: 'PE Authenticode Signature',
  surfaceRules: { tier: 2, activateOn: { findings: ['signed'] }, category: 'static-analysis' },
  description: 'Verify PE Authenticode signatures and extract embedded certificates via osslsigncode.',
  version: '1.0.0',

  systemDeps: [
    {
      type: 'binary',
      name: 'osslsigncode',
      target: '$OSSLSIGNCODE_PATH',
      envVar: 'OSSLSIGNCODE_PATH',
      dockerDefault: '/usr/bin/osslsigncode',
      required: false,
      description: 'osslsigncode for PE Authenticode verification and certificate extraction.',
      aptPackages: ['osslsigncode'],
      dockerValidation: ['osslsigncode --version >/dev/null 2>&1 || true'],
    },
  ],

  register(server, deps) {
    const { workspaceManager: wm, database: db } = deps

    server.registerTool(peSignatureVerifyToolDefinition, createPeSignatureVerifyHandler(wm, db))
    server.registerTool(peCertificateExtractToolDefinition, createPeCertificateExtractHandler(wm, db))

    return ['pe.signature.verify', 'pe.certificate.extract']
  },
}

export default peSignaturePlugin
