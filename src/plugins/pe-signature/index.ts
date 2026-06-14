/**
 * pe-signature — PE Authenticode signature verification and certificate extraction via osslsigncode.
 */

import type { Plugin } from '../sdk.js'

import {
  PE_SIGNATURE_TRUST_REVIEW_EVIDENCE,
  PE_SIGNATURE_TRUST_REVIEW_SAFETY,
  peSignatureVerifyToolDefinition,
  createPeSignatureVerifyHandler,
} from './tools/pe-signature-verify.js'
import {
  peCertificateExtractToolDefinition,
  createPeCertificateExtractHandler,
} from './tools/pe-certificate-extract.js'

const peSignaturePlugin: Plugin = {
  id: 'pe-signature',
  name: 'PE Authenticode Signature',
  executionDomain: 'static',
  aspects: {
    formats: ['pe', 'pe32', 'pe64', 'exe', 'dll', 'sys', 'efi', 'pe-clr'],
    platforms: ['windows'],
    architectures: ['x86', 'x64', 'arm', 'arm64'],
    execution: ['static', 'triage'],
    safety: PE_SIGNATURE_TRUST_REVIEW_SAFETY,
    capabilities: [
      'signatures',
      'certificates',
      'timestamp',
      'authenticode',
      'trust-review',
      'routing',
      'workflow-plan',
      'metadata-only-handoff',
    ],
    evidence: PE_SIGNATURE_TRUST_REVIEW_EVIDENCE,
  },
  surfaceRules: {
    tier: 2,
    activateOn: {
      fileTypes: ['pe', 'pe32', 'pe64', 'exe', 'dll', 'sys', 'efi', 'pe-clr', 'windows'],
      findings: ['signed', 'certificate', 'certificates', 'authenticode', 'trust'],
    },
    category: 'static-analysis',
    signalMap: {
      is_signed: ['signed', 'authenticode'],
      signature_valid: ['authenticode', 'trust'],
      signer: ['signed', 'certificate'],
      issuer: ['certificate', 'trust'],
      serial: 'certificate',
      timestamp: 'authenticode',
      digest_algorithm: 'authenticode',
      has_certificate: ['signed', 'certificate', 'authenticode'],
      certificate_pem: ['certificate', 'authenticode'],
      subject: 'certificate',
      not_before: 'certificate',
      not_after: 'certificate',
    },
  },
  description:
    'Verify PE Authenticode signatures and extract embedded certificates via osslsigncode.',
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
    server.registerTool(
      peCertificateExtractToolDefinition,
      createPeCertificateExtractHandler(wm, db)
    )

    return ['pe.signature.verify', 'pe.certificate.extract']
  },
}

export default peSignaturePlugin
