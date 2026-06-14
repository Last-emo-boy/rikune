import { describe, expect, test } from '@jest/globals'
import peSignaturePlugin from '../../src/plugins/pe-signature/index.js'
import {
  PE_SIGNATURE_AUTHENTICODE_TRUST_REVIEW_RECIPE,
  PE_SIGNATURE_TRUST_REVIEW_EVIDENCE,
  PE_SIGNATURE_TRUST_REVIEW_SAFETY,
  PE_SIGNATURE_VERIFY_RECOMMENDED_NEXT_TOOLS,
  peSignatureVerifyToolDefinition,
} from '../../src/plugins/pe-signature/tools/pe-signature-verify.js'
import {
  PE_CERTIFICATE_EXTRACT_RECOMMENDED_NEXT_TOOLS,
  peCertificateExtractToolDefinition,
} from '../../src/plugins/pe-signature/tools/pe-certificate-extract.js'

describe('pe-signature metadata', () => {
  test('declares PE activation/search tags and Authenticode trust signal mapping', () => {
    expect(peSignaturePlugin.aspects?.formats).toEqual(
      expect.arrayContaining(['pe', 'pe32', 'pe64', 'exe', 'dll', 'sys', 'efi', 'pe-clr'])
    )
    expect(peSignaturePlugin.aspects?.capabilities).toEqual(
      expect.arrayContaining(['authenticode', 'trust-review', 'workflow-plan'])
    )
    expect(peSignaturePlugin.surfaceRules?.activateOn?.fileTypes).toEqual(
      expect.arrayContaining([
        'pe',
        'pe32',
        'pe64',
        'exe',
        'dll',
        'sys',
        'efi',
        'pe-clr',
        'windows',
      ])
    )
    expect(peSignaturePlugin.surfaceRules?.activateOn?.findings).toEqual(
      expect.arrayContaining(['signed', 'certificate', 'certificates', 'authenticode', 'trust'])
    )
    expect(peSignaturePlugin.surfaceRules?.signalMap).toEqual(
      expect.objectContaining({
        is_signed: expect.arrayContaining(['signed', 'authenticode']),
        has_certificate: expect.arrayContaining(['signed', 'certificate', 'authenticode']),
        signature_valid: expect.arrayContaining(['authenticode', 'trust']),
      })
    )
  })

  test('declares Authenticode trust-review workflow recipe, evidence, and passive safety', () => {
    const recipe = peSignatureVerifyToolDefinition.workflowRecipes?.find(
      (candidate) => candidate.id === 'pe-signature.authenticode-trust-review'
    )

    expect(recipe).toEqual(
      expect.objectContaining({
        id: 'pe-signature.authenticode-trust-review',
        startsWith: expect.arrayContaining(['pe.signature.verify']),
        nextTools: expect.arrayContaining([
          'pe.structure.analyze',
          'windows.debug.metadata.inspect',
          'analysis.evidence.graph',
          'report.generate',
          'artifact.read',
        ]),
        producesArtifacts: expect.arrayContaining([
          'backend_pe-sig_verify',
          'backend_pe-sig_certificate',
        ]),
        evidence: expect.arrayContaining([
          'signatures',
          'certificates',
          'authenticode',
          'trust',
          'workflow',
          'provenance',
        ]),
        safety: expect.arrayContaining([
          'passive',
          'no_network_by_default',
          'no_mutation',
          'no_live_sample_by_default',
        ]),
      })
    )
    expect(peCertificateExtractToolDefinition.workflowRecipes).toEqual(
      expect.arrayContaining([expect.objectContaining({ id: recipe?.id })])
    )
    expect(PE_SIGNATURE_AUTHENTICODE_TRUST_REVIEW_RECIPE).toBe(recipe)
    expect(PE_SIGNATURE_TRUST_REVIEW_EVIDENCE).toEqual(
      expect.arrayContaining(['signatures', 'certificates', 'authenticode', 'trust'])
    )
    expect(PE_SIGNATURE_TRUST_REVIEW_SAFETY).toEqual(
      expect.arrayContaining([
        'passive',
        'no_network_by_default',
        'no_mutation',
        'no_live_sample_by_default',
      ])
    )
  })

  test('declares evidence categories and current recommended next tools only', () => {
    expect(peSignatureVerifyToolDefinition.evidence).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ category: 'signatures' }),
        expect.objectContaining({ category: 'certificates' }),
        expect.objectContaining({ category: 'authenticode' }),
        expect.objectContaining({ category: 'trust' }),
      ])
    )
    expect(peCertificateExtractToolDefinition.evidence).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ category: 'certificates' }),
        expect.objectContaining({ category: 'authenticode' }),
        expect.objectContaining({ category: 'trust' }),
      ])
    )
    expect(peSignatureVerifyToolDefinition.aspects?.safety).toEqual(
      expect.arrayContaining(PE_SIGNATURE_TRUST_REVIEW_SAFETY)
    )
    expect(peCertificateExtractToolDefinition.aspects?.safety).toEqual(
      expect.arrayContaining(PE_SIGNATURE_TRUST_REVIEW_SAFETY)
    )

    expect(PE_SIGNATURE_VERIFY_RECOMMENDED_NEXT_TOOLS).toEqual(
      expect.arrayContaining([
        'pe.certificate.extract',
        'pe.structure.analyze',
        'windows.debug.metadata.inspect',
        'analysis.evidence.graph',
        'report.generate',
        'artifact.read',
      ])
    )
    expect(PE_CERTIFICATE_EXTRACT_RECOMMENDED_NEXT_TOOLS).toEqual(
      expect.arrayContaining([
        'pe.signature.verify',
        'pe.structure.analyze',
        'windows.debug.metadata.inspect',
        'analysis.evidence.graph',
        'report.generate',
        'artifact.read',
        'sample.similarity',
      ])
    )
    expect(PE_SIGNATURE_VERIFY_RECOMMENDED_NEXT_TOOLS).not.toEqual(
      expect.arrayContaining(['pe.inspect', 'capa.analyze'])
    )
    expect(PE_CERTIFICATE_EXTRACT_RECOMMENDED_NEXT_TOOLS).not.toEqual(
      expect.arrayContaining(['pe.inspect', 'capa.analyze'])
    )
  })
})
