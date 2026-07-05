import { describe, expect, test } from '@jest/globals'
import { createPluginTestHarness } from '../../src/plugins/sdk.js'
import appleSigningPlugin from '../../src/plugins/apple-signing/index.js'
import { buildAppleSecurityProfile } from '../../src/plugins/apple-signing/tools/apple-security-profile.js'

describe('apple.security.profile', () => {
  test('maps entitlements and signing hints to runtime constraints without device actions', () => {
    const profile = buildAppleSecurityProfile({
      sample_id: 'sha256:ipa',
      container_inventory: {
        provisioning_candidates: ['Payload/Demo.app/embedded.mobileprovision'],
        nested_macho_candidates: [{ path: 'Payload/Demo.app/Frameworks/libDemo.dylib' }],
      },
      signing_inventory: {
        entitlement_hints: ['get-task-allow', 'keychain-access-groups', 'aps-environment'],
        signing_blob_hints: ['LC_CODE_SIGNATURE'],
      },
      static_findings: ['ios Payload/Demo.app/Info.plist'],
    })

    expect(profile.result_mode).toBe('apple_security_profile')
    expect(profile.platform_hint).toBe('ios')
    expect(profile.signing_summary.entitlement_count).toBeGreaterThanOrEqual(3)
    expect(profile.entitlement_risks).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ entitlement: 'get-task-allow', severity: 'high' }),
      ])
    )
    expect(profile.runtime_constraints).toEqual(
      expect.objectContaining({
        debugger_attach_sensitive: true,
        device_or_simulator_opt_in_required: true,
        no_online_certificate_verification: true,
      })
    )
    expect(profile.recommended_next_tools).toEqual(
      expect.arrayContaining(['apple.signing.inspect', 'ios.runtime.plan'])
    )
    expect(profile.safety_notes.join(' ')).toMatch(/No DMG mount/)
  })

  test('registers Apple security profile workflow metadata', () => {
    const harness = createPluginTestHarness()
    const names = harness.registerPlugin(appleSigningPlugin)
    const tool = harness.registeredTools.find(
      (candidate) => candidate.definition.name === 'apple.security.profile'
    )

    expect(names).toContain('apple.security.profile')
    expect(tool?.definition.workflowRecipes?.[0]).toEqual(
      expect.objectContaining({
        id: 'apple.security.runtime-profile',
        nextTools: expect.arrayContaining(['macos.runtime.plan', 'ios.runtime.plan']),
      })
    )
  })
})
