import { afterEach, beforeEach, describe, expect, test } from '@jest/globals'
import fs from 'fs'
import path from 'path'
import { WorkspaceManager } from '../../src/workspace-manager.js'
import { DatabaseManager } from '../../src/database.js'
import { resolvePrimarySamplePath } from '../../src/sample/sample-workspace.js'
import { createPluginTestHarness } from '../../src/plugins/sdk.js'
import peAnalysisPlugin from '../../src/plugins/pe-analysis/index.js'
import {
  PE_SECURITY_PROFILE_ARTIFACT_TYPE,
  buildPESecurityProfileFromBuffer,
  createPESecurityProfileHandler,
  peSecurityProfileToolDefinition,
} from '../../src/plugins/pe-analysis/tools/pe-security-profile.js'

const IMAGE_BASE = 0x140000000n
const IMAGE_BASE_NUMBER = Number(IMAGE_BASE)
const HARDENED_DLL_CHARACTERISTICS = 0x0020 | 0x0040 | 0x0100 | 0x4000

function createSecurityProfilePE(
  options: {
    dllCharacteristics?: number
    includeLoadConfig?: boolean
    includeTls?: boolean
    includeWriteExecuteSection?: boolean
  } = {}
): Buffer {
  const {
    dllCharacteristics = HARDENED_DLL_CHARACTERISTICS,
    includeLoadConfig = true,
    includeTls = true,
    includeWriteExecuteSection = true,
  } = options

  const dosHeader = Buffer.alloc(0x80, 0)
  dosHeader.write('MZ', 0, 'ascii')
  dosHeader.writeUInt32LE(0x80, 0x3c)

  const peSignature = Buffer.from('PE\0\0', 'ascii')
  const coffHeader = Buffer.alloc(20, 0)
  coffHeader.writeUInt16LE(0x8664, 0)
  coffHeader.writeUInt16LE(3, 2)
  coffHeader.writeUInt16LE(0x00f0, 16)
  coffHeader.writeUInt16LE(0x0022, 18)

  const optionalHeader = Buffer.alloc(0x00f0, 0)
  optionalHeader.writeUInt16LE(0x20b, 0)
  optionalHeader.writeUInt32LE(0x200, 4)
  optionalHeader.writeUInt32LE(0x1000, 16)
  optionalHeader.writeUInt32LE(0x1000, 20)
  optionalHeader.writeBigUInt64LE(IMAGE_BASE, 24)
  optionalHeader.writeUInt32LE(0x1000, 32)
  optionalHeader.writeUInt32LE(0x200, 36)
  optionalHeader.writeUInt32LE(0x4000, 56)
  optionalHeader.writeUInt32LE(0x200, 60)
  optionalHeader.writeUInt16LE(3, 68)
  optionalHeader.writeUInt16LE(dllCharacteristics, 70)
  optionalHeader.writeUInt32LE(16, 108)

  if (includeTls) {
    optionalHeader.writeUInt32LE(0x2100, 112 + 9 * 8)
    optionalHeader.writeUInt32LE(40, 112 + 9 * 8 + 4)
  }
  if (includeLoadConfig) {
    optionalHeader.writeUInt32LE(0x2000, 112 + 10 * 8)
    optionalHeader.writeUInt32LE(0xa0, 112 + 10 * 8 + 4)
  }

  const textSection = Buffer.alloc(40, 0)
  textSection.write('.text', 0, 'ascii')
  textSection.writeUInt32LE(0x100, 8)
  textSection.writeUInt32LE(0x1000, 12)
  textSection.writeUInt32LE(0x200, 16)
  textSection.writeUInt32LE(0x200, 20)
  textSection.writeUInt32LE(0x60000020, 36)

  const rdataSection = Buffer.alloc(40, 0)
  rdataSection.write('.rdata', 0, 'ascii')
  rdataSection.writeUInt32LE(0x200, 8)
  rdataSection.writeUInt32LE(0x2000, 12)
  rdataSection.writeUInt32LE(0x200, 16)
  rdataSection.writeUInt32LE(0x400, 20)
  rdataSection.writeUInt32LE(0x40000040, 36)

  const riskSection = Buffer.alloc(40, 0)
  riskSection.write(includeWriteExecuteSection ? '.wxc' : '.rsrc', 0, 'ascii')
  riskSection.writeUInt32LE(0x100, 8)
  riskSection.writeUInt32LE(0x3000, 12)
  riskSection.writeUInt32LE(0x200, 16)
  riskSection.writeUInt32LE(0x600, 20)
  riskSection.writeUInt32LE(includeWriteExecuteSection ? 0xe0000020 : 0x40000040, 36)

  const headers = Buffer.concat([
    dosHeader,
    peSignature,
    coffHeader,
    optionalHeader,
    textSection,
    rdataSection,
    riskSection,
  ])
  if (headers.length !== 0x200) {
    throw new Error(`Unexpected test PE header length: ${headers.length}`)
  }

  const textData = Buffer.alloc(0x200, 0)
  textData[0x10] = 0xc3

  const rdata = Buffer.alloc(0x200, 0)
  if (includeLoadConfig) {
    rdata.writeUInt32LE(0xa0, 0)
    rdata.writeBigUInt64LE(IMAGE_BASE + 0x2080n, 88)
    rdata.writeUInt32LE(0x00000500, 144)
  }
  if (includeTls) {
    rdata.writeBigUInt64LE(IMAGE_BASE + 0x2128n, 0x100 + 24)
    rdata.writeBigUInt64LE(IMAGE_BASE + 0x1010n, 0x128)
    rdata.writeBigUInt64LE(0n, 0x130)
  }

  return Buffer.concat([headers, textData, rdata, Buffer.alloc(0x200, 0)])
}

describe('pe.security.profile tool', () => {
  let workspaceManager: WorkspaceManager
  let database: DatabaseManager
  let testWorkspaceRoot: string
  let testDbPath: string
  const sampleId = 'sha256:' + '8'.repeat(64)

  beforeEach(async () => {
    testWorkspaceRoot = path.join(process.cwd(), 'test-workspace-pe-security-profile')
    testDbPath = path.join(process.cwd(), 'test-pe-security-profile.db')

    if (fs.existsSync(testWorkspaceRoot)) {
      fs.rmSync(testWorkspaceRoot, { recursive: true, force: true })
    }
    if (fs.existsSync(testDbPath)) {
      fs.unlinkSync(testDbPath)
    }

    workspaceManager = new WorkspaceManager(testWorkspaceRoot)
    database = new DatabaseManager(testDbPath)
    database.insertSample({
      id: sampleId,
      sha256: '8'.repeat(64),
      md5: '8'.repeat(32),
      size: 2048,
      file_type: 'PE32+',
      created_at: new Date().toISOString(),
      source: 'test',
    })

    const workspace = await workspaceManager.createWorkspace(sampleId)
    fs.writeFileSync(path.join(workspace.original, 'sample.exe'), createSecurityProfilePE())
  })

  afterEach(() => {
    try {
      database.close()
    } catch {
      // ignore
    }
    if (fs.existsSync(testWorkspaceRoot)) {
      fs.rmSync(testWorkspaceRoot, { recursive: true, force: true })
    }
    if (fs.existsSync(testDbPath)) {
      fs.unlinkSync(testDbPath)
    }
  })

  test('builds a passive PE mitigation profile from headers, load config, TLS, and sections', () => {
    const profile = buildPESecurityProfileFromBuffer(createSecurityProfilePE(), {
      filename: 'sample.exe',
      sampleId,
    })

    expect(profile.schema).toBe('rikune.pe_security_profile.v1')
    expect(profile.machine_name).toBe('IMAGE_FILE_MACHINE_AMD64')
    expect(profile.pe_kind).toBe('pe32-plus')
    expect(profile.image_base).toBe(IMAGE_BASE_NUMBER)
    expect(profile.dll_characteristics_flags).toEqual(
      expect.arrayContaining(['high_entropy_va', 'dynamic_base', 'nx_compat', 'guard_cf'])
    )
    expect(profile.mitigations.aslr.enabled).toBe(true)
    expect(profile.mitigations.dep_nx.enabled).toBe(true)
    expect(profile.mitigations.control_flow_guard.enabled).toBe(true)
    expect(profile.mitigations.security_cookie.enabled).toBe(true)
    expect(profile.load_config).toEqual(
      expect.objectContaining({
        present: true,
        parsed: true,
        size: 0xa0,
        security_cookie_va: IMAGE_BASE_NUMBER + 0x2080,
        guard_flags: 0x00000500,
        guard_flags_names: expect.arrayContaining(['cf_instrumented', 'cf_function_table_present']),
      })
    )
    expect(profile.tls).toEqual(
      expect.objectContaining({
        present: true,
        callback_table_va: IMAGE_BASE_NUMBER + 0x2128,
        callback_count: 1,
        callback_rvas: [0x1010],
      })
    )
    expect(profile.section_risks).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ type: 'write_execute_section', section: '.wxc' }),
      ])
    )
    expect(profile.risk_factors.map((factor: any) => factor.id)).toEqual(
      expect.arrayContaining(['tls_callbacks_present', 'write_execute_section'])
    )
    expect(profile.posture).toBe('medium-risk')
    expect(profile.policy).toEqual(
      expect.objectContaining({
        passive: true,
        no_execute: true,
        no_load: true,
        no_network: true,
        no_mutation: true,
      })
    )
    expect(profile.evidence_summary).toEqual(
      expect.objectContaining({
        source_tool: 'pe.security.profile',
        artifact_type: PE_SECURITY_PROFILE_ARTIFACT_TYPE,
        tls_callback_count: 1,
        write_execute_section_count: 1,
        static_only: true,
      })
    )
    expect(profile.workflow_handoff.dynamic_boundary).toEqual(
      expect.objectContaining({
        sample_execution_allowed: false,
        loader_invocation_allowed: false,
        sample_executed_by_tool: false,
      })
    )
    expect(profile.quality_gates).toEqual(
      expect.objectContaining({
        passive_static_analysis: true,
        builtin_parser_only: true,
        sample_executed_by_tool: false,
        loader_invoked_by_tool: false,
      })
    )
    expect(profile.recommended_next_tools).toEqual(
      expect.arrayContaining([
        'pe.structure.analyze',
        'analysis.evidence.graph',
        'windows.runtime.plan',
      ])
    )
  })

  test('raises exploitability posture when common PE mitigations are absent', () => {
    const profile = buildPESecurityProfileFromBuffer(
      createSecurityProfilePE({
        dllCharacteristics: 0,
        includeLoadConfig: false,
        includeTls: false,
        includeWriteExecuteSection: false,
      })
    )

    expect(profile.posture).toBe('high-risk')
    expect(profile.load_config.present).toBe(false)
    expect(profile.tls.callback_count).toBe(0)
    expect(profile.section_risks).toEqual([])
    expect(profile.risk_factors.map((factor: any) => factor.id)).toEqual(
      expect.arrayContaining([
        'missing_aslr',
        'missing_dep_nx',
        'missing_high_entropy_va',
        'missing_cfg',
        'missing_security_cookie',
        'missing_load_config',
      ])
    )
  })

  test('runs through the sample workspace without executing or loading the PE image', async () => {
    const handler = createPESecurityProfileHandler({
      workspaceManager,
      database,
      resolvePrimarySamplePath,
    } as any)

    const result = await handler({ sample_id: sampleId, persist_artifact: false })

    expect(result.ok).toBe(true)
    expect(result.artifacts).toEqual([])
    expect((result.data as any).policy).toEqual(
      expect.objectContaining({
        no_execute: true,
        no_load: true,
        no_network: true,
        no_mutation: true,
      })
    )
    expect((result.data as any).quality_gates.sample_executed_by_tool).toBe(false)
  })

  test('registers metadata for workflow search, artifacts, and builtin parser readiness', () => {
    expect(peSecurityProfileToolDefinition.artifacts?.map((artifact) => artifact.type)).toContain(
      PE_SECURITY_PROFILE_ARTIFACT_TYPE
    )
    expect(peSecurityProfileToolDefinition.evidence?.map((entry) => entry.category)).toEqual(
      expect.arrayContaining(['structure', 'mitigations', 'sections', 'workflow', 'provenance'])
    )
    expect(peSecurityProfileToolDefinition.aspects?.formats).toEqual(
      expect.arrayContaining(['pe', 'pe-clr', 'dll', 'exe', 'sys', 'efi'])
    )
    expect(peSecurityProfileToolDefinition.aspects?.capabilities).toEqual(
      expect.arrayContaining([
        'security-profile',
        'hardening-assessment',
        'exploitability-posture',
        'workflow-handoff',
      ])
    )
    expect(peSecurityProfileToolDefinition.aspects?.safety).toEqual(
      expect.arrayContaining([
        'passive',
        'no_network_by_default',
        'no_mutation',
        'no_loader_invocation',
      ])
    )
    expect(peSecurityProfileToolDefinition.workflowRecipes?.[0]).toEqual(
      expect.objectContaining({
        id: 'pe.security.hardening-profile',
        startsWith: expect.arrayContaining(['pe.security.profile', 'pe.structure.analyze']),
        nextTools: expect.arrayContaining([
          'pe.structure.analyze',
          'pe.imports.extract',
          'pe.pdata.extract',
          'pe.signature.verify',
          'static.capability.triage',
          'compiler.packer.detect',
          'analysis.evidence.graph',
          'report.generate',
          'windows.runtime.plan',
        ]),
        producesArtifacts: [PE_SECURITY_PROFILE_ARTIFACT_TYPE],
        evidence: expect.arrayContaining([
          'structure',
          'mitigations',
          'sections',
          'workflow',
          'provenance',
        ]),
        runtimeBackends: ['builtin-pe-parser'],
      })
    )
    expect(peSecurityProfileToolDefinition.runtimePolicy).toEqual(
      expect.objectContaining({
        passiveByDefault: true,
        requiresUserOptIn: false,
        noNetwork: true,
        noMutation: true,
        noLiveExecution: true,
      })
    )
    expect(peSecurityProfileToolDefinition.workerBackend).toEqual(
      expect.objectContaining({
        backendName: 'builtin-pe-parser',
        backendKind: 'builtin',
        adapter: 'pe.security.profile',
        outputArtifactTypes: expect.arrayContaining([PE_SECURITY_PROFILE_ARTIFACT_TYPE]),
        readiness: expect.objectContaining({
          doesNotStartBackend: true,
        }),
      })
    )

    const harness = createPluginTestHarness()
    const registeredNames = harness.registerPlugin(peAnalysisPlugin)
    expect(registeredNames).toContain('pe.security.profile')
    expect(peAnalysisPlugin.aspects?.capabilities).toEqual(
      expect.arrayContaining(['security-profile', 'mitigation-profile', 'loader-security'])
    )
    expect(harness.registeredTools.map((tool) => tool.definition.name)).toContain(
      'pe.security.profile'
    )
  })
})
