import { describe, expect, test } from '@jest/globals'
import syscallAbiSurfacePlugin from '../../src/plugins/syscall-abi-surface/index.js'
import {
  SYSCALL_ABI_SURFACE_ARTIFACT_TYPE,
  buildSyscallAbiSurfaceInventoryFromBuffer,
  createSyscallAbiSurfaceInventoryHandler,
  syscallAbiSurfaceInventoryToolDefinition,
} from '../../src/plugins/syscall-abi-surface/tools/syscall-abi-surface-inventory.js'

describe('syscall.abi.surface.inventory', () => {
  test('declares passive syscall ABI surface metadata', () => {
    expect(syscallAbiSurfacePlugin.id).toBe('syscall-abi-surface')
    expect(syscallAbiSurfacePlugin.executionDomain).toBe('static')
    expect(syscallAbiSurfacePlugin.surfaceRules?.tier).toBe(2)
    expect(syscallAbiSurfacePlugin.surfaceRules?.activateOn?.fileTypes).toEqual(
      expect.arrayContaining(['syscall', 'direct-syscall', 'raw-shellcode', 'ntdll-stub'])
    )
    expect(syscallAbiSurfaceInventoryToolDefinition.name).toBe(
      'syscall.abi.surface.inventory'
    )
    expect(
      syscallAbiSurfaceInventoryToolDefinition.artifacts?.map((artifact) => artifact.type)
    ).toEqual(expect.arrayContaining([SYSCALL_ABI_SURFACE_ARTIFACT_TYPE]))
    const recipe = syscallAbiSurfaceInventoryToolDefinition.workflowRecipes?.find(
      (candidate) => candidate.id === 'syscall.abi-surface-static-inventory'
    )
    expect(recipe).toEqual(
      expect.objectContaining({
        startsWith: ['syscall.abi.surface.inventory'],
        producesArtifacts: [SYSCALL_ABI_SURFACE_ARTIFACT_TYPE],
        safety: expect.arrayContaining([
          'passive',
          'no_syscall',
          'no_ptrace',
          'no_debugger',
          'no_frida',
          'no_emulation',
        ]),
      })
    )
    expect(recipe?.nextTools).toEqual(
      expect.arrayContaining(['code.xrefs.analyze', 'analysis.evidence.graph', 'artifact.read'])
    )
  })

  test('summarizes Windows direct syscall stubs and NT resolver evidence', () => {
    const stub = Buffer.from([
      0x4d,
      0x5a,
      0x00,
      0x00,
      0x4c,
      0x8b,
      0xd1,
      0xb8,
      0x3a,
      0x00,
      0x00,
      0x00,
      0x0f,
      0x05,
      0xc3,
      0x00,
    ])
    const strings = Buffer.from(
      [
        'SysWhispers',
        'SW3_GetSyscallNumber',
        'HellsGate',
        'ntdll.dll',
        'NtAllocateVirtualMemory',
        'NtProtectVirtualMemory',
        'NtQueryInformationProcess',
      ].join('\0'),
      'ascii'
    )
    const inventory = buildSyscallAbiSurfaceInventoryFromBuffer(Buffer.concat([stub, strings]), {
      filename: 'payload.syscall',
      sampleId: 'sha256:syscall',
    })

    expect(inventory.format).toBe('pe-windows-direct-syscall-surface')
    expect(inventory.platforms).toContain('windows')
    expect(inventory.architectures).toContain('x64')
    expect((inventory.windows_nt_surface as any).present).toBe(true)
    expect((inventory.windows_nt_surface as any).direct_stub_count).toBe(1)
    expect((inventory.windows_nt_surface as any).syscall_numbers).toContain('0x3a')
    expect((inventory.windows_nt_surface as any).high_risk_apis).toEqual(
      expect.arrayContaining(['NtAllocateVirtualMemory', 'NtProtectVirtualMemory'])
    )
    expect(inventory.string_evidence).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ id: 'direct-syscall.syswhispers' }),
        expect.objectContaining({ id: 'direct-syscall.named-technique' }),
        expect.objectContaining({ id: 'anti-analysis.nt-query' }),
      ])
    )
    expect(inventory.risk_flags).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ id: 'windows.direct-syscall-stub', severity: 'high' }),
        expect.objectContaining({ id: 'direct-syscall.named-evasion-framework' }),
        expect.objectContaining({ id: 'windows.nt-high-risk-api-surface' }),
      ])
    )
    expect(inventory.quality_gates).toEqual(
      expect.objectContaining({
        passive_static_inventory: true,
        sample_executed_by_tool: false,
        syscall_invoked_by_tool: false,
        debugger_attached_by_tool: false,
        emulator_started_by_tool: false,
      })
    )
    expect((inventory.workflow_handoff as any).runtime_policy).toEqual(
      expect.objectContaining({
        runtime_not_started_by_tool: true,
        runtime_requires_explicit_opt_in: true,
      })
    )
  })

  test('summarizes Linux syscall, seccomp, and ptrace boundary evidence', () => {
    const elf = Buffer.from([0x7f, 0x45, 0x4c, 0x46, 0x90, 0x90, 0xcd, 0x80])
    const strings = Buffer.from(
      ['__NR_execve', 'SYS_openat', 'seccomp', 'PR_SET_SECCOMP', 'PTRACE_TRACEME'].join('\0'),
      'ascii'
    )
    const inventory = buildSyscallAbiSurfaceInventoryFromBuffer(Buffer.concat([elf, strings]), {
      filename: 'payload.elf',
    })

    expect(inventory.format).toBe('elf-linux-syscall-abi-surface')
    expect(inventory.platforms).toContain('linux')
    expect((inventory.linux_syscall_surface as any).present).toBe(true)
    expect((inventory.linux_syscall_surface as any).int80_count).toBe(1)
    expect((inventory.linux_syscall_surface as any).seccomp_hint).toBe(true)
    expect((inventory.linux_syscall_surface as any).ptrace_hint).toBe(true)
    expect(inventory.risk_flags).toEqual(
      expect.arrayContaining([expect.objectContaining({ id: 'linux.syscall-policy-or-anti-debug' })])
    )
    expect(inventory.policy).toEqual(
      expect.objectContaining({
        passive: true,
        no_syscall: true,
        no_ptrace: true,
        no_external_tool: true,
      })
    )
  })

  test('handler degrades clearly when sample resolution is unavailable', async () => {
    const handler = createSyscallAbiSurfaceInventoryHandler()
    const result = await handler({ sample_id: 'sha256:test' })

    expect(result.ok).toBe(false)
    expect(result.errors?.join(' ')).toContain('resolvePrimarySamplePath dependency is unavailable')
  })
})
