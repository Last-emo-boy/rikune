import { describe, expect, test } from '@jest/globals'
import { createPluginTestHarness } from '../../src/plugins/sdk.js'
import linuxRuntimePlugin from '../../src/plugins/linux-runtime/index.js'
import {
  createWorkflowSearchHandler,
} from '../../src/tools/workflow-search.js'
import { getToolSurfaceManager } from '../../src/core/tool-surface-manager.js'
import type { Plugin } from '../../src/plugins/sdk.js'

function resetSurfaceForTest() {
  const surface = getToolSurfaceManager() as any
  surface.entries = new Map()
  surface.coreTools = new Set()
  surface.visibleCoreTools = new Set()
}

function createPluginManager(plugins: Plugin[]) {
  return {
    getStatuses: () =>
      plugins.map((plugin) => ({
        id: plugin.id,
        name: plugin.name,
        description: plugin.description,
        status: 'loaded',
        tools: plugin.tools.map((tool) => tool.definition.name),
        depChecks: [],
        qualityWarnings: [],
      })),
    getDiscoveredPlugins: () => plugins,
    getPlugin: (id: string) => plugins.find((plugin) => plugin.id === id),
  } as any
}

describe('linux.runtime.plan readiness', () => {
  test('builds Linux backend plans without running ELF, ptrace, or eBPF', async () => {
    const harness = createPluginTestHarness()
    harness.registerPlugin(linuxRuntimePlugin)
    const tool = harness.registeredTools.find(
      (candidate) => candidate.definition.name === 'linux.runtime.plan'
    )

    const result = (await tool?.handler({
      sample_id: 'sha256:elf',
      requested_backends: ['qiling', 'gdb', 'strace', 'ebpf'],
      static_evidence: ['DT_NEEDED:libssl.so.3', 'PT_INTERP:/lib64/ld-linux-x86-64.so.2', '.ko'],
    })) as any

    expect(result.ok).toBe(true)
    expect(result.data.platform).toBe('linux')
    expect(result.data.execution_semantics).toEqual(
      expect.objectContaining({ actual_mode: 'plan_only', live_execution: false })
    )
    expect(result.data.readiness).toEqual(
      expect.objectContaining({
        status: 'plan_only',
        opt_in_required: true,
        requires_isolation: true,
        policy_denied: true,
      })
    )
    expect(result.data.selected_backends.map((backend: any) => backend.backend)).toEqual([
      'qiling',
      'gdb',
      'strace',
      'ebpf',
    ])
    expect(result.data.static_correlation.mapping.join(' ')).toMatch(/kernel-module/)
    expect(result.data.recommended_next_tools).toEqual(
      expect.arrayContaining([
        'linux.binary.inventory',
        'linux.package.inventory',
        'dynamic.runtime.status',
        'tool.readiness',
      ])
    )
    expect(result.data.safety_notes.join(' ')).toMatch(/Do not run ELF files/)
    expect(result.data.safety_notes.join(' ')).toMatch(/load kernel modules/)
    expect(result.data.safety_notes.join(' ')).toMatch(/install packages/)
  })

  test('declares Linux runtime search profile for ELF, core, packages, and kernel modules', async () => {
    resetSurfaceForTest()
    const surface = getToolSurfaceManager()
    surface.registerPlugin(
      linuxRuntimePlugin,
      linuxRuntimePlugin.tools.map((tool) => tool.definition.name)
    )

    expect(linuxRuntimePlugin.executionDomain).toBe('dynamic')
    expect(linuxRuntimePlugin.aspects?.formats).toEqual(
      expect.arrayContaining([
        'linux-binary',
        'elf',
        'elf-core',
        'core',
        'linux-kernel-module',
        'ko',
        'deb',
        'rpm',
        'snap',
        'flatpak',
        'initramfs',
        'cpio',
      ])
    )
    expect(linuxRuntimePlugin.aspects?.capabilities).toEqual(
      expect.arrayContaining([
        'readiness-profile',
        'runtime-plan',
        'strace-plan',
        'ltrace-plan',
        'seccomp-plan',
        'ebpf-plan',
        'core-dump-analysis',
      ])
    )
    expect(linuxRuntimePlugin.runtimePolicy).toEqual(
      expect.objectContaining({
        passiveByDefault: true,
        requiresUserOptIn: true,
        requiresIsolation: true,
        networkPolicy: 'disabled',
      })
    )

    const handler = createWorkflowSearchHandler(createPluginManager([linuxRuntimePlugin]))
    const result = await handler({
      file_type: '.ko',
      query: 'kernel module eBPF seccomp strace runtime plan',
      goal: 'dynamic',
      depth: 'safe',
      top_k: 3,
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.search_profile.file_type_tags).toContain('ko')
    expect(data.results[0]).toEqual(
      expect.objectContaining({
        plugin_id: 'linux-runtime',
        readiness_state: 'runtime_opt_in_required',
        recommended_tools: expect.arrayContaining(['linux.runtime.plan']),
      })
    )
    expect(data.results[0].matched_profile_fields.join(' ')).toMatch(/file_type|goal=dynamic/)
  })
})
