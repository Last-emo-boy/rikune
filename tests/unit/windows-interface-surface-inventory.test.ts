import { describe, expect, test } from '@jest/globals'
import windowsInterfaceSurfacePlugin from '../../src/plugins/windows-interface-surface/index.js'
import {
  WINDOWS_INTERFACE_SURFACE_ARTIFACT_TYPE,
  buildWindowsInterfaceSurfaceInventoryFromBuffer,
  createWindowsInterfaceSurfaceInventoryHandler,
  windowsInterfaceSurfaceInventoryToolDefinition,
} from '../../src/plugins/windows-interface-surface/tools/windows-interface-surface-inventory.js'

describe('windows.interface.surface.inventory', () => {
  test('declares passive Windows interface surface metadata', () => {
    expect(windowsInterfaceSurfacePlugin.id).toBe('windows-interface-surface')
    expect(windowsInterfaceSurfacePlugin.executionDomain).toBe('static')
    expect(windowsInterfaceSurfacePlugin.surfaceRules?.tier).toBe(2)
    expect(windowsInterfaceSurfacePlugin.surfaceRules?.activateOn?.fileTypes).toEqual(
      expect.arrayContaining(['windows-interface', 'com', 'rpc', 'alpc', 'etw', 'wmi'])
    )
    expect(windowsInterfaceSurfaceInventoryToolDefinition.name).toBe(
      'windows.interface.surface.inventory'
    )
    expect(
      windowsInterfaceSurfaceInventoryToolDefinition.artifacts?.map((artifact) => artifact.type)
    ).toEqual(expect.arrayContaining([WINDOWS_INTERFACE_SURFACE_ARTIFACT_TYPE]))

    const recipe = windowsInterfaceSurfaceInventoryToolDefinition.workflowRecipes?.find(
      (candidate) => candidate.id === 'windows.interface-surface-static-inventory'
    )
    expect(recipe).toEqual(
      expect.objectContaining({
        startsWith: ['windows.interface.surface.inventory'],
        producesArtifacts: [WINDOWS_INTERFACE_SURFACE_ARTIFACT_TYPE],
        safety: expect.arrayContaining([
          'passive',
          'no_com_activation',
          'no_rpc_call',
          'no_alpc_connect',
          'no_named_pipe_connect',
          'no_wmi_query',
          'no_service_start',
          'no_etw_registration',
        ]),
      })
    )
    expect(recipe?.nextTools).toEqual(
      expect.arrayContaining([
        'pe.imports.extract',
        'static.resource.graph',
        'code.xrefs.analyze',
        'analysis.evidence.graph',
        'workflow.search',
      ])
    )
  })

  test('summarizes COM, RPC, IPC, ETW, WMI, service, and risk evidence', () => {
    const inventory = buildWindowsInterfaceSurfaceInventoryFromBuffer(
      Buffer.from(
        [
          'MZ',
          'CLSID',
          '{11111111-2222-3333-4444-555555555555}',
          'IID',
          '{aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee}',
          'CoCreateInstance',
          'DllRegisterServer',
          'DCOM',
          'RpcServerRegisterIf',
          'ncacn_ip_tcp',
          '{12345678-1234-5678-9abc-def012345678}',
          '\\\\.\\pipe\\svcctl',
          'CreateNamedPipeW',
          'ImpersonateNamedPipeClient',
          'EventRegister',
          'TraceLoggingProvider',
          '{87654321-4321-8765-cba9-210fedcba987}',
          'IWbemServices',
          'root\\subscription',
          '__EventFilter',
          'CommandLineEventConsumer',
          'OpenSCManagerW',
          'CreateServiceW',
        ].join('\0'),
        'ascii'
      ),
      { filename: 'broker.dll', sampleId: 'sha256:windows-interface' }
    )

    expect(inventory.format).toBe('windows-rpc-interface-surface')
    expect(inventory.platforms).toEqual(['windows'])
    expect(inventory.detected_by).toEqual(
      expect.arrayContaining(['pe-magic', 'interface-string-or-guid-evidence'])
    )
    expect((inventory.com_surface as any).present).toBe(true)
    expect((inventory.com_surface as any).activation_api_count).toBeGreaterThan(0)
    expect((inventory.com_surface as any).dcom_hint).toBe(true)
    expect((inventory.rpc_surface as any).present).toBe(true)
    expect((inventory.rpc_surface as any).has_remote_protocol_hint).toBe(true)
    expect((inventory.ipc_surface as any).present).toBe(true)
    expect((inventory.ipc_surface as any).impersonation_hint).toBe(true)
    expect((inventory.etw_surface as any).present).toBe(true)
    expect((inventory.wmi_surface as any).present).toBe(true)
    expect((inventory.wmi_surface as any).persistence_hint).toBe(true)
    expect((inventory.service_surface as any).present).toBe(true)
    expect(inventory.risk_flags).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ id: 'windows.dcom-remote-interface' }),
        expect.objectContaining({ id: 'windows.rpc-remote-protocol' }),
        expect.objectContaining({ id: 'windows.ipc-impersonation-surface', severity: 'high' }),
        expect.objectContaining({ id: 'windows.wmi-persistence-surface' }),
        expect.objectContaining({ id: 'windows.service-control-surface' }),
        expect.objectContaining({ id: 'windows.multi-interface-orchestration' }),
      ])
    )
    expect(inventory.policy).toEqual(
      expect.objectContaining({
        passive: true,
        no_com_activation: true,
        no_rpc_call: true,
        no_named_pipe_connect: true,
        no_wmi_query: true,
        no_service_start: true,
        no_etw_registration: true,
      })
    )
    expect(inventory.quality_gates).toEqual(
      expect.objectContaining({
        passive_static_inventory: true,
        sample_executed_by_tool: false,
        com_activated_by_tool: false,
        rpc_called_by_tool: false,
        named_pipe_connected_by_tool: false,
        wmi_queried_by_tool: false,
        service_started_by_tool: false,
      })
    )
    expect((inventory.workflow_handoff as any).runtime_policy).toEqual(
      expect.objectContaining({
        runtime_not_started_by_tool: true,
        runtime_requires_explicit_opt_in: true,
      })
    )
  })

  test('recognizes TypeLib containers without executing or loading them', () => {
    const inventory = buildWindowsInterfaceSurfaceInventoryFromBuffer(
      Buffer.from(
        'TYPELIB\0LIBID\0ITypeLib\0CLSID\0{99999999-8888-7777-6666-555555555555}',
        'ascii'
      ),
      { filename: 'component.tlb' }
    )

    expect(inventory.format).toBe('windows-com-interface-surface')
    expect((inventory.container as any).typelib).toBe(true)
    expect((inventory.com_surface as any).present).toBe(true)
    expect(inventory.policy.no_execute).toBe(true)
    expect(inventory.quality_gates.external_tool_invoked_by_tool).toBe(false)
  })

  test('handler degrades clearly when sample resolution is unavailable', async () => {
    const handler = createWindowsInterfaceSurfaceInventoryHandler()
    const result = await handler({ sample_id: 'sha256:test' })

    expect(result.ok).toBe(false)
    expect(result.errors?.join(' ')).toContain('resolvePrimarySamplePath dependency is unavailable')
  })
})
