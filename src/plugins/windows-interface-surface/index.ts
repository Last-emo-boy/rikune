/**
 * Windows Interface Surface Plugin
 *
 * Passive Windows userland interface inventory. It reads bounded bytes only and
 * never activates COM, calls RPC, connects ALPC/named pipes, queries WMI,
 * starts services, registers ETW providers, invokes external tools, or mutates
 * samples.
 */

import { definePlugin, defineTool } from '../sdk.js'
import {
  createWindowsInterfaceSurfaceInventoryHandler,
  windowsInterfaceSurfaceInventoryAspects,
  windowsInterfaceSurfaceInventoryToolDefinition,
} from './tools/windows-interface-surface-inventory.js'

const windowsInterfaceSurfacePlugin = definePlugin({
  id: 'windows-interface-surface',
  name: 'Windows Interface Surface Inventory',
  executionDomain: 'static',
  aspects: windowsInterfaceSurfaceInventoryAspects,
  surfaceRules: {
    tier: 2,
    activateOn: {
      fileTypes: [
        'windows-interface',
        'com',
        'dcom',
        'rpc',
        'alpc',
        'etw',
        'wmi',
        'named-pipe',
        'service-control',
        'winrt',
        'typelib',
        'tlb',
        'idl',
        'winmd',
        'pe',
      ],
      findings: [
        'CLSID',
        'IID',
        'CoCreateInstance',
        'DllRegisterServer',
        'RpcServerRegisterIf',
        'RpcBinding',
        'ncacn_np',
        'ncalrpc',
        '\\\\.\\pipe\\',
        '\\RPC Control\\',
        'NtAlpc',
        'EventRegister',
        'TraceLoggingProvider',
        'IWbemServices',
        'root\\cimv2',
        'OpenSCManager',
        'CreateService',
        'StartService',
      ],
    },
    category: 'static-analysis',
  },
  description:
    'Passive Windows userland interface inventory for COM/DCOM CLSID/IID evidence, RPC UUID/endpoints, ALPC and named-pipe IPC, ETW provider hints, WMI namespaces/classes, service-control strings, and static workflow handoff.',
  version: '1.0.0',
  tools: [
    defineTool({
      ...windowsInterfaceSurfaceInventoryToolDefinition,
      handler: (args, deps) => createWindowsInterfaceSurfaceInventoryHandler(deps)(args as never),
    }),
  ],
})

export default windowsInterfaceSurfacePlugin
