/**
 * Memory Forensics Plugin
 *
 * Integrates with Volatility 3 for memory dump analysis.
 * Provides tools for process listing, DLL extraction, registry hive parsing,
 * and memory-resident malware detection from memory dumps.
 */

import { execFile } from 'child_process'
import { promisify } from 'util'
import { z } from 'zod'
import {
  getWorkspaceManager,
  type Plugin,
  type ToolDefinition,
  type ToolResult,
  type PluginToolDeps,
} from '../sdk.js'
import {
  buildMemoryForensicsCorrelation,
  MEMORY_FORENSICS_FOLLOW_UP_TOOLS,
  MEMORY_FORENSICS_ROUTE_TERMS,
  MEMORY_FORENSICS_SEARCH_TERMS,
  MEMORY_FORENSICS_QUALITY_GATES_SCHEMA,
  MemoryCorrelationInputSchema,
  MemoryCorrelationOutputSchema,
} from './memory-correlation.js'

const execFileAsync = promisify(execFile)

const dumpInputSchema = z.object({
  sample_id: z.string().optional().describe('Sample ID of the memory dump'),
  dump_path: z.string().optional().describe('Direct path to memory dump file'),
})

const pidDumpInputSchema = dumpInputSchema.extend({
  pid: z.number().int().positive().optional().describe('Filter by Process ID'),
})

const volatilityOutputSchema = z.object({}).passthrough()

const MEMORY_FORENSICS_RUNTIME_POLICY = {
  passiveByDefault: true,
  requiresUserOptIn: false,
  requiresIsolation: false,
  allowedBackends: ['local'],
  networkPolicy: 'disabled',
  noNetwork: true,
  noMutation: true,
  noLiveExecution: true,
  noLiveMemoryAccess: true,
  notes: [
    'memory-forensics.correlate consumes existing JSON rows and never invokes Volatility.',
    'Volatility-backed tools read offline memory dump files only; they do not acquire live memory or execute samples.',
  ],
} as ToolDefinition['runtimePolicy'] & {
  noNetwork: true
  noMutation: true
  noLiveExecution: true
  noLiveMemoryAccess: true
}

function getVolatilityPath(): string {
  return process.env.VOLATILITY3_PATH || process.env.VOL3_PATH || 'vol3'
}

async function runVol3(args: string[], timeout = 120_000): Promise<string> {
  const vol3 = getVolatilityPath()
  const { stdout } = await execFileAsync(vol3, args, {
    timeout,
    maxBuffer: 50 * 1024 * 1024,
    env: { ...process.env },
  })
  return stdout
}

async function resolveDumpPath(
  args: { sample_id?: string; dump_path?: string },
  deps: PluginToolDeps
): Promise<string> {
  if (args.dump_path) return args.dump_path
  if (!args.sample_id) throw new Error('Either sample_id or dump_path must be provided')

  const wm = getWorkspaceManager(deps)
  if (typeof wm.getSamplePath === 'function') {
    return wm.getSamplePath(args.sample_id)
  }
  throw new Error('Cannot resolve sample path — provide dump_path directly')
}

function tryParseJson(text: string): Record<string, unknown> {
  try {
    return JSON.parse(text) as Record<string, unknown>
  } catch {
    return { raw_output: text }
  }
}

const memoryForensicsPlugin: Plugin = {
  id: 'memory-forensics',
  name: 'Memory Forensics (Volatility 3)',
  executionDomain: 'static',
  aspects: {
    formats: ['memory-dump', 'memory-image', 'vmem', 'dmp', 'elf-core'],
    platforms: ['windows', 'linux', 'macos'],
    execution: ['static', 'triage'],
    safety: ['passive', 'no_live_sample_by_default'],
    capabilities: [
      'process-list',
      'module-list',
      'memory-region-scan',
      'network-scan',
      'registry-scan',
      'command-line-extraction',
      'offline-correlation',
      'memory-trace-fusion',
      'workflow-plan',
      'workflow-handoff',
    ],
    evidence: [
      'memory',
      'process',
      'filesystem',
      'registry',
      'network',
      'behavior',
      'workflow',
      'correlation-graph',
      'provenance',
    ],
    search: MEMORY_FORENSICS_SEARCH_TERMS,
    route_terms: MEMORY_FORENSICS_ROUTE_TERMS,
  },
  runtimePolicy: MEMORY_FORENSICS_RUNTIME_POLICY,
  surfaceRules: { tier: 3, category: 'memory-forensics' },
  description:
    'Memory dump analysis using Volatility 3 — process listing, DLL extraction, registry analysis, and memory-resident malware detection.',
  version: '1.0.0',
  configSchema: [
    {
      envVar: 'VOLATILITY3_PATH',
      description: 'Path to Volatility 3 (vol3) executable',
      required: true,
    },
    {
      envVar: 'VOL3_SYMBOL_PATH',
      description: 'Path to Volatility 3 symbol tables',
      required: false,
    },
  ],
  systemDeps: [
    {
      type: 'binary',
      name: 'vol3',
      versionFlag: '--help',
      envVar: 'VOLATILITY3_PATH',
      dockerDefault: '/usr/local/bin/vol',
      required: true,
      description: 'Volatility 3 memory forensics framework',
      dockerInstall: 'pip install volatility3',
      dockerFeature: 'vol3',
      dockerValidation: ['HOME=/tmp/rikune-home /usr/local/bin/vol --help >/dev/null'],
    },
    {
      type: 'directory',
      name: 'vol3-symbols',
      target: '$VOL3_SYMBOL_PATH',
      envVar: 'VOL3_SYMBOL_PATH',
      dockerDefault: '/opt/vol3-symbols',
      required: false,
      description: 'Volatility 3 symbol tables',
      dockerFeature: 'vol3',
      directories: [{ path: '/opt/vol3-symbols' }],
    },
  ],

  register(server, deps): string[] {
    const tools: string[] = []

    // ── memory-forensics.pslist ──────────────────────────────────────────
    server.registerTool(
      {
        name: 'memory-forensics.pslist',
        description: 'List processes from a memory dump using Volatility 3.',
        inputSchema: dumpInputSchema,
        outputSchema: volatilityOutputSchema,
        aspects: {
          formats: ['memory-dump', 'memory-image', 'vmem', 'dmp'],
          platforms: ['windows', 'linux', 'macos'],
          execution: ['static', 'triage'],
          safety: ['passive'],
          evidence: ['memory', 'process'],
        },
        artifacts: [
          {
            type: 'memory_process_list',
            description: 'Process listing recovered from a memory dump',
            mime: 'application/json',
          },
        ],
        evidence: [
          { category: 'memory', artifactTypes: ['memory_process_list'] },
          { category: 'process', artifactTypes: ['memory_process_list'] },
        ],
      },
      async (args: { sample_id?: string; dump_path?: string }): Promise<ToolResult> => {
        const dumpPath = await resolveDumpPath(args, deps)
        const output = await runVol3(['-f', dumpPath, 'windows.pslist.PsList', '--output', 'json'])
        const data = tryParseJson(output)
        return {
          content: [{ type: 'text', text: JSON.stringify(data, null, 2) }],
          structuredContent: data,
        }
      }
    )
    tools.push('memory-forensics.pslist')

    // ── memory-forensics.dlllist ─────────────────────────────────────────
    server.registerTool(
      {
        name: 'memory-forensics.dlllist',
        description: 'List loaded DLLs from a memory dump.',
        inputSchema: pidDumpInputSchema,
        outputSchema: volatilityOutputSchema,
        aspects: {
          formats: ['memory-dump', 'memory-image', 'vmem', 'dmp'],
          platforms: ['windows'],
          execution: ['static', 'triage'],
          safety: ['passive'],
          evidence: ['memory', 'filesystem', 'process'],
        },
        artifacts: [
          {
            type: 'memory_module_list',
            description: 'Loaded module and DLL listing recovered from a memory dump',
            mime: 'application/json',
          },
        ],
        evidence: [
          { category: 'memory', artifactTypes: ['memory_module_list'] },
          { category: 'filesystem', artifactTypes: ['memory_module_list'] },
          { category: 'process', artifactTypes: ['memory_module_list'] },
        ],
      },
      async (args: {
        sample_id?: string
        dump_path?: string
        pid?: number
      }): Promise<ToolResult> => {
        const dumpPath = await resolveDumpPath(args, deps)
        const vol3Args = ['-f', dumpPath, 'windows.dlllist.DllList', '--output', 'json']
        if (args.pid) vol3Args.push('--pid', String(args.pid))
        const output = await runVol3(vol3Args)
        const data = tryParseJson(output)
        return {
          content: [{ type: 'text', text: JSON.stringify(data, null, 2) }],
          structuredContent: data,
        }
      }
    )
    tools.push('memory-forensics.dlllist')

    // ── memory-forensics.malfind ─────────────────────────────────────────
    server.registerTool(
      {
        name: 'memory-forensics.malfind',
        description: 'Detect injected code and suspicious memory regions in a memory dump.',
        inputSchema: pidDumpInputSchema,
        outputSchema: volatilityOutputSchema,
        aspects: {
          formats: ['memory-dump', 'memory-image', 'vmem', 'dmp'],
          platforms: ['windows'],
          execution: ['static', 'triage'],
          safety: ['passive'],
          evidence: ['memory', 'process', 'behavior'],
        },
        artifacts: [
          {
            type: 'memory_suspicious_regions',
            description: 'Suspicious injected or executable memory-region findings',
            mime: 'application/json',
          },
        ],
        evidence: [
          { category: 'memory', artifactTypes: ['memory_suspicious_regions'] },
          { category: 'process', artifactTypes: ['memory_suspicious_regions'] },
          { category: 'behavior', artifactTypes: ['memory_suspicious_regions'] },
        ],
      },
      async (args: {
        sample_id?: string
        dump_path?: string
        pid?: number
      }): Promise<ToolResult> => {
        const dumpPath = await resolveDumpPath(args, deps)
        const vol3Args = ['-f', dumpPath, 'windows.malfind.Malfind', '--output', 'json']
        if (args.pid) vol3Args.push('--pid', String(args.pid))
        const output = await runVol3(vol3Args)
        const data = tryParseJson(output)
        return {
          content: [{ type: 'text', text: JSON.stringify(data, null, 2) }],
          structuredContent: data,
        }
      }
    )
    tools.push('memory-forensics.malfind')

    // ── memory-forensics.netscan ─────────────────────────────────────────
    server.registerTool(
      {
        name: 'memory-forensics.netscan',
        description: 'Scan for network connections in a memory dump.',
        inputSchema: dumpInputSchema,
        outputSchema: volatilityOutputSchema,
        aspects: {
          formats: ['memory-dump', 'memory-image', 'vmem', 'dmp'],
          platforms: ['windows'],
          execution: ['static', 'triage'],
          safety: ['passive', 'no_network_by_default'],
          evidence: ['memory', 'network', 'process'],
        },
        artifacts: [
          {
            type: 'memory_network_scan',
            description: 'Network connection scan recovered from a memory dump',
            mime: 'application/json',
          },
        ],
        evidence: [
          { category: 'memory', artifactTypes: ['memory_network_scan'] },
          { category: 'network', artifactTypes: ['memory_network_scan'] },
          { category: 'process', artifactTypes: ['memory_network_scan'] },
        ],
      },
      async (args: { sample_id?: string; dump_path?: string }): Promise<ToolResult> => {
        const dumpPath = await resolveDumpPath(args, deps)
        const output = await runVol3([
          '-f',
          dumpPath,
          'windows.netscan.NetScan',
          '--output',
          'json',
        ])
        const data = tryParseJson(output)
        return {
          content: [{ type: 'text', text: JSON.stringify(data, null, 2) }],
          structuredContent: data,
        }
      }
    )
    tools.push('memory-forensics.netscan')

    // ── memory-forensics.hivelist ────────────────────────────────────────
    server.registerTool(
      {
        name: 'memory-forensics.hivelist',
        description: 'List registry hives found in a memory dump.',
        inputSchema: dumpInputSchema,
        outputSchema: volatilityOutputSchema,
        aspects: {
          formats: ['memory-dump', 'memory-image', 'vmem', 'dmp'],
          platforms: ['windows'],
          execution: ['static', 'triage'],
          safety: ['passive'],
          evidence: ['memory', 'registry'],
        },
        artifacts: [
          {
            type: 'memory_registry_hives',
            description: 'Registry hive listing recovered from a memory dump',
            mime: 'application/json',
          },
        ],
        evidence: [
          { category: 'memory', artifactTypes: ['memory_registry_hives'] },
          { category: 'registry', artifactTypes: ['memory_registry_hives'] },
        ],
      },
      async (args: { sample_id?: string; dump_path?: string }): Promise<ToolResult> => {
        const dumpPath = await resolveDumpPath(args, deps)
        const output = await runVol3([
          '-f',
          dumpPath,
          'windows.registry.hivelist.HiveList',
          '--output',
          'json',
        ])
        const data = tryParseJson(output)
        return {
          content: [{ type: 'text', text: JSON.stringify(data, null, 2) }],
          structuredContent: data,
        }
      }
    )
    tools.push('memory-forensics.hivelist')

    // ── memory-forensics.cmdline ─────────────────────────────────────────
    server.registerTool(
      {
        name: 'memory-forensics.cmdline',
        description: 'Extract command-line arguments for all processes in a memory dump.',
        inputSchema: pidDumpInputSchema,
        outputSchema: volatilityOutputSchema,
        aspects: {
          formats: ['memory-dump', 'memory-image', 'vmem', 'dmp'],
          platforms: ['windows'],
          execution: ['static', 'triage'],
          safety: ['passive'],
          evidence: ['memory', 'process', 'behavior'],
        },
        artifacts: [
          {
            type: 'memory_cmdline',
            description: 'Process command lines recovered from a memory dump',
            mime: 'application/json',
          },
        ],
        evidence: [
          { category: 'memory', artifactTypes: ['memory_cmdline'] },
          { category: 'process', artifactTypes: ['memory_cmdline'] },
          { category: 'behavior', artifactTypes: ['memory_cmdline'] },
        ],
      },
      async (args: {
        sample_id?: string
        dump_path?: string
        pid?: number
      }): Promise<ToolResult> => {
        const dumpPath = await resolveDumpPath(args, deps)
        const vol3Args = ['-f', dumpPath, 'windows.cmdline.CmdLine', '--output', 'json']
        if (args.pid) vol3Args.push('--pid', String(args.pid))
        const output = await runVol3(vol3Args)
        const data = tryParseJson(output)
        return {
          content: [{ type: 'text', text: JSON.stringify(data, null, 2) }],
          structuredContent: data,
        }
      }
    )
    tools.push('memory-forensics.cmdline')

    // -- memory-forensics.correlate -----------------------------------------
    server.registerTool(
      {
        name: 'memory-forensics.correlate',
        description:
          'Correlate existing Volatility JSON or fixture rows into an offline memory-forensics finding bundle with process, module, malfind, netscan, registry, command-line, IOC, timeline, and provenance views. This tool never invokes Volatility or touches live memory.',
        inputSchema: MemoryCorrelationInputSchema,
        outputSchema: MemoryCorrelationOutputSchema,
        aspects: {
          formats: ['memory-dump', 'memory-image', 'vmem', 'dmp', 'elf-core'],
          platforms: ['windows', 'linux', 'macos'],
          execution: ['static', 'correlation'],
          safety: ['passive', 'no_live_sample_by_default', 'no_network_by_default'],
          capabilities: [
            'offline-correlation',
            'process-tree',
            'ioc-candidates',
            'behavior-timeline',
            'memory-trace-fusion',
            'workflow-plan',
            'workflow-handoff',
          ],
          evidence: [
            'memory',
            'process',
            'network',
            'registry',
            'behavior',
            'workflow',
            'correlation-graph',
            'provenance',
          ],
          search: MEMORY_FORENSICS_SEARCH_TERMS,
          route_terms: MEMORY_FORENSICS_ROUTE_TERMS,
        },
        artifacts: [
          {
            type: 'memory_forensics_correlation',
            description: 'Offline correlation bundle from Volatility-derived memory-forensics rows',
            mime: 'application/json',
          },
          {
            type: 'behavior_timeline',
            description: 'Behavior timeline derived from memory-forensics evidence',
            mime: 'application/json',
          },
          {
            type: 'ioc_candidates',
            description: 'Network and process IOC candidates derived from memory evidence',
            mime: 'application/json',
          },
        ],
        evidence: [
          { category: 'memory', artifactTypes: ['memory_forensics_correlation'] },
          { category: 'process', artifactTypes: ['memory_forensics_correlation'] },
          { category: 'network', artifactTypes: ['ioc_candidates'] },
          { category: 'registry', artifactTypes: ['memory_forensics_correlation'] },
          { category: 'behavior', artifactTypes: ['behavior_timeline'] },
          { category: 'correlation-graph', artifactTypes: ['memory_forensics_correlation'] },
          { category: 'provenance', artifactTypes: ['memory_forensics_correlation'] },
        ],
        workflowRecipes: [
          {
            id: 'memory-forensics.offline-correlation',
            title: 'Offline memory forensics correlation',
            startsWith: ['memory-forensics.correlate'],
            nextTools: MEMORY_FORENSICS_FOLLOW_UP_TOOLS,
            requiredArtifacts: [
              'memory_process_list',
              'memory_suspicious_regions',
              'memory_network_scan',
            ],
            producesArtifacts: [
              'memory_forensics_correlation',
              'behavior_timeline',
              'ioc_candidates',
            ],
            evidence: ['memory', 'process', 'network', 'registry', 'behavior', 'provenance'],
            safety: ['passive', 'no_live_sample_by_default', 'no_network_by_default'],
            quality_gates: {
              schema: MEMORY_FORENSICS_QUALITY_GATES_SCHEMA,
              volatility_invoked_by_tool: false,
              live_memory_access: false,
            },
          },
        ],
        runtimePolicy: MEMORY_FORENSICS_RUNTIME_POLICY,
        workerBackend: {
          version: 'backend-worker.v1',
          backendName: 'Builtin memory forensics offline correlation',
          backendKind: 'builtin',
          adapter: 'builtin.memory-forensics.offline-correlation',
          availability: 'builtin',
          supportedModes: ['offline-correlation'],
          defaultMode: 'offline-correlation',
          inputArtifactTypes: [
            'memory_process_list',
            'memory_suspicious_regions',
            'memory_network_scan',
            'memory_registry_hives',
            'memory_cmdline',
          ],
          outputArtifactTypes: [
            'memory_forensics_correlation',
            'behavior_timeline',
            'ioc_candidates',
          ],
          policy: {
            passiveByDefault: true,
            requiresUserOptIn: false,
            requiresIsolation: false,
            noNetwork: true,
            noMutation: true,
            noLiveExecution: true,
            noLiveMemoryAccess: true,
            defaultTimeoutMs: 5_000,
            notes: [
              'Offline correlation consumes caller-provided Volatility JSON rows only.',
              'Readiness and correlation do not invoke Volatility, read raw dump content, acquire live memory, or start runtime tooling.',
            ],
          },
          readiness: {
            doesNotStartBackend: true,
            setupActions: [],
            missingBackendBehavior:
              'Offline correlation is builtin and does not require Volatility unless the user explicitly activates raw memory-dump extraction tools.',
          },
        },
      },
      async (args: unknown): Promise<ToolResult> => {
        const data = buildMemoryForensicsCorrelation(args)
        return {
          content: [{ type: 'text', text: JSON.stringify(data, null, 2) }],
          structuredContent: data,
        }
      }
    )
    tools.push('memory-forensics.correlate')

    return tools
  },
}

export default memoryForensicsPlugin
