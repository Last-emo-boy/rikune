/**
 * bytecode.taint — IL/bytecode-level taint tracking.
 *
 * Performs taint analysis at the IL (.NET) or bytecode (Java/Dalvik) level,
 * tracking data flow from sources (user input, file reads, network)
 * to sinks (exec, file write, crypto, network send).
 */

import { z } from 'zod'
import type { ToolDefinition, ToolArgs, WorkerResult, ArtifactRef } from '../types.js'
import type { WorkspaceManager } from '../workspace-manager.js'
import type { DatabaseManager } from '../database.js'
import type { CacheManager } from '../cache-manager.js'
import { generateCacheKey } from '../cache-manager.js'
import { lookupCachedResult, formatCacheWarning } from './cache-observability.js'
import { resolvePrimarySamplePath } from '../sample-workspace.js'
import { persistStaticAnalysisJsonArtifact } from '../static-analysis-artifacts.js'
import {
  buildStaticWorkerRequest,
  callStaticWorker as callPooledStaticWorker,
} from './static-worker-client.js'

const TOOL_NAME = 'bytecode.taint'
const TOOL_VERSION = '0.1.0'
const CACHE_TTL_MS = 30 * 24 * 60 * 60 * 1000

export const BytecodeTaintInputSchema = z.object({
  sample_id: z.string().describe('Sample identifier (sha256:<hex>)'),
  runtime: z.enum(['dotnet', 'java', 'auto']).default('auto')
    .describe('Target runtime for taint analysis'),
  source_categories: z.array(z.enum([
    'user_input',
    'file_read',
    'network_recv',
    'registry_read',
    'environment',
    'command_line',
    'clipboard',
    'crypto_key',
  ])).default(['user_input', 'file_read', 'network_recv', 'registry_read'])
    .describe('Taint source categories to track'),
  sink_categories: z.array(z.enum([
    'exec',
    'file_write',
    'network_send',
    'registry_write',
    'crypto_operation',
    'reflection_invoke',
    'process_create',
    'memory_write',
    'serialization',
  ])).default(['exec', 'file_write', 'network_send', 'crypto_operation', 'reflection_invoke'])
    .describe('Taint sink categories to detect'),
  max_depth: z.number().int().min(1).max(20).default(10)
    .describe('Maximum call depth for inter-procedural taint tracking'),
  target_method: z.string().optional()
    .describe('Limit taint tracking to a specific method entry point'),
  force_refresh: z.boolean().default(false),
})
export type BytecodeTaintInput = z.infer<typeof BytecodeTaintInputSchema>

export const bytecodeTaintToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Bytecode-level taint tracking for .NET IL and Java/Dalvik bytecode. ' +
    'Traces data flow from sources (user input, file/network reads, registry) to sinks ' +
    '(exec, file/network writes, crypto, reflection). Supports inter-procedural analysis ' +
    'with configurable call depth. Identifies injection vulnerabilities, data exfiltration ' +
    'paths, and crypto key handling issues.',
  inputSchema: BytecodeTaintInputSchema,
}

// ── Source/Sink API mappings ──────────────────────────────────────────────
const DOTNET_SOURCES: Record<string, string[]> = {
  user_input: ['Console.ReadLine', 'TextBox.Text', 'Request.QueryString', 'Request.Form'],
  file_read: ['File.ReadAllText', 'File.ReadAllBytes', 'StreamReader.Read', 'FileStream.Read'],
  network_recv: ['WebClient.DownloadString', 'HttpClient.GetAsync', 'Socket.Receive', 'NetworkStream.Read'],
  registry_read: ['Registry.GetValue', 'RegistryKey.GetValue'],
  environment: ['Environment.GetEnvironmentVariable', 'Environment.CommandLine'],
  command_line: ['Environment.GetCommandLineArgs'],
  clipboard: ['Clipboard.GetText'],
  crypto_key: ['ProtectedData.Unprotect', 'RegistryKey.GetValue'],
}

const DOTNET_SINKS: Record<string, string[]> = {
  exec: ['Process.Start', 'Assembly.Load', 'Activator.CreateInstance'],
  file_write: ['File.WriteAllText', 'File.WriteAllBytes', 'StreamWriter.Write'],
  network_send: ['WebClient.UploadString', 'HttpClient.PostAsync', 'Socket.Send'],
  registry_write: ['Registry.SetValue', 'RegistryKey.SetValue'],
  crypto_operation: ['Aes.CreateEncryptor', 'RSA.Encrypt', 'SHA256.ComputeHash'],
  reflection_invoke: ['MethodInfo.Invoke', 'Type.InvokeMember'],
  process_create: ['Process.Start', 'ProcessStartInfo'],
  memory_write: ['Marshal.Copy', 'Marshal.WriteByte'],
  serialization: ['BinaryFormatter.Deserialize', 'XmlSerializer.Deserialize'],
}

const JAVA_SOURCES: Record<string, string[]> = {
  user_input: ['Scanner.nextLine', 'BufferedReader.readLine', 'getIntent().getStringExtra'],
  file_read: ['FileInputStream.read', 'Files.readAllBytes', 'BufferedReader.readLine'],
  network_recv: ['URLConnection.getInputStream', 'Socket.getInputStream', 'HttpURLConnection.getInputStream'],
  registry_read: [],
  environment: ['System.getenv', 'System.getProperty'],
  command_line: ['main(String[])'],
  clipboard: ['Toolkit.getSystemClipboard'],
  crypto_key: ['KeyStore.getKey', 'SecretKeyFactory.generateSecret'],
}

const JAVA_SINKS: Record<string, string[]> = {
  exec: ['Runtime.exec', 'ProcessBuilder.start', 'Class.forName'],
  file_write: ['FileOutputStream.write', 'Files.write', 'BufferedWriter.write'],
  network_send: ['URLConnection.getOutputStream', 'Socket.getOutputStream', 'HttpURLConnection.getOutputStream'],
  registry_write: [],
  crypto_operation: ['Cipher.doFinal', 'MessageDigest.digest', 'Mac.doFinal'],
  reflection_invoke: ['Method.invoke', 'Constructor.newInstance'],
  process_create: ['Runtime.exec', 'ProcessBuilder.start'],
  memory_write: [],
  serialization: ['ObjectInputStream.readObject', 'XMLDecoder.readObject'],
}

export function createBytecodeTaintHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
  cacheManager: CacheManager,
) {
  return async (args: ToolArgs): Promise<WorkerResult> => {
    const input = BytecodeTaintInputSchema.parse(args)
    const startTime = Date.now()

    try {
      const sample = database.findSample(input.sample_id)
      if (!sample) {
        return { ok: false, errors: [`Sample not found: ${input.sample_id}`] }
      }

      // Cache check
      const cacheKey = generateCacheKey({
        sampleSha256: sample.sha256,
        toolName: TOOL_NAME,
        toolVersion: TOOL_VERSION,
        args: {
          runtime: input.runtime,
          source_categories: input.source_categories,
          sink_categories: input.sink_categories,
          max_depth: input.max_depth,
          target_method: input.target_method || null,
        },
      })

      if (!input.force_refresh) {
        const cached = await lookupCachedResult(cacheManager, cacheKey)
        if (cached) {
          return {
            ok: true,
            data: cached.data,
            warnings: ['Result from cache', formatCacheWarning(cached.metadata)],
            metrics: { elapsed_ms: Date.now() - startTime, tool: TOOL_NAME, cached: true },
          }
        }
      }

      const { samplePath } = await resolvePrimarySamplePath(workspaceManager, input.sample_id)

      // Call Python worker for actual taint analysis
      const workerRequest = buildStaticWorkerRequest({
        tool: TOOL_NAME,
        sampleId: input.sample_id,
        samplePath,
        args: {
          runtime: input.runtime,
          source_categories: input.source_categories,
          sink_categories: input.sink_categories,
          max_depth: input.max_depth,
          target_method: input.target_method || null,
        },
        toolVersion: TOOL_VERSION,
      })
      const workerResponse = await callPooledStaticWorker(workerRequest, { database })

      if (!workerResponse.ok) {
        // Fallback: provide source/sink mapping without runtime analysis
        const runtimeHint = input.runtime === 'auto' ? 'dotnet' : input.runtime
        const sourceMap = runtimeHint === 'dotnet' ? DOTNET_SOURCES : JAVA_SOURCES
        const sinkMap = runtimeHint === 'dotnet' ? DOTNET_SINKS : JAVA_SINKS

        const activeSources = input.source_categories
          .filter(c => (sourceMap[c] || []).length > 0)
          .map(c => ({ category: c, apis: sourceMap[c] }))
        const activeSinks = input.sink_categories
          .filter(c => (sinkMap[c] || []).length > 0)
          .map(c => ({ category: c, apis: sinkMap[c] }))

        const fallbackData = {
          runtime_detected: runtimeHint,
          analysis_mode: 'static_mapping_only',
          sources: activeSources,
          sinks: activeSinks,
          taint_paths: [],
          note: 'Python bytecode taint worker unavailable. Showing source/sink API mappings only. ' +
            'For full inter-procedural taint tracking, ensure the worker is running.',
          recommended_next: ['taint.track', 'dotnet.il.decompile'],
        }

        return {
          ok: true,
          data: fallbackData,
          warnings: ['Worker unavailable; static API mapping only', ...(workerResponse.warnings || [])],
          metrics: { elapsed_ms: Date.now() - startTime, tool: TOOL_NAME },
        }
      }

      const data = workerResponse.data as Record<string, unknown>

      // Cache result
      await cacheManager.setCachedResult(cacheKey, data, CACHE_TTL_MS, sample.sha256)

      // Persist artifact
      const artifacts: ArtifactRef[] = []
      try {
        artifacts.push(await persistStaticAnalysisJsonArtifact(
          workspaceManager, database, input.sample_id,
          'bytecode_taint', 'bytecode_taint_analysis', { tool: TOOL_NAME, data },
        ))
      } catch { /* best effort */ }

      return {
        ok: true,
        data,
        warnings: workerResponse.warnings,
        artifacts,
        metrics: { elapsed_ms: Date.now() - startTime, tool: TOOL_NAME },
      }
    } catch (error) {
      return {
        ok: false,
        errors: [(error as Error).message],
        metrics: { elapsed_ms: Date.now() - startTime, tool: TOOL_NAME },
      }
    }
  }
}
