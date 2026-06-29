import { z } from 'zod'
import type { ToolDefinition, WorkerResult } from '../../sdk.js'

const TOOL_NAME = 'android.behavior.graph'

export const AndroidBehaviorGraphInputSchema = z
  .object({
    sample_id: z.string().optional(),
    manifest: z.any().optional(),
    package_inventory: z.any().optional(),
    dex_classes: z.any().optional(),
    smali_snippets: z.array(z.string()).optional().default([]),
    findings: z.array(z.string()).optional().default([]),
  })
  .passthrough()

export const AndroidBehaviorGraphOutputSchema = z.object({
  ok: z.boolean(),
  data: z.record(z.string(), z.any()).optional(),
  errors: z.array(z.string()).optional(),
  metrics: z.object({ elapsed_ms: z.number(), tool: z.string() }).optional(),
})

export const androidBehaviorGraphToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Build a passive Android static behavior graph from manifest, package inventory, DEX class, and smali-like evidence. It recommends hook targets and runtime-plan follow-ups without using ADB, emulator, or Frida injection.',
  inputSchema: AndroidBehaviorGraphInputSchema,
  outputSchema: AndroidBehaviorGraphOutputSchema,
  aspects: {
    formats: ['apk', 'aab', 'apks', 'xapk', 'split-apk', 'dex', 'multi-dex', 'aar'],
    platforms: ['android'],
    architectures: ['arm', 'arm64', 'x86', 'x64'],
    execution: ['static', 'correlation'],
    safety: ['passive', 'no_live_sample_by_default'],
    capabilities: ['behavior-graph', 'manifest-correlation', 'hook-plan-input', 'workflow-plan'],
    evidence: ['manifest', 'classes', 'strings', 'behavior', 'workflow', 'provenance'],
  },
  artifacts: [
    {
      type: 'android_behavior_graph',
      description: 'Passive Android manifest, DEX/smali, native library, and hook candidate graph',
    },
  ],
  evidence: [
    { category: 'manifest', artifactTypes: ['android_behavior_graph'] },
    { category: 'behavior', artifactTypes: ['android_behavior_graph'] },
    { category: 'provenance', artifactTypes: ['android_behavior_graph'] },
  ],
  workflowRecipes: [
    {
      id: 'android.static.behavior-graph',
      title: 'Android static behavior graph',
      startsWith: ['android.package.inventory', 'apk.structure.analyze', 'android.behavior.graph'],
      nextTools: ['dex.classes.list', 'frida.script.generate', 'android.runtime.plan'],
      requiredArtifacts: ['android_package_inventory', 'apk_structure', 'dex_classes'],
      producesArtifacts: ['android_behavior_graph'],
      evidence: ['manifest', 'classes', 'behavior', 'workflow', 'provenance'],
      safety: ['passive', 'no_live_sample_by_default'],
    },
  ],
}

function stringify(value: unknown): string {
  if (typeof value === 'string') return value
  if (Array.isArray(value)) return value.map(stringify).join('\n')
  if (value && typeof value === 'object') return JSON.stringify(value)
  return ''
}

function uniqueMatches(text: string, pattern: RegExp): string[] {
  return Array.from(new Set(Array.from(text.matchAll(pattern)).map((match) => match[0]))).sort()
}

function classNamesFrom(text: string): string[] {
  const javaLike = uniqueMatches(text, /\b[a-zA-Z_$][\w$]*(?:\.[a-zA-Z_$][\w$]*){2,}\b/g)
  const dexLike = Array.from(text.matchAll(/L([A-Za-z0-9_$\/]+);/g)).map((match) =>
    match[1].replace(/\//g, '.')
  )
  return Array.from(new Set([...javaLike, ...dexLike])).sort()
}

function nativeLibrariesFrom(packageInventory: unknown): string[] {
  const obj =
    packageInventory && typeof packageInventory === 'object' ? (packageInventory as any) : {}
  const rows = Array.isArray(obj.native_library_candidates) ? obj.native_library_candidates : []
  return rows
    .map((row: any) => String(row.path ?? row.name ?? ''))
    .filter(Boolean)
    .sort()
}

function hookCandidates(
  permissions: string[],
  classes: string[],
  urls: string[],
  cryptoHints: string[]
) {
  const candidates = []
  if (
    permissions.some((permission) => /INTERNET|ACCESS_NETWORK_STATE/.test(permission)) ||
    urls.length
  ) {
    candidates.push({
      category: 'network',
      targets: ['java.net.URL', 'okhttp3.OkHttpClient', 'javax.net.ssl.SSLSocketFactory'],
      reason: 'Network permission, URL, or networking class evidence was observed.',
    })
  }
  if (cryptoHints.length || classes.some((name) => /crypto|cipher|messageDigest/i.test(name))) {
    candidates.push({
      category: 'crypto',
      targets: ['javax.crypto.Cipher', 'java.security.MessageDigest', 'javax.crypto.Mac'],
      reason: 'Crypto API or class hints were observed.',
    })
  }
  if (permissions.some((permission) => /READ_|WRITE_|STORAGE/.test(permission))) {
    candidates.push({
      category: 'filesystem',
      targets: ['java.io.File', 'android.content.ContentResolver'],
      reason: 'Storage-related permissions were observed.',
    })
  }
  if (classes.some((name) => /ClassLoader|DexClassLoader|PathClassLoader|reflect/i.test(name))) {
    candidates.push({
      category: 'classloader-reflection',
      targets: ['dalvik.system.DexClassLoader', 'java.lang.reflect.Method'],
      reason: 'Classloader or reflection hints were observed.',
    })
  }
  return candidates
}

export function buildAndroidBehaviorGraph(rawInput: unknown) {
  const input = AndroidBehaviorGraphInputSchema.parse(rawInput)
  const text = [
    stringify(input.manifest),
    stringify(input.package_inventory),
    stringify(input.dex_classes),
    input.smali_snippets.join('\n'),
    input.findings.join('\n'),
  ].join('\n')
  const permissions = uniqueMatches(text, /android\.permission\.[A-Z0-9_.]+/g)
  const intents = uniqueMatches(text, /android\.intent\.[A-Za-z0-9_.]+/g)
  const urls = uniqueMatches(text, /\bhttps?:\/\/[^\s"'<>]+/g)
  const cryptoHints = uniqueMatches(
    text,
    /\b(?:Cipher|MessageDigest|SecretKeySpec|AES|RSA|HmacSHA256|SHA-256)\b/g
  )
  const storageHints = uniqueMatches(
    text,
    /\b(?:SharedPreferences|SQLiteDatabase|ContentResolver|openFileOutput)\b/g
  )
  const classes = classNamesFrom(text).slice(0, 200)
  const nativeLibraries = nativeLibrariesFrom(input.package_inventory)
  const hooks = hookCandidates(permissions, classes, urls, cryptoHints)
  const nodes = [
    ...permissions.map((permission) => ({
      id: `permission:${permission}`,
      type: 'permission',
      label: permission,
    })),
    ...intents.map((intent) => ({ id: `intent:${intent}`, type: 'intent', label: intent })),
    ...classes.slice(0, 80).map((name) => ({ id: `class:${name}`, type: 'class', label: name })),
    ...nativeLibraries.map((library) => ({
      id: `native:${library}`,
      type: 'native-library',
      label: library,
    })),
    ...hooks.map((hook) => ({
      id: `hook:${hook.category}`,
      type: 'hook-candidate',
      label: hook.category,
    })),
  ]

  return {
    result_mode: 'android_behavior_graph',
    sample_id: input.sample_id ?? null,
    graph: {
      nodes,
      edges: hooks.flatMap((hook) =>
        hook.targets.map((target) => ({
          source: `hook:${hook.category}`,
          target,
          relation: 'recommends_hook_target',
        }))
      ),
    },
    indicators: {
      permissions,
      intents,
      urls,
      crypto_hints: cryptoHints,
      storage_hints: storageHints,
      native_libraries: nativeLibraries,
      classes: classes.slice(0, 80),
    },
    runtime_hook_candidates: hooks,
    native_library_handoff: nativeLibraries.map((library) => ({
      path: library,
      recommended_tools: ['linux.binary.inventory', 'native.object.inventory'],
    })),
    recommended_next_tools: [
      'android.package.inventory',
      'dex.classes.list',
      'frida.script.generate',
      'android.runtime.plan',
    ],
    safety_notes: [
      'Static correlation only; no emulator, ADB, device connection, Frida attach, or APK install is performed.',
    ],
  }
}

export function createAndroidBehaviorGraphHandler() {
  return async (args: unknown): Promise<WorkerResult> => ({
    ok: true,
    data: buildAndroidBehaviorGraph(args),
    metrics: { elapsed_ms: 0, tool: TOOL_NAME },
  })
}
