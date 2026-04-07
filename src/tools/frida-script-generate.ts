/**
 * frida.script.generate tool implementation
 * Auto-generate Frida hook scripts from analysis evidence.
 */

import { z } from 'zod'
import type { ToolDefinition, ToolArgs, WorkerResult, ArtifactRef } from '../types.js'
import type { WorkspaceManager } from '../workspace-manager.js'
import type { DatabaseManager } from '../database.js'
import { persistStaticAnalysisJsonArtifact } from '../static-analysis-artifacts.js'

const TOOL_NAME = 'frida.script.generate'

export const FridaScriptGenerateInputSchema = z.object({
  sample_id: z.string().describe('Sample identifier (sha256:<hex>)'),
  hook_targets: z
    .array(
      z.enum([
        'crypto',
        'network',
        'file_io',
        'registry',
        'process',
        'anti_debug',
        'memory',
        'custom',
      ])
    )
    .optional()
    .default(['crypto', 'network', 'anti_debug'])
    .describe('Categories of APIs to hook'),
  include_imports: z
    .boolean()
    .default(true)
    .describe('Hook all suspicious imports found in the binary'),
  custom_apis: z
    .array(z.string())
    .optional()
    .describe('Additional API names to hook'),
  output_format: z
    .enum(['standalone', 'modular'])
    .default('standalone')
    .describe('Script output format'),
})

export type FridaScriptGenerateInput = z.infer<typeof FridaScriptGenerateInputSchema>

export const FridaScriptGenerateOutputSchema = z.object({
  ok: z.boolean(),
  data: z
    .object({
      scripts: z.array(
        z.object({
          name: z.string(),
          category: z.string(),
          script: z.string(),
          hook_count: z.number(),
          apis_hooked: z.array(z.string()),
        })
      ),
      combined_script: z.string(),
      total_hooks: z.number(),
      recommended_next_tools: z.array(z.string()),
    })
    .optional(),
  warnings: z.array(z.string()).optional(),
  errors: z.array(z.string()).optional(),
  metrics: z.object({ elapsed_ms: z.number(), tool: z.string() }).optional(),
})

export const fridaScriptGenerateToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Auto-generate Frida hook scripts from sample analysis evidence. Generates hooks for crypto APIs, ' +
    'network calls, file I/O, registry access, process manipulation, and anti-debug bypass. ' +
    'Uses import analysis and taint tracking results to target the most relevant APIs.',
  inputSchema: FridaScriptGenerateInputSchema,
  outputSchema: FridaScriptGenerateOutputSchema,
}

// --------------------------------------------------------------------------
// API hook templates
// --------------------------------------------------------------------------

interface ApiHook {
  module: string
  func: string
  category: string
  onEnter: string
  onLeave: string
}

const HOOK_TEMPLATES: Record<string, ApiHook[]> = {
  crypto: [
    {
      module: 'advapi32.dll',
      func: 'CryptEncrypt',
      category: 'crypto',
      onEnter: `    var hKey = args[0]; var bFinal = args[1]; var dwFlags = args[2];
    var dwBufLen = args[4].toInt32(); var pbData = args[3];
    console.log('[CryptEncrypt] hKey=' + hKey + ' bFinal=' + bFinal + ' bufLen=' + dwBufLen);
    if (dwBufLen > 0 && dwBufLen < 4096) { console.log('  data=' + hexdump(pbData, {length: Math.min(dwBufLen, 64)})); }`,
      onLeave: `    console.log('[CryptEncrypt] result=' + retval);`,
    },
    {
      module: 'advapi32.dll',
      func: 'CryptDecrypt',
      category: 'crypto',
      onEnter: `    var hKey = args[0]; var pbData = args[3]; var pdwDataLen = args[4];
    console.log('[CryptDecrypt] hKey=' + hKey);`,
      onLeave: `    console.log('[CryptDecrypt] result=' + retval);`,
    },
    {
      module: 'bcrypt.dll',
      func: 'BCryptEncrypt',
      category: 'crypto',
      onEnter: `    console.log('[BCryptEncrypt] hKey=' + args[0] + ' inputLen=' + args[2].toInt32());`,
      onLeave: `    console.log('[BCryptEncrypt] result=' + retval);`,
    },
    {
      module: 'bcrypt.dll',
      func: 'BCryptDecrypt',
      category: 'crypto',
      onEnter: `    console.log('[BCryptDecrypt] hKey=' + args[0] + ' inputLen=' + args[2].toInt32());`,
      onLeave: `    console.log('[BCryptDecrypt] result=' + retval);`,
    },
  ],
  network: [
    {
      module: 'ws2_32.dll',
      func: 'connect',
      category: 'network',
      onEnter: `    var sockAddr = args[1]; var family = sockAddr.readU16();
    if (family === 2) { // AF_INET
      var port = (sockAddr.add(2).readU8() << 8) | sockAddr.add(3).readU8();
      var ip = sockAddr.add(4).readU8() + '.' + sockAddr.add(5).readU8() + '.' + sockAddr.add(6).readU8() + '.' + sockAddr.add(7).readU8();
      console.log('[connect] ' + ip + ':' + port);
    }`,
      onLeave: `    console.log('[connect] result=' + retval);`,
    },
    {
      module: 'ws2_32.dll',
      func: 'send',
      category: 'network',
      onEnter: `    var len = args[2].toInt32();
    console.log('[send] len=' + len);
    if (len > 0 && len < 4096) { console.log('  data=' + hexdump(args[1], {length: Math.min(len, 128)})); }`,
      onLeave: `    console.log('[send] bytes_sent=' + retval);`,
    },
    {
      module: 'ws2_32.dll',
      func: 'recv',
      category: 'network',
      onEnter: `    this.buf = args[1]; this.len = args[2].toInt32();
    console.log('[recv] bufLen=' + this.len);`,
      onLeave: `    var bytesRecv = retval.toInt32();
    if (bytesRecv > 0 && bytesRecv < 4096) { console.log('[recv] received=' + bytesRecv + ' data=' + hexdump(this.buf, {length: Math.min(bytesRecv, 128)})); }`,
    },
    {
      module: 'winhttp.dll',
      func: 'WinHttpOpen',
      category: 'network',
      onEnter: `    console.log('[WinHttpOpen] userAgent=' + (args[0].isNull() ? 'null' : args[0].readUtf16String()));`,
      onLeave: `    console.log('[WinHttpOpen] handle=' + retval);`,
    },
    {
      module: 'winhttp.dll',
      func: 'WinHttpConnect',
      category: 'network',
      onEnter: `    var server = args[1].isNull() ? 'null' : args[1].readUtf16String();
    var port = args[2].toInt32();
    console.log('[WinHttpConnect] server=' + server + ':' + port);`,
      onLeave: `    console.log('[WinHttpConnect] handle=' + retval);`,
    },
  ],
  file_io: [
    {
      module: 'kernel32.dll',
      func: 'CreateFileW',
      category: 'file_io',
      onEnter: `    var fileName = args[0].readUtf16String();
    var access = args[1].toInt32(); var disposition = args[4].toInt32();
    console.log('[CreateFileW] ' + fileName + ' access=0x' + access.toString(16) + ' disposition=' + disposition);`,
      onLeave: `    console.log('[CreateFileW] handle=' + retval);`,
    },
    {
      module: 'kernel32.dll',
      func: 'WriteFile',
      category: 'file_io',
      onEnter: `    var nBytes = args[2].toInt32();
    console.log('[WriteFile] handle=' + args[0] + ' bytes=' + nBytes);
    if (nBytes > 0 && nBytes < 1024) { console.log('  data=' + hexdump(args[1], {length: Math.min(nBytes, 64)})); }`,
      onLeave: `    console.log('[WriteFile] result=' + retval);`,
    },
    {
      module: 'kernel32.dll',
      func: 'ReadFile',
      category: 'file_io',
      onEnter: `    this.buf = args[1]; this.nBytes = args[2].toInt32();
    console.log('[ReadFile] handle=' + args[0] + ' requestedBytes=' + this.nBytes);`,
      onLeave: `    console.log('[ReadFile] result=' + retval);`,
    },
  ],
  registry: [
    {
      module: 'advapi32.dll',
      func: 'RegOpenKeyExW',
      category: 'registry',
      onEnter: `    var subKey = args[1].readUtf16String();
    console.log('[RegOpenKeyExW] hKey=' + args[0] + ' subKey=' + subKey);`,
      onLeave: `    console.log('[RegOpenKeyExW] result=' + retval);`,
    },
    {
      module: 'advapi32.dll',
      func: 'RegSetValueExW',
      category: 'registry',
      onEnter: `    var valueName = args[1].readUtf16String();
    var dataLen = args[4].toInt32();
    console.log('[RegSetValueExW] valueName=' + valueName + ' dataLen=' + dataLen);`,
      onLeave: `    console.log('[RegSetValueExW] result=' + retval);`,
    },
  ],
  process: [
    {
      module: 'kernel32.dll',
      func: 'CreateProcessW',
      category: 'process',
      onEnter: `    var appName = args[0].isNull() ? 'null' : args[0].readUtf16String();
    var cmdLine = args[1].isNull() ? 'null' : args[1].readUtf16String();
    console.log('[CreateProcessW] app=' + appName + ' cmd=' + cmdLine);`,
      onLeave: `    console.log('[CreateProcessW] result=' + retval);`,
    },
    {
      module: 'kernel32.dll',
      func: 'VirtualAllocEx',
      category: 'process',
      onEnter: `    var hProcess = args[0]; var size = args[2].toInt32(); var protect = args[4].toInt32();
    console.log('[VirtualAllocEx] hProcess=' + hProcess + ' size=' + size + ' protect=0x' + protect.toString(16));`,
      onLeave: `    console.log('[VirtualAllocEx] addr=' + retval);`,
    },
    {
      module: 'kernel32.dll',
      func: 'WriteProcessMemory',
      category: 'process',
      onEnter: `    var nBytes = args[3].toInt32();
    console.log('[WriteProcessMemory] hProcess=' + args[0] + ' addr=' + args[1] + ' bytes=' + nBytes);`,
      onLeave: `    console.log('[WriteProcessMemory] result=' + retval);`,
    },
  ],
  anti_debug: [
    {
      module: 'kernel32.dll',
      func: 'IsDebuggerPresent',
      category: 'anti_debug',
      onEnter: `    console.log('[IsDebuggerPresent] called');`,
      onLeave: `    console.log('[IsDebuggerPresent] original=' + retval + ' -> patching to 0');
    retval.replace(ptr(0));`,
    },
    {
      module: 'ntdll.dll',
      func: 'NtQueryInformationProcess',
      category: 'anti_debug',
      onEnter: `    this.infoClass = args[1].toInt32();
    this.buf = args[2];
    console.log('[NtQueryInformationProcess] infoClass=' + this.infoClass);`,
      onLeave: `    if (this.infoClass === 7) { // ProcessDebugPort
      this.buf.writeInt32(0);
      console.log('[NtQueryInformationProcess] patched ProcessDebugPort to 0');
    }
    if (this.infoClass === 0x1e) { // ProcessDebugObjectHandle
      retval.replace(ptr(0xC0000353)); // STATUS_PORT_NOT_SET
      console.log('[NtQueryInformationProcess] patched ProcessDebugObjectHandle');
    }`,
    },
    {
      module: 'kernel32.dll',
      func: 'CheckRemoteDebuggerPresent',
      category: 'anti_debug',
      onEnter: `    this.pDebuggerPresent = args[1];
    console.log('[CheckRemoteDebuggerPresent] called');`,
      onLeave: `    this.pDebuggerPresent.writeInt32(0);
    console.log('[CheckRemoteDebuggerPresent] patched to false');`,
    },
    {
      module: 'ntdll.dll',
      func: 'NtSetInformationThread',
      category: 'anti_debug',
      onEnter: `    var infoClass = args[1].toInt32();
    if (infoClass === 0x11) { // ThreadHideFromDebugger
      console.log('[NtSetInformationThread] ThreadHideFromDebugger -> NOP');
      args[1] = ptr(0); // Change info class to 0 (nop)
    }`,
      onLeave: ``,
    },
  ],
  memory: [
    {
      module: 'kernel32.dll',
      func: 'VirtualAlloc',
      category: 'memory',
      onEnter: `    var size = args[1].toInt32(); var protect = args[3].toInt32();
    console.log('[VirtualAlloc] size=' + size + ' protect=0x' + protect.toString(16));`,
      onLeave: `    console.log('[VirtualAlloc] addr=' + retval);
    if (retval.toInt32() !== 0) {
      // Track RWX allocations — potential unpacking
      var protect = this.context.r8 ? this.context.r8.toInt32() : 0;
      if (protect === 0x40) { console.log('[VirtualAlloc] WARNING: RWX allocation detected — possible unpacking'); }
    }`,
    },
    {
      module: 'kernel32.dll',
      func: 'VirtualProtect',
      category: 'memory',
      onEnter: `    var addr = args[0]; var size = args[1].toInt32(); var newProtect = args[2].toInt32();
    console.log('[VirtualProtect] addr=' + addr + ' size=' + size + ' newProtect=0x' + newProtect.toString(16));`,
      onLeave: `    console.log('[VirtualProtect] result=' + retval);`,
    },
  ],
}

function generateHookCode(hook: ApiHook): string {
  let code = `  // Hook ${hook.module}!${hook.func}\n`
  code += `  try {\n`
  code += `    var p${hook.func} = Module.getExportByName('${hook.module}', '${hook.func}');\n`
  code += `    Interceptor.attach(p${hook.func}, {\n`
  code += `      onEnter: function(args) {\n${hook.onEnter}\n      },\n`
  if (hook.onLeave) {
    code += `      onLeave: function(retval) {\n${hook.onLeave}\n      }\n`
  }
  code += `    });\n`
  code += `    console.log('[+] Hooked ${hook.func}');\n`
  code += `  } catch(e) { console.log('[-] Failed to hook ${hook.func}: ' + e); }\n`
  return code
}

function generateCustomHook(apiName: string): string {
  const parts = apiName.split('!')
  const module = parts.length > 1 ? parts[0] : 'kernel32.dll'
  const func = parts.length > 1 ? parts[1] : apiName

  let code = `  // Hook ${module}!${func} (custom)\n`
  code += `  try {\n`
  code += `    var p${func} = Module.getExportByName('${module}', '${func}');\n`
  code += `    Interceptor.attach(p${func}, {\n`
  code += `      onEnter: function(args) {\n`
  code += `        console.log('[${func}] called, arg0=' + args[0] + ' arg1=' + args[1] + ' arg2=' + args[2]);\n`
  code += `      },\n`
  code += `      onLeave: function(retval) {\n`
  code += `        console.log('[${func}] returned ' + retval);\n`
  code += `      }\n`
  code += `    });\n`
  code += `    console.log('[+] Hooked ${func}');\n`
  code += `  } catch(e) { console.log('[-] Failed to hook ${func}: ' + e); }\n`
  return code
}

function getImportedApis(database: DatabaseManager, sampleId: string): string[] {
  try {
    const evidenceRows = database.findAnalysisEvidenceBySample(sampleId, 'pe_imports')
    if (evidenceRows.length > 0) {
      const latest = evidenceRows[0]
      const result =
        typeof latest.result_json === 'string' ? JSON.parse(latest.result_json) : latest.result_json
      if (result?.imports && Array.isArray(result.imports)) {
        const apis: string[] = []
        for (const imp of result.imports) {
          if (imp.dll && Array.isArray(imp.functions)) {
            for (const fn of imp.functions) {
              const name = typeof fn === 'string' ? fn : fn?.name
              if (name) apis.push(`${imp.dll}!${name}`)
            }
          }
        }
        return apis
      }
    }
  } catch { /* ignore */ }
  return []
}

export function createFridaScriptGenerateHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager
) {
  return async (args: ToolArgs): Promise<WorkerResult> => {
    const input = FridaScriptGenerateInputSchema.parse(args)
    const startTime = Date.now()

    try {
      const sample = database.findSample(input.sample_id)
      if (!sample) {
        return { ok: false, errors: [`Sample not found: ${input.sample_id}`] }
      }

      const warnings: string[] = []
      const scripts: Array<{
        name: string
        category: string
        script: string
        hook_count: number
        apis_hooked: string[]
      }> = []

      // Generate scripts per category
      for (const target of input.hook_targets) {
        if (target === 'custom') continue
        const hooks = HOOK_TEMPLATES[target]
        if (!hooks || hooks.length === 0) {
          warnings.push(`No hook templates for category: ${target}`)
          continue
        }

        let scriptBody = `// === ${target.toUpperCase()} hooks ===\n`
        scriptBody += `'use strict';\n\n`
        const apisHooked: string[] = []

        for (const hook of hooks) {
          scriptBody += generateHookCode(hook) + '\n'
          apisHooked.push(`${hook.module}!${hook.func}`)
        }

        scripts.push({
          name: `hook_${target}.js`,
          category: target,
          script: scriptBody,
          hook_count: hooks.length,
          apis_hooked: apisHooked,
        })
      }

      // Hook imports if requested
      if (input.include_imports) {
        const importedApis = getImportedApis(database, input.sample_id)
        const suspiciousImports = importedApis.filter((api) => {
          const lower = api.toLowerCase()
          return (
            lower.includes('virtualalloc') ||
            lower.includes('createprocess') ||
            lower.includes('writeprocessmemory') ||
            lower.includes('crypt') ||
            lower.includes('internetopen') ||
            lower.includes('urldownload') ||
            lower.includes('shellexecute') ||
            lower.includes('regsetvalue') ||
            lower.includes('getprocaddress')
          )
        })

        if (suspiciousImports.length > 0) {
          let scriptBody = `// === IMPORT-BASED hooks ===\n'use strict';\n\n`
          for (const api of suspiciousImports) {
            scriptBody += generateCustomHook(api) + '\n'
          }
          scripts.push({
            name: 'hook_imports.js',
            category: 'imports',
            script: scriptBody,
            hook_count: suspiciousImports.length,
            apis_hooked: suspiciousImports,
          })
        }
      }

      // Custom APIs
      if (input.custom_apis && input.custom_apis.length > 0) {
        let scriptBody = `// === CUSTOM hooks ===\n'use strict';\n\n`
        for (const api of input.custom_apis) {
          scriptBody += generateCustomHook(api) + '\n'
        }
        scripts.push({
          name: 'hook_custom.js',
          category: 'custom',
          script: scriptBody,
          hook_count: input.custom_apis.length,
          apis_hooked: input.custom_apis,
        })
      }

      if (scripts.length === 0) {
        return {
          ok: false,
          errors: ['No hooks could be generated — no matching categories or APIs found.'],
          metrics: { elapsed_ms: Date.now() - startTime, tool: TOOL_NAME },
        }
      }

      // Combine all scripts
      let combined = `// === AUTO-GENERATED Frida hook script ===\n`
      combined += `// Sample: ${input.sample_id}\n`
      combined += `// Generated: ${new Date().toISOString()}\n`
      combined += `// Categories: ${input.hook_targets.join(', ')}\n`
      combined += `'use strict';\n\n`
      for (const s of scripts) {
        combined += `// ---- ${s.category} ----\n`
        combined += s.script + '\n'
      }

      const totalHooks = scripts.reduce((sum, s) => sum + s.hook_count, 0)

      const data = {
        scripts,
        combined_script: combined,
        total_hooks: totalHooks,
        recommended_next_tools: ['dynamic.trace', 'frida.attach'],
      }

      try {
        await persistStaticAnalysisJsonArtifact(
          workspaceManager, database, input.sample_id, 'frida_script', 'frida_hooks', { tool: TOOL_NAME, data: { total_hooks: totalHooks, categories: scripts.map(s => s.category) } }
        )
      } catch { /* best effort */ }

      return {
        ok: true,
        data,
        warnings: warnings.length > 0 ? warnings : undefined,
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
