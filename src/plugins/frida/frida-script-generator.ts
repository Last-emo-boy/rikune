/**
 * Frida Script Generator
 * Auto-generates Frida instrumentation scripts based on detected capabilities
 */

interface Capability {
  name: string
  confidence: number
  apis: string[]
}

interface GenerateOptions {
  maxApis?: number
  customTemplates?: string[]
  minConfidence?: number
}

const templates: Record<string, string> = {
  process_injection: `
  // Process Injection Monitoring
  var apis = %APIS%;
  apis.forEach(function(apiName) {
    try {
      var addr = Module.findExportByName('kernel32.dll', apiName);
      if (addr) {
        Interceptor.attach(addr, {
          onEnter: function(args) {
            console.log('[process_injection] ' + apiName + ' called');
            send({ type: 'api_call', category: 'process_injection', api: apiName, args: [] });
          },
          onLeave: function(retval) {
            console.log('[process_injection] ' + apiName + ' returned: ' + retval);
          }
        });
      }
    } catch(e) {}
  });`,

  crypto: `
  // Crypto API Monitoring
  var cryptoApis = %APIS%;
  cryptoApis.forEach(function(apiName) {
    try {
      var addr = Module.findExportByName('advapi32.dll', apiName);
      if (!addr) addr = Module.findExportByName('bcrypt.dll', apiName);
      if (!addr) addr = Module.findExportByName('ncrypt.dll', apiName);
      if (addr) {
        Interceptor.attach(addr, {
          onEnter: function(args) {
            console.log('[crypto] ' + apiName + ' called');
            send({ type: 'api_call', category: 'crypto', api: apiName, args: [] });
          },
          onLeave: function(retval) {
            console.log('[crypto] ' + apiName + ' returned: ' + retval);
          }
        });
      }
    } catch(e) {}
  });`,

  persistence: `
  // Persistence Monitoring
  var persistApis = %APIS%;
  persistApis.forEach(function(apiName) {
    try {
      var addr = Module.findExportByName('advapi32.dll', apiName);
      if (!addr) addr = Module.findExportByName('kernel32.dll', apiName);
      if (addr) {
        Interceptor.attach(addr, {
          onEnter: function(args) {
            console.log('[persistence] ' + apiName + ' called');
            send({ type: 'api_call', category: 'persistence', api: apiName, args: [] });
          },
          onLeave: function(retval) {
            console.log('[persistence] ' + apiName + ' returned: ' + retval);
          }
        });
      }
    } catch(e) {}
  });`,

  network: `
  // Network Monitoring
  var netApis = %APIS%;
  netApis.forEach(function(apiName) {
    try {
      var addr = Module.findExportByName('wininet.dll', apiName);
      if (!addr) addr = Module.findExportByName('ws2_32.dll', apiName);
      if (!addr) addr = Module.findExportByName('winhttp.dll', apiName);
      if (addr) {
        Interceptor.attach(addr, {
          onEnter: function(args) {
            console.log('[network] ' + apiName + ' called');
            send({ type: 'api_call', category: 'network', api: apiName, args: [] });
          },
          onLeave: function(retval) {
            console.log('[network] ' + apiName + ' returned: ' + retval);
          }
        });
      }
    } catch(e) {}
  });`,
}

// Map capability name variants to template names
const capabilityMapping: Record<string, string> = {
  process_injection: 'process_injection',
  injection: 'process_injection',
  crypto: 'crypto',
  cryptography: 'crypto',
  encryption: 'crypto',
  persistence: 'persistence',
  registry: 'persistence',
  network: 'network',
  c2: 'network',
  communication: 'network',
}

export function generateFridaScript(capabilities: Capability[], options?: GenerateOptions): string {
  const minConfidence = options?.minConfidence ?? 0.5
  const maxApis = options?.maxApis ?? 50

  const parts: string[] = []

  parts.push('"use strict";')
  parts.push('')
  parts.push('// Auto-generated Frida Script')
  parts.push('// Generated for detected capabilities')
  parts.push('')

  for (const cap of capabilities) {
    if (cap.confidence < minConfidence) continue

    const templateName = capabilityMapping[cap.name] || cap.name
    const template = templates[templateName]

    if (template) {
      const limitedApis = cap.apis.slice(0, maxApis)
      const apisJson = JSON.stringify(limitedApis)
      parts.push(`  // Capability: ${cap.name} (confidence: ${cap.confidence})`)
      parts.push(template.replace('%APIS%', apisJson))
      parts.push('')
    }
  }

  if (options?.customTemplates) {
    for (const custom of options.customTemplates) {
      parts.push(custom)
      parts.push('')
    }
  }

  parts.push('rpc.exports = {')
  parts.push('  getStatus: function() { return "active"; }')
  parts.push('};')

  return parts.join('\n')
}

export function getAvailableTemplates(): string[] {
  return Object.keys(templates)
}

export function getTemplate(name: string): string | undefined {
  return templates[name]
}
