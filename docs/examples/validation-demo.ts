/**
 * Demonstration of enhanced input parameter validation
 * 
 * This example shows how the MCP Server validates input parameters
 * and provides clear error messages with examples.
 */

import { MCPServer } from '../src/server.js'
import { Config } from '../src/config.js'
import { z } from 'zod'

// Create a sample configuration
const config: Config = {
  server: {
    port: 3000,
    host: 'localhost',
  },
  database: {
    type: 'sqlite',
    path: ':memory:',
  },
  workspace: {
    root: './workspaces',
    maxSampleSize: 500 * 1024 * 1024,
  },
  workers: {
    ghidra: {
      enabled: false,
      maxConcurrent: 4,
      timeout: 300,
    },
    static: {
      enabled: true,
    },
    dotnet: {
      enabled: false,
    },
  },
  cache: {
    enabled: true,
    ttl: 30 * 24 * 60 * 60,
  },
  logging: {
    level: 'info',
    pretty: true,
  },
}

// Initialize the MCP Server
const server = new MCPServer(config)

// Register a sample tool with validation
server.registerTool(
  {
    name: 'sample.ingest',
    description: 'Upload and register a new sample',
    inputSchema: z.object({
      path: z.string().optional(),
      bytes_b64: z.string().optional(),
      filename: z.string().optional(),
      source: z.string().optional(),
    }).refine(
      (data) => data.path || data.bytes_b64,
      {
        message: 'Either path or bytes_b64 must be provided',
      }
    ),
  },
  async (args) => {
    return {
      ok: true,
      data: {
        sample_id: 'sha256:abc123...',
        size: 1024,
        file_type: 'PE32',
      },
    }
  }
)

// Example 1: Valid input
console.log('=== Example 1: Valid Input ===')
try {
  const result = await server.callTool('sample.ingest', {
    path: '/path/to/sample.exe',
    filename: 'sample.exe',
  })
  console.log('Success:', JSON.parse(result.content[0].text))
} catch (error) {
  console.error('Error:', error)
}

// Example 2: Missing required field
console.log('\n=== Example 2: Missing Required Field ===')
try {
  const result = await server.callTool('sample.ingest', {
    filename: 'sample.exe',
  })
  console.log('Result:', JSON.parse(result.content[0].text))
} catch (error) {
  console.error('Error:', error)
}

// Example 3: Wrong type
console.log('\n=== Example 3: Wrong Type ===')
server.registerTool(
  {
    name: 'pe.fingerprint',
    description: 'Extract PE fingerprint',
    inputSchema: z.object({
      sample_id: z.string(),
      fast: z.boolean().optional(),
    }),
  },
  async (args) => {
    return {
      ok: true,
      data: {
        sha256: 'abc123...',
        imphash: 'def456...',
      },
    }
  }
)

try {
  const result = await server.callTool('pe.fingerprint', {
    sample_id: 'sha256:abc123',
    fast: 'yes', // Wrong type - should be boolean
  })
  console.log('Result:', JSON.parse(result.content[0].text))
} catch (error) {
  console.error('Error:', error)
}

// Example 4: Nested validation error
console.log('\n=== Example 4: Nested Validation Error ===')
server.registerTool(
  {
    name: 'ghidra.analyze',
    description: 'Analyze with Ghidra',
    inputSchema: z.object({
      sample_id: z.string(),
      options: z.object({
        timeout: z.number(),
        maxCpu: z.number().optional(),
      }).optional(),
    }),
  },
  async (args) => {
    return {
      ok: true,
      data: {
        analysis_id: 'uuid-123',
        function_count: 42,
      },
    }
  }
)

try {
  const result = await server.callTool('ghidra.analyze', {
    sample_id: 'sha256:abc123',
    options: {
      timeout: 'invalid', // Wrong type
    },
  })
  console.log('Result:', JSON.parse(result.content[0].text))
} catch (error) {
  console.error('Error:', error)
}

// Clean up
await server.stop()
