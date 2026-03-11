/**
 * Integration Verification Script
 * Verifies that all components are properly integrated
 * Task 11.1: Integration verification
 */

import { MCPServer } from '../src/server.js'
import { loadConfig } from '../src/config.js'
import { WorkspaceManager } from '../src/workspace-manager.js'
import { DatabaseManager } from '../src/database.js'
import { PolicyGuard } from '../src/policy-guard.js'
import { CacheManager } from '../src/cache-manager.js'

async function verifyIntegration() {
  console.log('=== Component Integration Verification ===\n')

  try {
    // 1. Verify configuration loading
    console.log('✓ Testing configuration loading...')
    const config = loadConfig()
    console.log(`  - Config loaded successfully`)
    console.log(`  - Workspace root: ${config.workspace.root}`)
    console.log(`  - Database path: ${config.database.path || './data/database.db'}`)

    // 2. Verify component initialization
    console.log('\n✓ Testing component initialization...')
    
    const workspaceManager = new WorkspaceManager(config.workspace.root)
    console.log('  - WorkspaceManager initialized')

    const database = new DatabaseManager(':memory:') // Use in-memory for testing
    console.log('  - DatabaseManager initialized')

    const policyGuard = new PolicyGuard('./test-audit.log')
    console.log('  - PolicyGuard initialized')

    const cacheManager = new CacheManager('./test-cache', database)
    console.log('  - CacheManager initialized')

    // 3. Verify MCP Server initialization
    console.log('\n✓ Testing MCP Server initialization...')
    const server = new MCPServer(config)
    console.log('  - MCPServer initialized')

    // 4. Verify tool registration (import and register all tools)
    console.log('\n✓ Testing tool registration...')
    
    const { sampleIngestToolDefinition, createSampleIngestHandler } = await import('../src/tools/sample-ingest.js')
    const { sampleProfileGetToolDefinition, createSampleProfileGetHandler } = await import('../src/tools/sample-profile-get.js')
    const { peFingerprintToolDefinition, createPEFingerprintHandler } = await import('../src/tools/pe-fingerprint.js')
    const { peImportsExtractToolDefinition, createPEImportsExtractHandler } = await import('../src/tools/pe-imports-extract.js')
    const { peExportsExtractToolDefinition, createPEExportsExtractHandler } = await import('../src/tools/pe-exports-extract.js')
    const { stringsExtractToolDefinition, createStringsExtractHandler } = await import('../src/tools/strings-extract.js')
    const { stringsFlossDecodeToolDefinition, createStringsFlossDecodeHandler } = await import('../src/tools/strings-floss-decode.js')
    const { yaraScanToolDefinition, createYaraScanHandler } = await import('../src/tools/yara-scan.js')
    const { runtimeDetectToolDefinition, createRuntimeDetectHandler } = await import('../src/tools/runtime-detect.js')
    const { packerDetectToolDefinition, createPackerDetectHandler } = await import('../src/tools/packer-detect.js')
    const { triageWorkflowToolDefinition, createTriageWorkflowHandler } = await import('../src/workflows/triage.js')
    const { reportSummarizeToolDefinition, createReportSummarizeHandler } = await import('../src/tools/report-summarize.js')

    server.registerTool(sampleIngestToolDefinition, createSampleIngestHandler(workspaceManager, database, policyGuard))
    server.registerTool(sampleProfileGetToolDefinition, createSampleProfileGetHandler(database))
    server.registerTool(peFingerprintToolDefinition, createPEFingerprintHandler(workspaceManager, database, cacheManager))
    server.registerTool(peImportsExtractToolDefinition, createPEImportsExtractHandler(workspaceManager, database, cacheManager))
    server.registerTool(peExportsExtractToolDefinition, createPEExportsExtractHandler(workspaceManager, database, cacheManager))
    server.registerTool(stringsExtractToolDefinition, createStringsExtractHandler(workspaceManager, database, cacheManager))
    server.registerTool(stringsFlossDecodeToolDefinition, createStringsFlossDecodeHandler(workspaceManager, database, cacheManager))
    server.registerTool(yaraScanToolDefinition, createYaraScanHandler(workspaceManager, database, cacheManager))
    server.registerTool(runtimeDetectToolDefinition, createRuntimeDetectHandler(workspaceManager, database, cacheManager))
    server.registerTool(packerDetectToolDefinition, createPackerDetectHandler(workspaceManager, database, cacheManager))
    server.registerTool(triageWorkflowToolDefinition, createTriageWorkflowHandler(workspaceManager, database, cacheManager))
    server.registerTool(reportSummarizeToolDefinition, createReportSummarizeHandler(workspaceManager, database, cacheManager))

    // 5. Verify tool listing
    console.log('\n✓ Testing tool listing...')
    const tools = await server.listTools()
    console.log(`  - Total tools registered: ${tools.length}`)
    
    const expectedTools = [
      'sample.ingest',
      'sample.profile.get',
      'pe.fingerprint',
      'pe.imports.extract',
      'pe.exports.extract',
      'strings.extract',
      'strings.floss.decode',
      'yara.scan',
      'runtime.detect',
      'packer.detect',
      'workflow.triage',
      'report.summarize'
    ]

    console.log('\n  Registered tools:')
    for (const tool of tools) {
      const isExpected = expectedTools.includes(tool.name)
      console.log(`    ${isExpected ? '✓' : '✗'} ${tool.name}`)
    }

    // Check if all expected tools are registered
    const missingTools = expectedTools.filter(name => !tools.some(t => t.name === name))
    if (missingTools.length > 0) {
      console.log(`\n  ✗ Missing tools: ${missingTools.join(', ')}`)
      throw new Error('Not all expected tools are registered')
    }

    // 6. Verify tool schemas
    console.log('\n✓ Testing tool schemas...')
    for (const tool of tools) {
      if (!tool.inputSchema || typeof tool.inputSchema !== 'object') {
        throw new Error(`Tool ${tool.name} has invalid inputSchema`)
      }
      console.log(`  - ${tool.name}: schema valid`)
    }

    // 7. Summary
    console.log('\n=== Integration Verification Summary ===')
    console.log('✓ All components initialized successfully')
    console.log('✓ All tools registered successfully')
    console.log('✓ All tool schemas are valid')
    console.log('\n✅ Integration verification PASSED')
    
    return true
  } catch (error) {
    console.error('\n❌ Integration verification FAILED')
    console.error('Error:', error)
    return false
  }
}

// Run verification
verifyIntegration()
  .then(success => {
    process.exit(success ? 0 : 1)
  })
  .catch(error => {
    console.error('Unexpected error:', error)
    process.exit(1)
  })
