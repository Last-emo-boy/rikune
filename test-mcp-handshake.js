/**
 * Test MCP handshake
 * This script simulates an MCP client to test the handshake process
 */

import { spawn } from 'child_process';

console.log('Starting MCP handshake test...\n');

// Spawn the MCP server
const server = spawn('node', ['dist/index.js'], {
  stdio: ['pipe', 'pipe', 'pipe']
});

let stdout = '';
let stderr = '';

server.stdout.on('data', (data) => {
  stdout += data.toString();
  console.log('STDOUT:', data.toString());
});

server.stderr.on('data', (data) => {
  stderr += data.toString();
  console.log('STDERR:', data.toString());
});

server.on('error', (error) => {
  console.error('Failed to start server:', error);
  process.exit(1);
});

// Wait for server to start
setTimeout(() => {
  console.log('\n--- Sending initialize request ---\n');
  
  // Send MCP initialize request
  const initRequest = {
    jsonrpc: '2.0',
    id: 1,
    method: 'initialize',
    params: {
      protocolVersion: '2024-11-05',
      capabilities: {
        roots: {
          listChanged: true
        },
        sampling: {}
      },
      clientInfo: {
        name: 'test-client',
        version: '1.0.0'
      }
    }
  };

  const message = JSON.stringify(initRequest) + '\n';
  console.log('Sending:', message);
  
  server.stdin.write(message);

  // Wait for response
  setTimeout(() => {
    console.log('\n--- Test complete ---');
    console.log('Total stdout:', stdout);
    console.log('Total stderr:', stderr);
    
    server.kill();
    process.exit(0);
  }, 3000);
}, 2000);
