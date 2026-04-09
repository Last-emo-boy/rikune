/**
 * Ghidra Integration Plugin
 *
 * Headless Ghidra analysis and health checks.
 */

import { accessSync } from 'fs'
import type { Plugin } from '../sdk.js'
import {
  ghidraAnalyzeToolDefinition, createGhidraAnalyzeHandler,
} from './tools/ghidra-analyze.js'
import {
  ghidraHealthToolDefinition, createGhidraHealthHandler,
} from './tools/ghidra-health.js'

const ghidraPlugin: Plugin = {
  id: 'ghidra',
  name: 'Ghidra Integration',
  description: 'Headless Ghidra analysis and health checks',
  version: '1.0.0',
  configSchema: [
    { envVar: 'GHIDRA_INSTALL_DIR', description: 'Path to Ghidra installation directory', required: true },
    { envVar: 'GHIDRA_PROJECT_DIR', description: 'Directory for Ghidra project files', required: false },
  ],
  systemDeps: [
    {
      type: 'directory', name: 'Ghidra', target: '$GHIDRA_INSTALL_DIR',
      envVar: 'GHIDRA_INSTALL_DIR', dockerDefault: '/opt/ghidra', required: true,
      description: 'Ghidra reverse engineering suite',
      dockerInstall: 'Download Ghidra release to /opt/ghidra',
      dockerFeature: 'ghidra',
      dockerValidation: ['test -f /opt/ghidra/support/analyzeHeadless'],
      extraEnv: {
        JAVA_HOME: '/opt/java/openjdk',
        JAVA_TOOL_OPTIONS: '""',
        GHIDRA_PROJECT_ROOT: '/ghidra-projects',
        GHIDRA_LOG_ROOT: '/ghidra-logs',
      },
      buildArgs: { GHIDRA_VERSION: '12.0.4' },
      directories: [
        { path: '/ghidra-projects', chown: 'appuser:appuser' },
        { path: '/ghidra-logs', chown: 'appuser:appuser' },
      ],
      volumes: [
        { source: '${RIKUNE_DATA_ROOT:-D:/Docker/rikune}/ghidra-projects', target: '/ghidra-projects', mode: 'rw' },
        { source: '${RIKUNE_DATA_ROOT:-D:/Docker/rikune}/ghidra-logs', target: '/ghidra-logs', mode: 'rw' },
      ],
    },
    { type: 'binary', name: 'java', versionFlag: '-version', required: true, description: 'Java 17+ runtime (Temurin recommended)', dockerDefault: '/opt/java/openjdk/bin/java', dockerInstall: 'FROM eclipse-temurin:21-jdk', dockerFeature: 'ghidra' },
  ],
  check() {
    const ghidraDir = process.env.GHIDRA_INSTALL_DIR
    if (!ghidraDir) return false
    try { accessSync(ghidraDir); return true } catch { return false }
  },
  register(server, deps) {
    server.registerTool(ghidraAnalyzeToolDefinition, createGhidraAnalyzeHandler(deps))
    server.registerTool(ghidraHealthToolDefinition, createGhidraHealthHandler(deps))
    return ['ghidra.analyze', 'ghidra.health']
  },
}

export default ghidraPlugin
