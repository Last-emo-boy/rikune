/**
 * PCAP Analysis Plugin
 *
 * Network packet capture analysis using tshark (Wireshark CLI).
 */

import type { Plugin } from '../sdk.js'
import { pcapAnalyzeToolDefinition, createPcapAnalyzeHandler } from './tools/pcap-analyze.js'
import { pcapDnsListToolDefinition, createPcapDnsListHandler } from './tools/pcap-dns-list.js'
import { pcapExtractStreamsToolDefinition, createPcapExtractStreamsHandler } from './tools/pcap-extract-streams.js'

const pcapAnalysisPlugin: Plugin = {
  id: 'pcap-analysis',
  name: 'PCAP Analysis',
  surfaceRules: { tier: 1, activateOn: { fileTypes: ['pcap', 'pcapng', 'network'] }, category: 'network-analysis' },
  description: 'Network packet capture analysis and stream extraction using tshark',
  version: '1.0.0',
  configSchema: [
    { envVar: 'TSHARK_PATH', description: 'Path to tshark binary', required: false, defaultValue: 'tshark' },
  ],
  systemDeps: [
    {
      type: 'binary',
      name: 'tshark',
      target: '$TSHARK_PATH',
      envVar: 'TSHARK_PATH',
      dockerDefault: '/usr/bin/tshark',
      versionFlag: '--version',
      required: false,
      description: 'Wireshark CLI for packet analysis',
      dockerInstall: 'apt-get install -y tshark',
      aptPackages: ['tshark'],
      dockerValidation: ['tshark --version >/dev/null 2>&1'],
    },
  ],
  register(server, deps) {
    const { workspaceManager: wm, database: db } = deps

    server.registerTool(pcapAnalyzeToolDefinition, createPcapAnalyzeHandler(wm, db))
    server.registerTool(pcapDnsListToolDefinition, createPcapDnsListHandler(wm, db))
    server.registerTool(pcapExtractStreamsToolDefinition, createPcapExtractStreamsHandler(wm, db))

    return ['pcap.analyze', 'pcap.dns.list', 'pcap.extract.streams']
  },
}

export default pcapAnalysisPlugin
