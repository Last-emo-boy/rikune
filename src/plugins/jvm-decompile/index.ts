/**
 * jvm-decompile Plugin
 *
 * Decompile JVM bytecode (.class/.jar/.war/.aar/.jmod) to Java source via CFR
 * (Class File Reader), a single-JAR Java decompiler. Fills the JVM source
 * decompilation gap left by the metadata-only `jvm` plugin, which never
 * launches a Java decompiler.
 */

import type { Plugin } from '../sdk.js'
import { jvmDecompileToolDefinition, createJvmDecompileHandler } from './tools/jvm-decompile.js'

const jvmDecompilePlugin: Plugin = {
  id: 'jvm-decompile',
  name: 'JVM Bytecode Decompiler (CFR)',
  executionDomain: 'static',
  aspects: {
    formats: ['class', 'jar', 'war', 'aar', 'jmod', 'kotlin-metadata', 'java'],
    platforms: ['jvm', 'android', 'cross-platform'],
    execution: ['static', 'decompilation'],
    runtimes: ['cfr'],
    safety: ['passive', 'read_only', 'no_live_sample_by_default', 'no_network_by_default'],
    capabilities: [
      'java-decompilation',
      'class-recovery',
      'source-recovery',
      'archive-decompilation',
    ],
    evidence: ['source', 'classes', 'provenance'],
  },
  surfaceRules: {
    tier: 2,
    activateOn: { fileTypes: ['class', 'jar', 'war', 'aar', 'jmod', 'java'] },
    category: 'reverse-engineering',
  },
  description:
    'Decompile JVM bytecode (.class/.jar) to Java source via CFR. ' +
    'Never executes the bytecode — CFR parses class files to recover source.',
  version: '0.1.0',
  dependencies: ['jvm'],
  configSchema: [
    {
      envVar: 'CFR_JAR',
      description: 'Path to cfr.jar (single-JAR decompiler from https://github.com/leibnitz27/cfr)',
      required: false,
    },
    {
      envVar: 'JAVA_PATH',
      description: 'Path to Java 8+ binary (or set JAVA_HOME)',
      required: false,
    },
  ],
  systemDeps: [
    {
      type: 'binary',
      name: 'java',
      versionFlag: '-version',
      required: false,
      description: 'Java 8+ runtime (Temurin recommended; shared with ghidra)',
      dockerDefault: '/opt/java/openjdk/bin/java',
      dockerInstall: 'FROM eclipse-temurin:21-jdk',
      dockerFeature: 'jvm-decompile',
    },
    {
      type: 'file',
      name: 'cfr',
      target: '$CFR_JAR',
      envVar: 'CFR_JAR',
      required: false,
      description: 'CFR (Class File Reader) single-JAR Java decompiler',
      dockerInstall:
        'curl -L -o /opt/cfr/cfr.jar https://github.com/leibnitz27/cfr/releases/download/0.152/cfr-0.152.jar',
      dockerFeature: 'jvm-decompile',
      dockerValidation: ['java -jar "$CFR_JAR" --version >/dev/null 2>&1 || true'],
      dockerInstallRoute: 'profile-gated',
      dockerInstallProfile: 'optional',
    },
  ],
  resources: { workers: 'shared' },
  check() {
    return true
  },
  register(server, deps) {
    server.registerTool(jvmDecompileToolDefinition, createJvmDecompileHandler(deps))
    return ['jvm.decompile']
  },
}

export default jvmDecompilePlugin
