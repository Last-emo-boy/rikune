/**
 * Compiler Codegen Fingerprint Plugin
 *
 * Passive compiler, linker, language-runtime, and code-generation provenance
 * inventory. It never executes samples, invokes compilers/linkers, contacts
 * symbol/source servers, or starts runtime analysis.
 */

import { definePlugin, defineTool } from '../sdk.js'
import {
  compilerCodegenFingerprintAspects,
  compilerCodegenFingerprintToolDefinition,
  createCompilerCodegenFingerprintHandler,
} from './tools/compiler-codegen-fingerprint.js'

const compilerCodegenPlugin = definePlugin({
  id: 'compiler-codegen',
  name: 'Compiler Codegen Fingerprint',
  executionDomain: 'static',
  aspects: compilerCodegenFingerprintAspects,
  surfaceRules: {
    tier: 1,
    activateOn: {
      fileTypes: [
        'compiler-codegen',
        'codegen',
        'compiler-provenance',
        'toolchain-provenance',
        'build-provenance',
        'optimization-level',
        'lto',
        'pgo',
        'rich-header',
        'codeview',
        'pe',
        'pe32',
        'pe64',
        'dll',
        'exe',
        'sys',
        'pe-clr',
        'elf',
        'elf-executable',
        'elf-so',
        'elf-object',
        'linux-binary',
        'macho',
        'mach-o',
        'macho-object',
        'dylib',
        'coff',
        'coff-lib',
        'object',
        'static-lib',
      ],
      findings: [
        'compiler provenance',
        'codegen fingerprint',
        'Rich header',
        'CodeView',
        'RSDS',
        'NB10',
        'PDB',
        'DWARF producer',
        'GCC:',
        'clang version',
        'rustc',
        'Go build ID',
        'LC_BUILD_VERSION',
        'LTO',
        'PGO',
      ],
    },
    category: 'static-analysis',
  },
  description:
    'Passive compiler/codegen provenance fingerprinting across PE, ELF, Mach-O, COFF, and native objects using bounded static evidence such as Rich/CodeView, .comment, build-id, language runtime markers, linker hints, and optimization/LTO/PGO signals.',
  version: '1.0.0',
  tools: [
    defineTool({
      ...compilerCodegenFingerprintToolDefinition,
      handler: (args, deps) => createCompilerCodegenFingerprintHandler(deps)(args as never),
    }),
  ],
})

export default compilerCodegenPlugin
