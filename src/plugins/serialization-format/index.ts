/**
 * Serialization Format Plugin
 *
 * Passive identification and profiling of binary serialization formats:
 * Protocol Buffers (wire), Cap'n Proto, MessagePack, FlatBuffers, Thrift,
 * Avro, CBOR, and BSON. Never deserializes into runtime objects or follows
 * external schema references.
 */

import { definePlugin, defineTool } from '../sdk.js'
import {
  createSerializationInventoryHandler,
  serializationInventoryToolDefinition,
} from './tools/serialization-inventory.js'

const SERIALIZATION_FORMATS = [
  'protobuf',
  'capn-proto',
  'msgpack',
  'flatbuffers',
  'thrift',
  'avro',
  'cbor',
  'bson',
  'serialization',
  'binary-serialization',
]

const serializationFormatPlugin = definePlugin({
  id: 'serialization-format',
  name: 'Serialization Format Inventory',
  executionDomain: 'static',
  aspects: {
    formats: SERIALIZATION_FORMATS,
    platforms: ['cross-platform', 'linux', 'windows', 'macos', 'android', 'ios', 'embedded'],
    architectures: ['x86', 'x64', 'arm', 'arm64', 'wasm'],
    execution: ['static', 'triage', 'correlation', 'workflow-plan'],
    safety: [
      'passive',
      'no_deserialization',
      'no_runtime_decode',
      'no_network_by_default',
      'no_mutation',
      'no_extract_to_execution_path',
    ],
    capabilities: [
      'serialization-format-detection',
      'wire-format-profiling',
      'field-hint-extraction',
      'schema-risk-triage',
      'external-reference-detection',
      'workflow-routing',
    ],
    evidence: ['structure', 'metadata', 'strings', 'workflow', 'provenance'],
  },
  surfaceRules: {
    tier: 1,
    activateOn: {
      fileTypes: SERIALIZATION_FORMATS,
      findings: [
        'serialization-format',
        'wire-format',
        'schema-reference',
        'external-schema',
        'secret-like-string',
      ],
    },
    category: 'static-analysis',
  },
  description:
    "Passive identification and profiling of binary serialization formats: Protocol Buffers, Cap'n Proto, MessagePack, FlatBuffers, Thrift, Avro, CBOR, and BSON without runtime deserialization.",
  version: '1.0.0',
  tools: [
    defineTool({
      ...serializationInventoryToolDefinition,
      handler: (args, deps) => createSerializationInventoryHandler(deps)(args as never),
    }),
  ],
})

export default serializationFormatPlugin
