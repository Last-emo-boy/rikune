import { describe, expect, test } from '@jest/globals'
import {
  buildMlModelInventoryFromBuffer,
  mlModelInventoryToolDefinition,
} from '../../src/plugins/ml-model/tools/ml-model-inventory.js'

function u64(value: number): Buffer {
  const data = Buffer.alloc(8)
  data.writeBigUInt64LE(BigInt(value), 0)
  return data
}

function protoVarint(value: number): Buffer {
  const bytes: number[] = []
  let current = value
  while (current >= 0x80) {
    bytes.push((current & 0x7f) | 0x80)
    current = Math.floor(current / 128)
  }
  bytes.push(current)
  return Buffer.from(bytes)
}

function protoField(field: number, wireType: number, body: Buffer): Buffer {
  return Buffer.concat([protoVarint((field << 3) | wireType), body])
}

function protoString(field: number, value: string): Buffer {
  const body = Buffer.from(value, 'utf8')
  return protoField(field, 2, Buffer.concat([protoVarint(body.length), body]))
}

function protoMessage(field: number, body: Buffer): Buffer {
  return protoField(field, 2, Buffer.concat([protoVarint(body.length), body]))
}

function protoInt(field: number, value: number): Buffer {
  return protoField(field, 0, protoVarint(value))
}

function storedZip(entries: Array<{ path: string; body?: Buffer }>): Buffer {
  const chunks: Buffer[] = []
  for (const entry of entries) {
    const name = Buffer.from(entry.path, 'utf8')
    const body = entry.body ?? Buffer.alloc(0)
    const header = Buffer.alloc(30)
    header.writeUInt32LE(0x04034b50, 0)
    header.writeUInt16LE(0, 8)
    header.writeUInt32LE(body.length, 18)
    header.writeUInt32LE(body.length, 22)
    header.writeUInt16LE(name.length, 26)
    chunks.push(header, name, body)
  }
  return Buffer.concat(chunks)
}

function safetensorsFixture(): Buffer {
  const header = Buffer.from(
    JSON.stringify({
      weight: { dtype: 'F32', shape: [2, 2], data_offsets: [0, 16] },
      bias: { dtype: 'F16', shape: [2], data_offsets: [16, 20] },
      __metadata__: {
        license: 'apache-2.0',
        source: 'https://example.invalid/model',
        chat_template: '{{ system prompt }}',
      },
    }),
    'utf8'
  )
  return Buffer.concat([u64(header.length), header, Buffer.alloc(20)])
}

function ggufFixture(): Buffer {
  const key = Buffer.from('tokenizer.chat_template', 'utf8')
  const value = Buffer.from('{{ system prompt }}', 'utf8')
  const tensor = Buffer.from('blk.0.attn_q.weight', 'utf8')
  return Buffer.concat([
    Buffer.from('GGUF', 'ascii'),
    Buffer.from([0x03, 0x00, 0x00, 0x00]),
    u64(1),
    u64(1),
    u64(key.length),
    key,
    Buffer.from([0x08, 0x00, 0x00, 0x00]),
    u64(value.length),
    value,
    u64(tensor.length),
    tensor,
    Buffer.from([0x02, 0x00, 0x00, 0x00]),
    u64(16),
    u64(16),
    Buffer.from([0x0c, 0x00, 0x00, 0x00]),
    u64(0),
  ])
}

function npyFixture(descr = '|O'): Buffer {
  const headerText = `{'descr': '${descr}', 'fortran_order': False, 'shape': (2,), }`
  const header = Buffer.from(headerText.padEnd(80, ' ') + '\n', 'latin1')
  const prefix = Buffer.alloc(10)
  prefix[0] = 0x93
  prefix.write('NUMPY', 1, 'ascii')
  prefix[6] = 1
  prefix[7] = 0
  prefix.writeUInt16LE(header.length, 8)
  return Buffer.concat([prefix, header, Buffer.alloc(16)])
}

function onnxFixture(): Buffer {
  const externalData = Buffer.concat([protoString(1, 'location'), protoString(2, '../weights.bin')])
  const tensor = Buffer.concat([protoString(8, 'weights'), protoMessage(13, externalData)])
  const node = Buffer.concat([protoString(4, 'CustomOp'), protoString(7, 'com.acme')])
  const graph = Buffer.concat([
    protoString(2, 'demo'),
    protoMessage(1, node),
    protoMessage(5, tensor),
  ])
  const opset = Buffer.concat([protoString(1, ''), protoInt(2, 18)])
  return Buffer.concat([
    protoInt(1, 9),
    protoString(2, 'unit-test'),
    protoMessage(7, graph),
    protoMessage(8, opset),
  ])
}

describe('ml.model.inventory', () => {
  test('parses SafeTensors tensor metadata without loading model data', () => {
    const inventory = buildMlModelInventoryFromBuffer(safetensorsFixture(), {
      filename: 'model.safetensors',
      sampleId: 'sha256:model',
    })

    expect(inventory.format).toBe('safetensors')
    expect(inventory.inventory).toEqual(
      expect.objectContaining({
        tensor_count: 2,
        dtype_counts: expect.objectContaining({ F32: 1, F16: 1 }),
      })
    )
    expect(inventory.policy).toEqual(
      expect.objectContaining({
        passive: true,
        no_deserialize: true,
        no_model_load: true,
        no_inference: true,
        no_ml_framework_load: true,
      })
    )
    expect(inventory.structure.safetensors).toEqual(
      expect.objectContaining({ decode_status: 'parsed', bounds_validated: true })
    )
    expect(inventory.risk_signals.map((signal: any) => signal.id)).toEqual(
      expect.arrayContaining([
        'safetensors.metadata.url_reference',
        'safetensors.metadata.prompt_template',
      ])
    )
  })

  test('flags PyTorch zip checkpoints as pickle loader risk', () => {
    const pickle = Buffer.concat([
      Buffer.from([0x80, 0x02, 0x63]),
      Buffer.from('posix\nsystem\n', 'utf8'),
      Buffer.from([0x52, 0x2e]),
    ])
    const inventory = buildMlModelInventoryFromBuffer(
      storedZip([
        { path: 'archive/data.pkl', body: pickle },
        { path: 'archive/version', body: Buffer.from('3\n') },
      ]),
      { filename: 'model.pt' }
    )

    expect(inventory.format).toBe('pytorch-checkpoint')
    expect(inventory.pickle_profile).toEqual(
      expect.objectContaining({
        dangerous_globals: expect.arrayContaining(['posix.system']),
      })
    )
    expect(inventory.risk_signals.map((signal: any) => signal.id)).toEqual(
      expect.arrayContaining(['pytorch.pickle_checkpoint', 'pickle.dangerous_global'])
    )
    expect(inventory.quality_gates).toEqual(
      expect.objectContaining({
        deserialized_by_tool: false,
        model_loaded_by_tool: false,
        inference_started_by_tool: false,
      })
    )
  })

  test('parses GGUF metadata and tensor directory without reading tensor payloads', () => {
    const inventory = buildMlModelInventoryFromBuffer(ggufFixture(), { filename: 'llm.gguf' })

    expect(inventory.format).toBe('gguf')
    expect(inventory.structure.gguf).toEqual(
      expect.objectContaining({
        decode_status: 'parsed',
        version: 3,
        tensor_count: 1,
      })
    )
    expect(inventory.inventory.tensor_preview).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ name: 'blk.0.attn_q.weight', quantization_type: 'Q4_K' }),
      ])
    )
    expect(inventory.risk_signals.map((signal: any) => signal.id)).toContain(
      'gguf.metadata.prompt_template'
    )
  })

  test('flags NumPy object dtype without calling numpy.load', () => {
    const inventory = buildMlModelInventoryFromBuffer(npyFixture(), { filename: 'array.npy' })

    expect(inventory.format).toBe('npy')
    expect(inventory.structure.npy).toEqual(
      expect.objectContaining({ decode_status: 'parsed', object_dtype: true })
    )
    expect(inventory.risk_signals.map((signal: any) => signal.id)).toContain('numpy.object_dtype')
    expect(inventory.policy.no_deserialize).toBe(true)
  })

  test('summarizes ONNX custom operators and external data references passively', () => {
    const inventory = buildMlModelInventoryFromBuffer(onnxFixture(), { filename: 'model.onnx' })

    expect(inventory.format).toBe('onnx')
    expect(inventory.structure.onnx).toEqual(
      expect.objectContaining({
        decode_status: 'parsed',
        graph: expect.objectContaining({
          custom_domains: ['com.acme'],
          external_data: expect.arrayContaining([
            expect.objectContaining({ key: 'location', value: '../weights.bin' }),
          ]),
        }),
      })
    )
    expect(inventory.risk_signals.map((signal: any) => signal.id)).toEqual(
      expect.arrayContaining(['onnx.custom_domain', 'onnx.external_data_reference'])
    )
  })

  test('declares passive tool metadata, artifacts, and workflow recipe', () => {
    expect(mlModelInventoryToolDefinition.aspects?.formats).toEqual(
      expect.arrayContaining(['ml-model', 'safetensors', 'gguf', 'onnx', 'tflite'])
    )
    expect(mlModelInventoryToolDefinition.aspects?.safety).toEqual(
      expect.arrayContaining(['passive', 'no_deserialization', 'no_model_load', 'no_inference'])
    )
    expect(mlModelInventoryToolDefinition.artifacts?.map((artifact) => artifact.type)).toContain(
      'ml_model_inventory'
    )
    expect(mlModelInventoryToolDefinition.workflowRecipes?.[0]).toEqual(
      expect.objectContaining({
        id: 'ml.model-static-inventory',
        startsWith: ['ml.model.inventory'],
        producesArtifacts: ['ml_model_inventory'],
        nextTools: expect.arrayContaining(['strings.extract', 'analysis.evidence.graph']),
      })
    )
  })
})
