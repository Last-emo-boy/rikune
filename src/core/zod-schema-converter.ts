/**
 * Zod-to-JSON-Schema converter
 *
 * Recursively converts Zod schemas into JSON Schema objects for the MCP
 * protocol `tools/list` response.
 */

import { z } from 'zod'

/**
 * Resolve a (possibly lazy) zod default value. zod4 stores the default as a
 * value on `_zod.def.defaultValue`; a thunk is still supported for lazy defaults.
 */
function resolveDefaultValue(schema: { _zod: { def: { defaultValue: unknown } } }): unknown {
  const dv: unknown = schema._zod.def.defaultValue
  return typeof dv === 'function' ? (dv as () => unknown)() : dv
}

/**
 * Convert Zod schema to JSON Schema format
 * Basic implementation for common Zod types
 */
export function zodToJsonSchema(schema: z.ZodTypeAny): Record<string, unknown> {
  const converted = zodFieldToJsonSchema(schema)
  if (converted && typeof converted === 'object') {
    return converted
  }

  return { type: 'object', properties: {} }
}

/**
 * Determine whether a field is required in object schema.
 * Optional/default/catch wrappers should not be marked as required.
 */
export function isFieldRequired(schema: z.ZodTypeAny): boolean {
  if (schema instanceof z.ZodOptional) {
    return false
  }
  if (schema instanceof z.ZodDefault) {
    return false
  }
  if (schema instanceof z.ZodCatch) {
    return false
  }
  // zod4: .transform() yields a ZodPipe (ZodEffects was removed); follow its input schema.
  if (schema instanceof z.ZodPipe) {
    return isFieldRequired(schema._zod.def.in as z.ZodTypeAny)
  }
  if (schema instanceof z.ZodNullable) {
    return isFieldRequired(schema.unwrap() as z.ZodTypeAny)
  }
  if (schema instanceof z.ZodReadonly) {
    return isFieldRequired(schema.unwrap() as z.ZodTypeAny)
  }

  return true
}

/**
 * Attach schema description when available.
 */
export function withSchemaMetadata(
  jsonSchema: Record<string, unknown>,
  schema: z.ZodTypeAny
): Record<string, unknown> {
  const withDescription = schema.description
    ? {
        ...jsonSchema,
        description: schema.description,
      }
    : jsonSchema

  const guidance = getSchemaGuidance(schema)
  if (guidance.length === 0) {
    return withDescription
  }

  return {
    ...withDescription,
    'x-guidance': guidance,
  }
}

export function getSchemaGuidance(schema: z.ZodTypeAny): string[] {
  // zod4: transforms are ZodPipe; surface their description as guidance.
  if (schema instanceof z.ZodPipe && schema.description) {
    return [schema.description]
  }

  return []
}

export function applyStringChecks(
  jsonSchema: Record<string, unknown>,
  schema: z.ZodString
): Record<string, unknown> {
  const checks = ((schema as any)._def?.checks || []) as Array<Record<string, unknown>>
  const result: Record<string, unknown> = { ...jsonSchema }

  for (const check of checks) {
    switch (check.kind) {
      case 'min':
        result.minLength = check.value
        break
      case 'max':
        result.maxLength = check.value
        break
      case 'email':
        result.format = 'email'
        break
      case 'url':
        result.format = 'uri'
        break
      case 'uuid':
        result.format = 'uuid'
        break
      case 'datetime':
        result.format = 'date-time'
        break
      case 'regex':
        if (check.regex instanceof RegExp) {
          result.pattern = check.regex.source
        }
        break
    }
  }

  return result
}

export function applyNumberChecks(
  jsonSchema: Record<string, unknown>,
  schema: z.ZodNumber
): Record<string, unknown> {
  const checks = ((schema as any)._def?.checks || []) as Array<Record<string, unknown>>
  const result: Record<string, unknown> = { ...jsonSchema }

  for (const check of checks) {
    switch (check.kind) {
      case 'int':
        result.type = 'integer'
        break
      case 'min':
        if (check.inclusive === false) {
          result.exclusiveMinimum = check.value
        } else {
          result.minimum = check.value
        }
        break
      case 'max':
        if (check.inclusive === false) {
          result.exclusiveMaximum = check.value
        } else {
          result.maximum = check.value
        }
        break
      case 'multipleOf':
        result.multipleOf = check.value
        break
    }
  }

  return result
}

export function applyArrayChecks(
  jsonSchema: Record<string, unknown>,
  schema: z.ZodTypeAny
): Record<string, unknown> {
  const def = (schema as any)._def || {}
  return {
    ...jsonSchema,
    ...(def.minLength?.value !== undefined ? { minItems: def.minLength.value } : {}),
    ...(def.maxLength?.value !== undefined ? { maxItems: def.maxLength.value } : {}),
  }
}

export function isNeverSchema(schema: z.ZodTypeAny): boolean {
  return schema instanceof z.ZodNever
}

/**
 * Generate an example object from a Zod schema
 * Helps users understand the expected input format
 */
export function generateSchemaExample(schema: z.ZodTypeAny): Record<string, unknown> | null {
  try {
    if (schema instanceof z.ZodPipe) {
      return generateSchemaExample(schema._zod.def.in as z.ZodTypeAny)
    }
    if (
      schema instanceof z.ZodOptional ||
      schema instanceof z.ZodNullable ||
      schema instanceof z.ZodCatch
    ) {
      return generateSchemaExample(schema.unwrap() as z.ZodTypeAny)
    }
    if (schema instanceof z.ZodDefault) {
      return generateSchemaExample(schema.unwrap() as z.ZodTypeAny)
    }
    if (schema instanceof z.ZodReadonly) {
      return generateSchemaExample(schema.unwrap() as z.ZodTypeAny)
    }

    // Handle ZodObject
    if (schema instanceof z.ZodObject) {
      const shape = schema.shape as Record<string, z.ZodTypeAny>
      const example: Record<string, unknown> = {}

      for (const [key, fieldSchema] of Object.entries(shape)) {
        example[key] = generateFieldExample(fieldSchema)
      }

      return example
    }

    return null
  } catch {
    return null
  }
}

/**
 * Generate an example value for a specific field schema
 */
export function generateFieldExample(schema: z.ZodTypeAny): unknown {
  // Handle optional fields
  if (schema instanceof z.ZodOptional) {
    return generateFieldExample(schema.unwrap() as z.ZodTypeAny)
  }

  // Handle nullable fields
  if (schema instanceof z.ZodNullable) {
    return generateFieldExample(schema.unwrap() as z.ZodTypeAny)
  }

  // Handle default values
  if (schema instanceof z.ZodDefault) {
    return resolveDefaultValue(schema)
  }

  if (schema instanceof z.ZodCatch) {
    return generateFieldExample(schema.unwrap() as z.ZodTypeAny)
  }

  // zod4: .transform() yields a ZodPipe; example off the input schema.
  if (schema instanceof z.ZodPipe) {
    return generateFieldExample(schema._zod.def.in as z.ZodTypeAny)
  }

  if (schema instanceof z.ZodReadonly) {
    return generateFieldExample(schema.unwrap() as z.ZodTypeAny)
  }

  // Handle string
  if (schema instanceof z.ZodString) {
    return 'string'
  }

  // Handle number
  if (schema instanceof z.ZodNumber) {
    return 0
  }

  // Handle boolean
  if (schema instanceof z.ZodBoolean) {
    return true
  }

  // Handle array
  if (schema instanceof z.ZodArray) {
    const elementExample = generateFieldExample(schema.element as z.ZodTypeAny)
    return [elementExample]
  }

  // Handle object
  if (schema instanceof z.ZodObject) {
    const shape = schema.shape as Record<string, z.ZodTypeAny>
    const example: Record<string, unknown> = {}
    for (const [key, fieldSchema] of Object.entries(shape)) {
      example[key] = generateFieldExample(fieldSchema)
    }
    return example
  }

  // Handle enum
  if (schema instanceof z.ZodEnum) {
    const values = schema.options as string[]
    return values[0]
  }

  // Handle literal
  if (schema instanceof z.ZodLiteral) {
    return [...schema.values][0]
  }

  // Handle union
  if (schema instanceof z.ZodUnion) {
    const options = schema.options as z.ZodTypeAny[]
    return generateFieldExample(options[0])
  }

  // Default fallback
  return 'value'
}

/**
 * Convert Zod field schema to JSON Schema property
 */
export function zodFieldToJsonSchema(schema: z.ZodTypeAny): Record<string, unknown> {
  // Handle optional
  if (schema instanceof z.ZodOptional) {
    return withSchemaMetadata(zodFieldToJsonSchema(schema.unwrap() as z.ZodTypeAny), schema)
  }

  // Handle nullable
  if (schema instanceof z.ZodNullable) {
    const innerSchema = zodFieldToJsonSchema(schema.unwrap() as z.ZodTypeAny)
    return withSchemaMetadata(
      {
        anyOf: [innerSchema, { type: 'null' }],
      },
      schema
    )
  }

  // Handle defaults
  if (schema instanceof z.ZodDefault) {
    const innerSchema = zodFieldToJsonSchema(schema.unwrap() as z.ZodTypeAny)
    try {
      return withSchemaMetadata(
        {
          ...innerSchema,
          default: resolveDefaultValue(schema),
        },
        schema
      )
    } catch {
      return withSchemaMetadata(innerSchema, schema)
    }
  }

  // Handle catch fallback values
  if (schema instanceof z.ZodCatch) {
    return withSchemaMetadata(zodFieldToJsonSchema(schema.unwrap() as z.ZodTypeAny), schema)
  }

  // Handle transform wrappers (zod4: ZodPipe replaced ZodEffects)
  if (schema instanceof z.ZodPipe) {
    return withSchemaMetadata(zodFieldToJsonSchema(schema._zod.def.in as z.ZodTypeAny), schema)
  }

  // Handle readonly wrapper
  if (schema instanceof z.ZodReadonly) {
    return withSchemaMetadata(zodFieldToJsonSchema(schema.unwrap() as z.ZodTypeAny), schema)
  }

  // Handle any/unknown
  if (schema instanceof z.ZodAny || schema instanceof z.ZodUnknown) {
    return withSchemaMetadata({}, schema)
  }

  // Handle string
  if (schema instanceof z.ZodString) {
    return withSchemaMetadata(applyStringChecks({ type: 'string' }, schema), schema)
  }

  // Handle number
  if (schema instanceof z.ZodNumber) {
    return withSchemaMetadata(applyNumberChecks({ type: 'number' }, schema), schema)
  }

  // Handle boolean
  if (schema instanceof z.ZodBoolean) {
    return withSchemaMetadata({ type: 'boolean' }, schema)
  }

  // Handle array
  if (schema instanceof z.ZodArray) {
    // When the element type is ZodAny/ZodUnknown, omit `items` entirely.
    // JSON Schema without `items` means any element is accepted, and avoids
    // emitting `items: {}` which strict validators (e.g. Copilot) reject
    // because the empty schema object has no `type` property.
    const elementType = schema.element as z.ZodTypeAny
    const hasConcreteItemType =
      !(elementType instanceof z.ZodAny) && !(elementType instanceof z.ZodUnknown)
    const base: Record<string, unknown> = { type: 'array' }
    if (hasConcreteItemType) {
      base.items = zodFieldToJsonSchema(elementType)
    }
    return withSchemaMetadata(applyArrayChecks(base, schema), schema)
  }

  // Handle enum
  if (schema instanceof z.ZodEnum) {
    return withSchemaMetadata(
      {
        type: 'string',
        enum: schema.options,
      },
      schema
    )
  }

  // Handle literal
  if (schema instanceof z.ZodLiteral) {
    const literalValue = [...schema.values][0]
    const literalType = literalValue === null ? 'null' : typeof literalValue
    return withSchemaMetadata(
      {
        type: literalType,
        const: literalValue,
      },
      schema
    )
  }

  // Handle object
  if (schema instanceof z.ZodObject) {
    const shape = schema.shape as Record<string, z.ZodTypeAny>
    const properties: Record<string, unknown> = {}
    const required: string[] = []

    for (const [key, fieldSchema] of Object.entries(shape)) {
      properties[key] = zodFieldToJsonSchema(fieldSchema)
      if (isFieldRequired(fieldSchema)) {
        required.push(key)
      }
    }

    // zod4: object key policy is expressed via `catchall` (z.never() = strict,
    // z.unknown()/loose = passthrough). There is no `unknownKeys` field anymore.
    const catchall = schema._zod.def.catchall as z.ZodTypeAny | undefined

    return withSchemaMetadata(
      {
        type: 'object',
        properties,
        ...(required.length > 0 ? { required } : {}),
        ...(catchall && !isNeverSchema(catchall)
          ? { additionalProperties: zodFieldToJsonSchema(catchall) }
          : { additionalProperties: false }),
      },
      schema
    )
  }

  // Handle union
  if (schema instanceof z.ZodUnion) {
    const options = schema.options as z.ZodTypeAny[]
    return withSchemaMetadata(
      {
        anyOf: options.map((option) => zodFieldToJsonSchema(option)),
      },
      schema
    )
  }

  // Handle discriminated union
  if (schema instanceof z.ZodDiscriminatedUnion) {
    const options = Array.from(schema.options as Iterable<z.ZodTypeAny>)
    return withSchemaMetadata(
      {
        anyOf: options.map((option) => zodFieldToJsonSchema(option)),
      },
      schema
    )
  }

  // Handle record
  if (schema instanceof z.ZodRecord) {
    return withSchemaMetadata(
      {
        type: 'object',
        additionalProperties: zodFieldToJsonSchema(schema.valueType as z.ZodTypeAny),
      },
      schema
    )
  }

  // Handle tuple
  if (schema instanceof z.ZodTuple) {
    const items = schema._zod.def.items as z.ZodTypeAny[]
    return withSchemaMetadata(
      {
        type: 'array',
        items: items.map((item: z.ZodTypeAny) => zodFieldToJsonSchema(item)),
      },
      schema
    )
  }

  // Default
  return withSchemaMetadata({ type: 'string' }, schema)
}
