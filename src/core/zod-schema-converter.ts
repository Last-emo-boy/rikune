/**
 * Zod-to-JSON-Schema converter
 *
 * Recursively converts Zod schemas into JSON Schema objects for the MCP
 * protocol `tools/list` response.
 */

import { z } from 'zod'

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
  if (schema instanceof z.ZodEffects) {
    return isFieldRequired(schema._def.schema)
  }
  if (schema instanceof z.ZodNullable) {
    return isFieldRequired(schema._def.innerType)
  }
  if (schema instanceof z.ZodBranded) {
    return isFieldRequired(schema._def.type)
  }
  if (schema instanceof z.ZodReadonly) {
    return isFieldRequired(schema._def.innerType)
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
  if (schema instanceof z.ZodEffects && schema.description) {
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
  schema: z.ZodArray<z.ZodTypeAny>
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
    if (schema instanceof z.ZodEffects) {
      return generateSchemaExample(schema._def.schema)
    }
    if (schema instanceof z.ZodOptional || schema instanceof z.ZodNullable || schema instanceof z.ZodCatch) {
      return generateSchemaExample(schema._def.innerType)
    }
    if (schema instanceof z.ZodDefault) {
      return generateSchemaExample(schema._def.innerType)
    }
    if (schema instanceof z.ZodBranded) {
      return generateSchemaExample(schema._def.type)
    }
    if (schema instanceof z.ZodReadonly) {
      return generateSchemaExample(schema._def.innerType)
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
    return generateFieldExample(schema._def.innerType)
  }

  // Handle nullable fields
  if (schema instanceof z.ZodNullable) {
    return generateFieldExample(schema._def.innerType)
  }

  // Handle default values
  if (schema instanceof z.ZodDefault) {
    return schema._def.defaultValue()
  }

  if (schema instanceof z.ZodCatch) {
    return generateFieldExample(schema._def.innerType)
  }

  if (schema instanceof z.ZodEffects) {
    return generateFieldExample(schema._def.schema)
  }

  if (schema instanceof z.ZodBranded) {
    return generateFieldExample(schema._def.type)
  }

  if (schema instanceof z.ZodReadonly) {
    return generateFieldExample(schema._def.innerType)
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
    const elementExample = generateFieldExample(schema._def.type)
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
    const values = schema._def.values as string[]
    return values[0]
  }

  // Handle literal
  if (schema instanceof z.ZodLiteral) {
    return schema._def.value
  }

  // Handle union
  if (schema instanceof z.ZodUnion) {
    const options = schema._def.options as z.ZodTypeAny[]
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
    return withSchemaMetadata(zodFieldToJsonSchema(schema._def.innerType), schema)
  }

  // Handle nullable
  if (schema instanceof z.ZodNullable) {
    const innerSchema = zodFieldToJsonSchema(schema._def.innerType)
    return withSchemaMetadata({
      anyOf: [innerSchema, { type: 'null' }],
    }, schema)
  }

  // Handle defaults
  if (schema instanceof z.ZodDefault) {
    const innerSchema = zodFieldToJsonSchema(schema._def.innerType)
    try {
      return withSchemaMetadata({
        ...innerSchema,
        default: schema._def.defaultValue(),
      }, schema)
    } catch {
      return withSchemaMetadata(innerSchema, schema)
    }
  }

  // Handle catch fallback values
  if (schema instanceof z.ZodCatch) {
    return withSchemaMetadata(zodFieldToJsonSchema(schema._def.innerType), schema)
  }

  // Handle effects/transform wrappers
  if (schema instanceof z.ZodEffects) {
    return withSchemaMetadata(zodFieldToJsonSchema(schema._def.schema), schema)
  }

  // Handle branded types
  if (schema instanceof z.ZodBranded) {
    return withSchemaMetadata(zodFieldToJsonSchema(schema._def.type), schema)
  }

  // Handle readonly wrapper
  if (schema instanceof z.ZodReadonly) {
    return withSchemaMetadata(zodFieldToJsonSchema(schema._def.innerType), schema)
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
    const elementType = schema._def.type
    const hasConcreteItemType =
      !(elementType instanceof z.ZodAny) && !(elementType instanceof z.ZodUnknown)
    const base: Record<string, unknown> = { type: 'array' }
    if (hasConcreteItemType) {
      base.items = zodFieldToJsonSchema(elementType)
    }
    return withSchemaMetadata(
      applyArrayChecks(base, schema),
      schema
    )
  }

  // Handle enum
  if (schema instanceof z.ZodEnum) {
    return withSchemaMetadata({
      type: 'string',
      enum: schema._def.values,
    }, schema)
  }

  // Handle literal
  if (schema instanceof z.ZodLiteral) {
    const literalValue = schema._def.value
    const literalType = literalValue === null ? 'null' : typeof literalValue
    return withSchemaMetadata({
      type: literalType,
      const: literalValue,
    }, schema)
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

    const catchall = (schema as any)._def?.catchall as z.ZodTypeAny | undefined
    const unknownKeys = (schema as any)._def?.unknownKeys as string | undefined

    return withSchemaMetadata(
      {
        type: 'object',
        properties,
        ...(required.length > 0 ? { required } : {}),
        ...(
          catchall && !isNeverSchema(catchall)
            ? { additionalProperties: zodFieldToJsonSchema(catchall) }
            : unknownKeys === 'passthrough'
              ? { additionalProperties: true }
              : { additionalProperties: false }
        ),
      },
      schema
    )
  }

  // Handle union
  if (schema instanceof z.ZodUnion) {
    const options = schema._def.options as z.ZodTypeAny[]
    return withSchemaMetadata({
      anyOf: options.map((option) => zodFieldToJsonSchema(option)),
    }, schema)
  }

  // Handle discriminated union
  if (schema instanceof z.ZodDiscriminatedUnion) {
    const options = Array.from(schema.options.values()) as z.ZodTypeAny[]
    return withSchemaMetadata({
      anyOf: options.map((option) => zodFieldToJsonSchema(option)),
    }, schema)
  }

  // Handle record
  if (schema instanceof z.ZodRecord) {
    return withSchemaMetadata({
      type: 'object',
      additionalProperties: zodFieldToJsonSchema(schema._def.valueType),
    }, schema)
  }

  // Handle tuple
  if (schema instanceof z.ZodTuple) {
    return withSchemaMetadata({
      type: 'array',
      items: schema._def.items.map((item: z.ZodTypeAny) => zodFieldToJsonSchema(item)),
    }, schema)
  }

  // Default
  return withSchemaMetadata({ type: 'string' }, schema)
}
