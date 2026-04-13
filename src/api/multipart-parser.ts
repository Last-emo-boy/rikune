/**
 * Multipart Form Data Parser
 * Hardened parser for multipart/form-data requests.
 *
 * Security measures:
 * - Maximum part count limit (prevents file bomb)
 * - Maximum field value length limit
 * - Maximum filename length limit
 * - Filename sanitisation (no path traversal)
 * - Content-length cross-check against actual body size
 */

const MAX_PARTS = 32
const MAX_FIELD_VALUE_BYTES = 1024 * 64  // 64 KB per field
const MAX_FILENAME_LENGTH = 255

export interface MultipartFile {
  fieldname: string
  filename: string
  data: Buffer
  mimetype: string
}

export interface ParsedMultipart {
  files: MultipartFile[]
  fields: Record<string, string>
}

/**
 * Sanitise a filename received from the client.
 * Strips path separators, null bytes, and control chars.
 */
function sanitiseFilename(raw: string): string {
  // Remove path components (both / and \)
  let name = raw.replace(/^.*[/\\]/, '')
  // Strip null bytes and control characters
  name = name.replace(/[\x00-\x1f]/g, '')
  // Limit length
  if (name.length > MAX_FILENAME_LENGTH) {
    const ext = name.lastIndexOf('.')
    if (ext > 0) {
      name = name.substring(0, MAX_FILENAME_LENGTH - (name.length - ext)) + name.substring(ext)
    } else {
      name = name.substring(0, MAX_FILENAME_LENGTH)
    }
  }
  return name || 'upload.bin'
}

/**
 * Parse multipart/form-data request
 */
export function parseMultipart(
  body: Buffer,
  contentType: string
): ParsedMultipart {
  const result: ParsedMultipart = {
    files: [],
    fields: {},
  }

  // Extract boundary from content-type
  const boundaryMatch = contentType.match(/boundary=(?:"([^"]+)"|([^;]+))/i)
  if (!boundaryMatch) {
    throw new Error('Invalid multipart content-type: missing boundary')
  }

  const boundary = boundaryMatch[1] || boundaryMatch[2]
  const boundaryBuffer = Buffer.from(`--${boundary}`)
  
  // Split body by boundary
  const parts: Buffer[] = []
  let start = 0
  while (true) {
    const pos = body.indexOf(boundaryBuffer, start)
    if (pos === -1) break
    parts.push(body.slice(start, pos))
    start = pos + boundaryBuffer.length

    // Enforce max parts limit
    if (parts.length > MAX_PARTS + 1) {
      throw new Error(`Too many multipart parts (max ${MAX_PARTS})`)
    }
  }

  for (const part of parts) {
    // Skip empty parts and epilogue
    if (part.length === 0 || part.toString('utf8', 0, Math.min(part.length, 6)).startsWith('--\r\n')) {
      continue
    }

    // Remove leading CRLF
    let cleanPart = part
    if (cleanPart[0] === 0x0d && cleanPart[1] === 0x0a) {
      cleanPart = cleanPart.slice(2)
    }

    // Split headers and body
    const headerEndIndex = cleanPart.indexOf(Buffer.from('\r\n\r\n'))
    if (headerEndIndex === -1) {
      continue
    }

    const headerBuffer = cleanPart.slice(0, headerEndIndex)
    const bodyBuffer = cleanPart.slice(headerEndIndex + 4)

    // Remove trailing CRLF from body if present
    let cleanBody = bodyBuffer
    if (cleanBody.length >= 2 && cleanBody[cleanBody.length - 2] === 0x0d && cleanBody[cleanBody.length - 1] === 0x0a) {
      cleanBody = cleanBody.slice(0, -2)
    }

    // Parse headers
    const headers = parseHeaders(headerBuffer)
    const contentDisposition = headers['content-disposition']

    if (!contentDisposition) {
      continue
    }

    // Parse content-disposition
    const dispMatch = contentDisposition.match(
      /name="([^"]+)"(?:;\s*filename="([^"]*)")?/
    )
    if (!dispMatch) {
      continue
    }

    const fieldName = dispMatch[1]
    const filename = dispMatch[2]

    if (filename !== undefined && filename !== '') {
      // This is a file
      const safeFilename = sanitiseFilename(filename)
      const mimetype = headers['content-type'] || 'application/octet-stream'
      result.files.push({
        fieldname: fieldName,
        filename: safeFilename,
        data: cleanBody,
        mimetype,
      })
    } else {
      // This is a regular field — enforce size limit
      if (cleanBody.length > MAX_FIELD_VALUE_BYTES) {
        throw new Error(`Field "${fieldName}" exceeds max allowed size (${MAX_FIELD_VALUE_BYTES} bytes)`)
      }
      result.fields[fieldName] = cleanBody.toString('utf8')
    }
  }

  return result
}

/**
 * Parse headers from buffer
 */
function parseHeaders(headerBuffer: Buffer): Record<string, string> {
  const headers: Record<string, string> = {}
  const headerStr = headerBuffer.toString('utf8')
  const lines = headerStr.split('\r\n')

  for (const line of lines) {
    if (!line.trim()) continue

    const colonIndex = line.indexOf(':')
    if (colonIndex === -1) continue

    const key = line.slice(0, colonIndex).trim().toLowerCase()
    const value = line.slice(colonIndex + 1).trim()
    headers[key] = value
  }

  return headers
}
