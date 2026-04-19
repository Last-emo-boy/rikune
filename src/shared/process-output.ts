/**
 * Helpers for decoding process output and rendering raw command lines.
 */

export interface DecodedProcessText {
  text: string
  encoding: string
}

export interface DecodedProcessStreams {
  stdout: DecodedProcessText
  stderr: DecodedProcessText
}

const WINDOWS_CANDIDATE_ENCODINGS = ['utf-8', 'gb18030', 'gbk', 'cp936', 'utf-16le', 'latin1']
const DEFAULT_CANDIDATE_ENCODINGS = ['utf-8', 'utf-16le', 'latin1']

function toBuffer(input: Buffer | string | null | undefined): Buffer {
  if (input === undefined || input === null) {
    return Buffer.alloc(0)
  }
  if (Buffer.isBuffer(input)) {
    return input
  }
  return Buffer.from(input)
}

function scoreDecodedText(text: string): number {
  if (!text) {
    return 0
  }

  let replacementCount = 0
  let controlCount = 0

  for (const char of text) {
    const code = char.charCodeAt(0)
    if (code === 0xfffd) {
      replacementCount += 1
      continue
    }
    if (code < 32 && char !== '\r' && char !== '\n' && char !== '\t') {
      controlCount += 1
    }
  }

  return text.length - replacementCount * 8 - controlCount * 2
}

function tryDecode(buffer: Buffer, encoding: string): string | null {
  try {
    const decoder = new TextDecoder(encoding)
    return decoder.decode(buffer)
  } catch {
    return null
  }
}

export function decodeProcessText(
  input: Buffer | string | null | undefined,
  platform: NodeJS.Platform = process.platform
): DecodedProcessText {
  if (typeof input === 'string') {
    return {
      text: input,
      encoding: 'utf-8',
    }
  }

  const buffer = toBuffer(input)
  if (buffer.length === 0) {
    return {
      text: '',
      encoding: 'utf-8',
    }
  }

  const candidateEncodings =
    platform === 'win32' ? WINDOWS_CANDIDATE_ENCODINGS : DEFAULT_CANDIDATE_ENCODINGS

  let best: DecodedProcessText | null = null
  let bestScore = Number.NEGATIVE_INFINITY

  for (const encoding of candidateEncodings) {
    const decoded = tryDecode(buffer, encoding)
    if (decoded === null) {
      continue
    }

    const score = scoreDecodedText(decoded)
    if (score > bestScore) {
      bestScore = score
      best = {
        text: decoded,
        encoding,
      }
    }
  }

  if (best) {
    return best
  }

  return {
    text: buffer.toString('utf8'),
    encoding: 'utf-8',
  }
}

export function decodeProcessStreams(
  stdout: Buffer | string | null | undefined,
  stderr: Buffer | string | null | undefined,
  platform: NodeJS.Platform = process.platform
): DecodedProcessStreams {
  return {
    stdout: decodeProcessText(stdout, platform),
    stderr: decodeProcessText(stderr, platform),
  }
}

export function buildRawCommandLine(command: string, args: string[]): string {
  return [command, ...args].join(' ').trim()
}
