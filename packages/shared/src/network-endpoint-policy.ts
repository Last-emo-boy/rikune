import dnsPromises from 'node:dns/promises'
import { isIP, type LookupFunction } from 'node:net'
import { createTrustedFetch, type TrustedFetch } from './trusted-fetch.js'

export type EndpointCredentialSource = 'none' | 'explicit' | 'configured'

export type EndpointPolicyErrorCode =
  | 'invalid_endpoint'
  | 'endpoint_scheme_not_allowed'
  | 'endpoint_userinfo_forbidden'
  | 'endpoint_query_forbidden'
  | 'endpoint_metadata_forbidden'
  | 'endpoint_origin_not_allowed'
  | 'credential_origin_mismatch'
  | 'endpoint_parent_mismatch'

export class EndpointPolicyError extends Error {
  readonly code: EndpointPolicyErrorCode
  readonly endpointLabel: string

  constructor(code: EndpointPolicyErrorCode, message: string, endpointLabel = 'endpoint') {
    super(message)
    this.name = 'EndpointPolicyError'
    this.code = code
    this.endpointLabel = endpointLabel
  }
}

export interface TrustedHttpEndpointOptions {
  label?: string
  configuredEndpoint?: string | URL
  credentialSource?: EndpointCredentialSource
  allowedOrigins?: readonly (string | URL)[]
  trustedParentEndpoint?: string | URL
  allowParentPortChange?: boolean
  rejectMetadataAddresses?: boolean
}

export interface ParsedHttpServiceEndpoint {
  url: URL
  origin: string
  hostname: string
}

export interface TrustedLookupAddress {
  address: string
  family: number
}

export type TrustedLookupResolver = (
  hostname: string,
  options: { all: true; verbatim: true }
) => Promise<readonly TrustedLookupAddress[]>

const HTTP_PROTOCOLS = new Set(['http:', 'https:'])
const METADATA_HOSTNAMES = new Set([
  'metadata',
  'metadata.google.internal',
  'metadata.google.com',
  'instance-data.ec2.internal',
  'metadata.azure.internal',
])

function endpointLabel(options?: TrustedHttpEndpointOptions): string {
  return options?.label || 'endpoint'
}

function normalizeHostname(hostname: string): string {
  let normalized = hostname.trim().toLowerCase()
  if (normalized.startsWith('[') && normalized.endsWith(']')) {
    normalized = normalized.slice(1, -1)
  }
  return normalized.replace(/\.+$/, '')
}

function formatHostname(hostname: string): string {
  return isIP(hostname) === 6 ? `[${hostname}]` : hostname
}

function defaultPort(protocol: string): string {
  return protocol === 'http:' ? '80' : '443'
}

function parseIpv4Words(value: string): number[] | null {
  if (isIP(value) !== 4) {
    return null
  }
  const octets = value.split('.').map((part) => Number(part))
  if (
    octets.length !== 4 ||
    octets.some((part) => !Number.isInteger(part) || part < 0 || part > 255)
  ) {
    return null
  }
  return octets
}

function parseIpv6Words(value: string): number[] | null {
  const normalized = normalizeHostname(value)
  if (isIP(normalized) !== 6) {
    return null
  }

  const compressionIndex = normalized.indexOf('::')
  if (compressionIndex >= 0 && compressionIndex !== normalized.lastIndexOf('::')) {
    return null
  }

  const parseGroups = (part: string): number[] | null => {
    if (!part) {
      return []
    }
    const groups = part.split(':')
    const words: number[] = []
    for (const [index, group] of groups.entries()) {
      if (group.includes('.')) {
        if (index !== groups.length - 1) {
          return null
        }
        const octets = parseIpv4Words(group)
        if (!octets) {
          return null
        }
        words.push((octets[0] << 8) | octets[1], (octets[2] << 8) | octets[3])
        continue
      }
      if (!/^[0-9a-f]{1,4}$/i.test(group)) {
        return null
      }
      words.push(Number.parseInt(group, 16))
    }
    return words
  }

  if (compressionIndex < 0) {
    const words = parseGroups(normalized)
    return words && words.length === 8 ? words : null
  }

  const left = parseGroups(normalized.slice(0, compressionIndex))
  const right = parseGroups(normalized.slice(compressionIndex + 2))
  if (!left || !right) {
    return null
  }
  const missing = 8 - left.length - right.length
  if (missing < 1) {
    return null
  }
  return [...left, ...Array.from({ length: missing }, () => 0), ...right]
}

function isMappedIpv4(words: readonly number[]): boolean {
  return words.length === 8 && words.slice(0, 5).every((word) => word === 0) && words[5] === 0xffff
}

function mappedIpv4FromWords(words: readonly number[]): string {
  return `${words[6] >> 8}.${words[6] & 0xff}.${words[7] >> 8}.${words[7] & 0xff}`
}

function isMetadataAddress(hostname: string): boolean {
  const normalized = normalizeHostname(hostname)
  if (METADATA_HOSTNAMES.has(normalized)) {
    return true
  }

  const ipVersion = isIP(normalized)
  if (ipVersion === 4) {
    const octets = normalized.split('.').map((part) => Number(part))
    if (octets.length !== 4 || octets.some((part) => !Number.isInteger(part))) {
      return false
    }
    if (octets.every((part) => part === 0)) {
      return true
    }
    if (octets[0] === 169 && octets[1] === 254) {
      return true
    }
    if (octets[0] === 100 && octets[1] === 100 && octets[2] === 100 && octets[3] === 200) {
      return true
    }
    return false
  }

  if (ipVersion === 6) {
    const words = parseIpv6Words(normalized)
    if (!words) {
      return false
    }
    if (isMappedIpv4(words) && isMetadataAddress(mappedIpv4FromWords(words))) {
      return true
    }
    const isEc2Metadata =
      words[0] === 0xfd00 &&
      words[1] === 0x0ec2 &&
      words.slice(2, 7).every((word) => word === 0) &&
      words[7] === 0x0254
    const isGcpMetadata =
      words[0] === 0xfd20 &&
      words[1] === 0x00ce &&
      words.slice(2, 7).every((word) => word === 0) &&
      words[7] === 0x0254
    if (isEc2Metadata || isGcpMetadata) {
      return true
    }
    return words.every((word) => word === 0) || (words[0] & 0xffc0) === 0xfe80
  }

  return false
}

function isForbiddenTrustedLookupAddress(address: string): boolean {
  const normalized = normalizeHostname(address)
  const words = parseIpv6Words(normalized)
  if (words && isMappedIpv4(words)) {
    return true
  }
  return isMetadataAddress(normalized)
}

function validateTrustedLookupAddresses(
  addresses: readonly TrustedLookupAddress[]
): TrustedLookupAddress[] {
  if (!Array.isArray(addresses) || addresses.length === 0) {
    throw new Error('Trusted DNS lookup returned no addresses.')
  }

  return addresses.map((entry, index) => {
    if (
      !entry ||
      typeof entry.address !== 'string' ||
      (entry.family !== 4 && entry.family !== 6) ||
      isIP(normalizeHostname(entry.address)) !== entry.family
    ) {
      throw new Error(`Trusted DNS lookup returned an invalid address at index ${index}.`)
    }
    if (isForbiddenTrustedLookupAddress(entry.address)) {
      throw new Error('Trusted DNS lookup returned a forbidden metadata or special-use address.')
    }
    return { address: entry.address, family: entry.family }
  })
}

async function resolveAllTrustedAddresses(
  hostname: string,
  _options: { all: true; verbatim: true }
): Promise<readonly TrustedLookupAddress[]> {
  const addresses = await dnsPromises.lookup(hostname, { all: true, verbatim: true })
  return addresses.map(({ address, family }) => ({ address, family }))
}

function lookupError(message: string): NodeJS.ErrnoException {
  const error = new Error(message) as NodeJS.ErrnoException
  error.code = 'ENOTFOUND'
  return error
}

function requestedLookupFamily(family: unknown): 0 | 4 | 6 {
  if (family === undefined || family === 0) {
    return 0
  }
  if (family === 4 || family === 'IPv4') {
    return 4
  }
  if (family === 6 || family === 'IPv6') {
    return 6
  }
  throw lookupError(`Unsupported DNS lookup family: ${String(family)}`)
}

export function createTrustedLookup(
  resolver: TrustedLookupResolver = resolveAllTrustedAddresses
): LookupFunction {
  return (hostname, options, callback) => {
    void (async () => {
      try {
        const addresses = validateTrustedLookupAddresses(
          await resolver(hostname, { all: true, verbatim: true })
        )
        const family = requestedLookupFamily(options?.family)
        const matching =
          family === 0 ? addresses : addresses.filter((entry) => entry.family === family)
        if (matching.length === 0) {
          callback(lookupError(`No trusted DNS address matched family ${family}.`), '', 0)
          return
        }
        if (options?.all === true) {
          callback(null, matching)
          return
        }
        callback(null, matching[0].address, matching[0].family)
      } catch (error) {
        callback(error instanceof Error ? error : lookupError(String(error)), '', 0)
      }
    })()
  }
}

export function parseHttpServiceEndpoint(
  value: string | URL,
  label = 'endpoint'
): ParsedHttpServiceEndpoint {
  let url: URL
  try {
    url = value instanceof URL ? new URL(value.toString()) : new URL(value.trim())
  } catch {
    throw new EndpointPolicyError('invalid_endpoint', `${label} must be a valid URL.`, label)
  }

  if (!HTTP_PROTOCOLS.has(url.protocol)) {
    throw new EndpointPolicyError(
      'endpoint_scheme_not_allowed',
      `${label} must use http or https.`,
      label
    )
  }
  if (url.username || url.password) {
    throw new EndpointPolicyError(
      'endpoint_userinfo_forbidden',
      `${label} must not contain URL credentials.`,
      label
    )
  }
  if (url.search || url.hash) {
    throw new EndpointPolicyError(
      'endpoint_query_forbidden',
      `${label} must not contain a query string or fragment.`,
      label
    )
  }

  const hostname = normalizeHostname(url.hostname)
  if (!hostname) {
    throw new EndpointPolicyError('invalid_endpoint', `${label} must include a hostname.`, label)
  }

  return {
    url,
    origin: canonicalHttpOrigin(url),
    hostname,
  }
}

export function canonicalHttpOrigin(value: string | URL): string {
  const url = value instanceof URL ? new URL(value.toString()) : new URL(value.trim())
  if (!HTTP_PROTOCOLS.has(url.protocol)) {
    throw new EndpointPolicyError(
      'endpoint_scheme_not_allowed',
      'Endpoint origin must use http or https.',
      'endpoint'
    )
  }
  const hostname = normalizeHostname(url.hostname)
  const port = url.port && url.port !== defaultPort(url.protocol) ? `:${url.port}` : ''
  return `${url.protocol}//${formatHostname(hostname)}${port}`
}

function originSet(values: readonly (string | URL)[] | undefined): Set<string> | undefined {
  if (values === undefined) {
    return undefined
  }
  return new Set(values.map((value) => canonicalHttpOrigin(value)))
}

export function sameHttpOrigin(left: string | URL, right: string | URL): boolean {
  return canonicalHttpOrigin(left) === canonicalHttpOrigin(right)
}

export function assertTrustedHttpEndpoint(
  value: string | URL,
  options: TrustedHttpEndpointOptions = {}
): ParsedHttpServiceEndpoint {
  const label = endpointLabel(options)
  const parsed = parseHttpServiceEndpoint(value, label)

  if (options.rejectMetadataAddresses !== false && isMetadataAddress(parsed.hostname)) {
    throw new EndpointPolicyError(
      'endpoint_metadata_forbidden',
      `${label} points to a metadata, link-local, or unspecified address.`,
      label
    )
  }

  const allowed = originSet(options.allowedOrigins)
  if (allowed && !allowed.has(parsed.origin)) {
    throw new EndpointPolicyError(
      'endpoint_origin_not_allowed',
      `${label} origin is not in the configured endpoint allowlist.`,
      label
    )
  }

  if (options.credentialSource === 'configured') {
    if (!options.configuredEndpoint) {
      if (!options.trustedParentEndpoint || options.allowParentPortChange !== true) {
        throw new EndpointPolicyError(
          'credential_origin_mismatch',
          `${label} cannot use configured credentials without a configured endpoint.`,
          label
        )
      }
    } else {
      const configured = parseHttpServiceEndpoint(options.configuredEndpoint, 'configured endpoint')
      if (configured.origin !== parsed.origin) {
        const trustedParent = options.trustedParentEndpoint
          ? parseHttpServiceEndpoint(options.trustedParentEndpoint, 'trusted parent endpoint')
          : undefined
        const trustedPortChange =
          options.allowParentPortChange === true &&
          trustedParent &&
          trustedParent.origin === configured.origin &&
          trustedParent.hostname === parsed.hostname &&
          trustedParent.url.protocol === parsed.url.protocol
        if (!trustedPortChange) {
          throw new EndpointPolicyError(
            'credential_origin_mismatch',
            `${label} must use the configured endpoint origin when configured credentials are used.`,
            label
          )
        }
      }
    }
  }

  if (options.trustedParentEndpoint) {
    const parent = parseHttpServiceEndpoint(
      options.trustedParentEndpoint,
      'trusted parent endpoint'
    )
    const sameHost =
      parent.hostname === parsed.hostname && parent.url.protocol === parsed.url.protocol
    const sameOrigin = parent.origin === parsed.origin
    const parentPortChange = options.allowParentPortChange === true && sameHost
    if (!sameOrigin && !parentPortChange) {
      throw new EndpointPolicyError(
        'endpoint_parent_mismatch',
        `${label} is not bound to the trusted parent endpoint.`,
        label
      )
    }
  }

  return parsed
}

export function endpointUrl(
  endpoint: string | URL,
  pathname: string,
  options: TrustedHttpEndpointOptions = {}
): string {
  const parsed = assertTrustedHttpEndpoint(endpoint, options)
  const resolved = new URL(pathname, parsed.url)
  if (canonicalHttpOrigin(resolved) !== parsed.origin) {
    const label = endpointLabel(options)
    throw new EndpointPolicyError(
      'endpoint_origin_not_allowed',
      `${label} path must not change the configured endpoint origin.`,
      label
    )
  }
  return resolved.toString()
}

export function createRedirectSafeFetch(
  options: {
    allowedOrigins?: readonly (string | URL)[]
    label?: string
    resolveEndpointAddresses?: TrustedLookupResolver
  } = {}
): TrustedFetch {
  return createTrustedFetch(options)
}
