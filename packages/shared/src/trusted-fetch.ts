import type { Dispatcher } from 'undici'
import {
  assertTrustedHttpEndpoint,
  createTrustedLookup,
  type TrustedLookupResolver,
} from './network-endpoint-policy.js'

type TrustedFetchInput = string | URL | Request

export interface TrustedFetchOptions {
  allowedOrigins?: readonly (string | URL)[]
  label?: string
  resolveEndpointAddresses?: TrustedLookupResolver
}

export interface TrustedFetch {
  (input: TrustedFetchInput, init?: RequestInit): Promise<Response>
  close(): Promise<void>
}

function getRequestUrl(input: TrustedFetchInput): string {
  if (typeof input === 'string') {
    return input
  }
  if (input instanceof URL) {
    return input.toString()
  }
  return input.url
}

async function loadUndici(): Promise<typeof import('undici')> {
  return import('undici')
}

/**
 * Build a fetch implementation whose socket target is selected only after the
 * complete DNS answer has passed the shared endpoint policy. The original
 * hostname remains the HTTP authority and TLS server name.
 */
export function createTrustedFetch(options: TrustedFetchOptions = {}): TrustedFetch {
  const trustedLookup = createTrustedLookup(options.resolveEndpointAddresses)
  let dispatcherPromise: Promise<Dispatcher> | undefined
  let closePromise: Promise<void> | undefined
  let closed = false

  const getDispatcher = (): Promise<Dispatcher> => {
    if (!dispatcherPromise) {
      dispatcherPromise = loadUndici().then(
        ({ Agent }) =>
          new Agent({
            connect: {
              lookup: trustedLookup,
              maxCachedSessions: 0,
            },
          })
      )
    }
    return dispatcherPromise
  }

  const trustedFetch = (async (input: TrustedFetchInput, init: RequestInit = {}) => {
    if (closed) {
      throw new Error('Trusted fetch client is closed')
    }
    const requestUrl = getRequestUrl(input)
    assertTrustedHttpEndpoint(requestUrl, {
      label: options.label || 'request endpoint',
      allowedOrigins: options.allowedOrigins,
    })
    const dispatcher = await getDispatcher()
    return globalThis.fetch(input, {
      ...init,
      redirect: 'error',
      // Never accept a caller-provided dispatcher that could bypass the lookup.
      dispatcher,
    } as RequestInit)
  }) as TrustedFetch

  trustedFetch.close = () => {
    closed = true
    if (!closePromise) {
      closePromise = (async () => {
        if (!dispatcherPromise) {
          return
        }
        const dispatcher = await dispatcherPromise
        await dispatcher.close()
      })()
    }
    return closePromise
  }

  return trustedFetch
}
