import type { FetchImplementation } from 'jose'
import type { Deps } from '../types'

export const JWKS_TIMEOUT_MS = 5000

// Messages are fixed and never quote the response
export class JwksFetchError extends Error {
    override name = 'JwksFetchError'
}

// The fetch given to jose for IdP key sets. jose throws a generic JOSEError for a non-200 or non-JSON answer,
// which could not be told apart from other failures, so every failure here is a JwksFetchError. The timer races
// jose's abort signal because a runtime without AbortController cannot abort the fetch; it covers the body too.
export function jwksFetch(fetch: Deps['fetch']): FetchImplementation {
    return (url, init) => withTimeout(load(fetch, url, init), JWKS_TIMEOUT_MS)
}

async function load(fetch: Deps['fetch'], url: string, init: RequestInit): Promise<Response> {
    let response: Response
    try {
        response = await fetch(url, init)
    } catch (cause) {
        throw new JwksFetchError('JWKS request failed', { cause })
    }
    if (response.status !== 200) {
        // Releases the connection rather than leaving the body unread
        await response.body?.cancel().catch(() => {})
        throw new JwksFetchError('JWKS response status is not 200')
    }
    let text: string
    try {
        // Decoded by hand: workerd warns when .text() reads a body whose type does not look like text
        text = new TextDecoder().decode(await response.arrayBuffer())
    } catch (cause) {
        throw new JwksFetchError('JWKS response body could not be read', { cause })
    }
    let body: unknown
    try {
        body = JSON.parse(text)
    } catch {
        throw new JwksFetchError('JWKS response is not JSON')
    }
    if (typeof body !== 'object' || body === null || Array.isArray(body)) throw new JwksFetchError('JWKS response is not a JSON object')
    return new Response(JSON.stringify(body), { headers: { 'content-type': 'application/json' } })
}

function withTimeout<T>(work: Promise<T>, ms: number): Promise<T> {
    return new Promise<T>((resolve, reject) => {
        const timer = setTimeout(() => reject(new JwksFetchError('JWKS request timed out')), ms)
        work.then(resolve, reject).finally(() => clearTimeout(timer))
    })
}
