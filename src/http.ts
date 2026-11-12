import type { LogCode, OAuthErrorCode } from './types'

// null when over the limit. A declared Content-Length over it is refused unread, but the header is not
// trusted: the bytes actually read are counted, and reading stops at the first byte past the limit.
export async function readBody(request: Request, maxBytes: number): Promise<string | null> {
    if (Number(request.headers.get('content-length')) > maxBytes) return null
    if (!request.body) return ''
    const reader = request.body.getReader()
    const decoder = new TextDecoder()
    let size = 0
    let text = ''
    for (;;) {
        const { done, value } = await reader.read()
        if (done) return text + decoder.decode()
        size += value.byteLength
        if (size > maxBytes) {
            await reader.cancel()
            return null
        }
        text += decoder.decode(value, { stream: true })
    }
}

export function json(status: number, body: unknown, headers?: HeadersInit): Response {
    return Response.json(body, { status, headers: new Headers(headers) })
}

export function empty(status: number, headers?: HeadersInit): Response {
    return new Response(null, { status, headers: new Headers(headers) })
}

const SUBJECT_TOKEN_CODES: LogCode[] = [
    'malformed_token',
    'untrusted_issuer',
    'bad_algorithm',
    'bad_signature',
    'unknown_key',
    'expired',
    'too_old',
    'not_yet_valid',
    'missing_claim',
    'claim_mismatch',
    'client_mismatch',
    'bad_uid',
]

// Fixed phrases, so a description never echoes request or token content. Every subject token failure shares
// one, so the endpoint is not an oracle; the precise reason is the log code.
const DESCRIPTIONS: [status: number, error: OAuthErrorCode, codes: LogCode[], description: string][] = [
    [400, 'invalid_request', ['bad_request'], 'The request is malformed.'],
    [400, 'invalid_request', SUBJECT_TOKEN_CODES, 'The subject token is not acceptable.'],
    [400, 'invalid_target', ['unknown_product', 'bad_request'], 'The requested audience is not available.'],
    [400, 'invalid_scope', ['bad_request'], 'Scopes are not supported.'],
    [400, 'unsupported_grant_type', ['unsupported_grant'], 'Only token exchange is supported.'],
    [413, 'invalid_request', ['too_large'], 'The request is too large.'],
    [503, 'temporarily_unavailable', ['jwks_unavailable'], 'The identity provider is unavailable.'],
    [500, 'server_error', ['runtime_unavailable', 'internal_error'], 'The service failed.'],
]

// A combination outside the table is a bug in the caller: throwing turns it into a 500 rather than a wrong
// description. The no-store headers and Vary win over extra headers of the same name.
export function oauthError(status: number, error: OAuthErrorCode, code: LogCode, headers?: HeadersInit): Response {
    const row = DESCRIPTIONS.find(([s, e, codes]) => s === status && e === error && codes.includes(code))
    if (!row) throw new Error(`no error description for ${status} ${error} ${code}`)
    const merged = new Headers(headers)
    merged.set('cache-control', 'no-store')
    merged.set('pragma', 'no-cache')
    merged.set('vary', 'Origin')
    return json(status, { error, error_description: row[3] }, merged)
}
