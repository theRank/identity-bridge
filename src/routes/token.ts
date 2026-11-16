import { empty, json, oauthError, readBody } from '../http'
import { BadUidError, deriveUserId } from '../ids'
import { ExchangeError, verifySubjectToken, type VerifiedSubject } from '../idp/verify'
import { mintAccessToken } from '../tokens'
import type { Config, Deps, LogCode, OAuthErrorCode, ProductConfig, RouteContext, RouteHandler, Runtime } from '../types'

const FORM = 'application/x-www-form-urlencoded'
const MAX_BODY_BYTES = 16384
const TOKEN_EXCHANGE = 'urn:ietf:params:oauth:grant-type:token-exchange'
const ACCESS_TOKEN_TYPE = 'urn:ietf:params:oauth:token-type:access_token'
const SUBJECT_TOKEN_TYPES = ['urn:ietf:params:oauth:token-type:jwt', ACCESS_TOKEN_TYPE, 'urn:ietf:params:oauth:token-type:id_token']
const RECOGNIZED = [
    'grant_type',
    'subject_token',
    'subject_token_type',
    'audience',
    'requested_token_type',
    'actor_token',
    'actor_token_type',
    'scope',
    'resource',
]
const NO_STORE = { 'cache-control': 'no-store', pragma: 'no-cache' }
// On every answer, POST and OPTIONS alike, because whether CORS headers are given depends on the Origin
const VARY = { vary: 'Origin' }
const PREFLIGHT = { 'access-control-allow-methods': 'POST', 'access-control-allow-headers': 'Content-Type', 'access-control-max-age': '600' }
const STATUS: Record<ExchangeError['error'], number> = { invalid_request: 400, temporarily_unavailable: 503 }

type Rejection = [error: OAuthErrorCode, code: LogCode]

const MALFORMED: Rejection = ['invalid_request', 'bad_request']

interface ExchangeRequest {
    subjectToken: string
    audience: string
}

export const tokenRoute: RouteHandler = async (request, runtime, deps, ctx) => {
    if (request.method === 'OPTIONS') return preflight(request, runtime.config)
    return exchange(request, runtime, deps, ctx)
}

async function exchange(request: Request, runtime: Runtime, deps: Deps, ctx: RouteContext): Promise<Response> {
    if (mediaType(request.headers.get('content-type')) !== FORM) return reject(ctx, 400, 'invalid_request', 'bad_request')
    const body = await readBody(request, MAX_BODY_BYTES)
    if (body === null) return reject(ctx, 413, 'invalid_request', 'too_large')
    const params = validate(formParams(body))
    if (Array.isArray(params)) return reject(ctx, 400, ...params)

    const product = runtime.config.products[params.audience]
    if (product === undefined) return reject(ctx, 400, 'invalid_target', 'unknown_product')
    ctx.product = product.id
    const cors = corsHeaders(request, product)
    try {
        return await issue(params.subjectToken, product, runtime, deps, ctx, cors)
    } catch {
        // Answered here because handle's answer has no CORS headers, so a browser could not read it. The error is
        // dropped, as it may quote the token.
        return reject(ctx, 500, 'server_error', 'internal_error', cors)
    }
}

async function issue(
    subjectToken: string,
    product: ProductConfig,
    runtime: Runtime,
    deps: Deps,
    ctx: RouteContext,
    cors: Record<string, string>,
): Promise<Response> {
    let verified: VerifiedSubject
    try {
        verified = await verifySubjectToken(subjectToken, product, runtime.config, deps)
    } catch (error) {
        if (!(error instanceof ExchangeError)) throw error
        if (error.idp !== undefined) ctx.idp = error.idp
        return reject(ctx, STATUS[error.error], error.error, error.code, cors)
    }
    const { idp, subject, uid, profile } = verified
    ctx.idp = idp.id

    let userId: string
    try {
        userId = await deriveUserId(idp.issuer, subject, uid)
    } catch (error) {
        if (!(error instanceof BadUidError)) throw error
        return reject(ctx, 400, 'invalid_request', 'bad_uid', cors)
    }
    const identity = { userId, idpId: idp.id, profile }
    const accessToken = await mintAccessToken(runtime.keys, runtime.config, product.id, identity, Math.floor(deps.now() / 1000), deps.randomUUID())
    const body = {
        access_token: accessToken,
        issued_token_type: ACCESS_TOKEN_TYPE,
        token_type: 'Bearer',
        expires_in: runtime.config.tokenTtlSeconds,
    }
    return json(200, body, { ...NO_STORE, ...VARY, ...cors })
}

// The product is named only in the body, which a preflight does not carry, so an origin of any product is allowed
function preflight(request: Request, config: Config): Response {
    const origin = request.headers.get('origin')
    const listed = origin !== null && Object.values(config.products).some((product) => product.allowedOrigins.includes(origin))
    return empty(204, listed ? { ...VARY, 'access-control-allow-origin': origin, ...PREFLIGHT } : VARY)
}

// CORS is a browser control, not authentication: an origin the product does not list is still served, only
// without the header that lets a browser read the answer
function corsHeaders(request: Request, product: ProductConfig): Record<string, string> {
    const origin = request.headers.get('origin')
    return origin !== null && product.allowedOrigins.includes(origin) ? { 'access-control-allow-origin': origin } : {}
}

function mediaType(contentType: string | null): string {
    return (contentType ?? '').split(';', 1)[0]!.trim().toLowerCase()
}

// An empty value counts as omitted (RFC 6749 §3.2): it neither makes a repeat nor satisfies a required parameter
function formParams(body: string): Map<string, string[]> {
    const params = new Map<string, string[]>()
    for (const [name, value] of new URLSearchParams(body)) {
        if (value === '' || !RECOGNIZED.includes(name)) continue
        const values = params.get(name)
        if (values === undefined) params.set(name, [value])
        else values.push(value)
    }
    return params
}

// The order decides the answer to a request that breaks several rules: repeats are checked before the grant
// type, so a repeated grant_type is invalid_request even when one of its values is another grant
function validate(params: Map<string, string[]>): ExchangeRequest | Rejection {
    if ((params.get('audience')?.length ?? 0) > 1) return ['invalid_target', 'bad_request']
    for (const values of params.values()) if (values.length > 1) return MALFORMED
    const value = (name: string) => params.get(name)?.[0]

    const grantType = value('grant_type')
    if (grantType === undefined) return MALFORMED
    if (grantType !== TOKEN_EXCHANGE) return ['unsupported_grant_type', 'unsupported_grant']
    if (params.has('resource')) return ['invalid_target', 'bad_request']
    if (params.has('scope')) return ['invalid_scope', 'bad_request']

    const subjectToken = value('subject_token')
    const audience = value('audience')
    const subjectTokenType = value('subject_token_type')
    const requestedTokenType = value('requested_token_type')
    if (params.has('actor_token') || params.has('actor_token_type')) return MALFORMED
    if (subjectToken === undefined || audience === undefined) return MALFORMED
    if (subjectTokenType === undefined || !SUBJECT_TOKEN_TYPES.includes(subjectTokenType)) return MALFORMED
    if (requestedTokenType !== undefined && requestedTokenType !== ACCESS_TOKEN_TYPE) return MALFORMED
    return { subjectToken, audience }
}

function reject(ctx: RouteContext, status: number, error: OAuthErrorCode, code: LogCode, headers?: HeadersInit): Response {
    ctx.code = code
    return oauthError(status, error, code, headers)
}
