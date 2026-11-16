// The configuration types describe what the parser returns, with every default applied, so consumers never
// re-apply defaults. Records are built with a null prototype: indexing any key is safe.

export type IdpAlgorithm = 'RS256' | 'RS384' | 'RS512' | 'PS256' | 'ES256' | 'ES384' | 'EdDSA'

export interface Config {
    issuer: string
    region?: string
    tokenTtlSeconds: number
    idps: Record<string, IdpConfig>
    products: Record<string, ProductConfig>
    webhookSources: Record<string, WebhookSourceConfig>
}

export interface IdpConfig {
    id: string
    issuer: string
    jwksUri: string
    algorithms: IdpAlgorithm[]
    maxTokenAgeSeconds: number
    clockToleranceSeconds: number
    requiredClaims: Record<string, string | number | boolean>
    claims: ClaimMapping
}

// Claim names in the IdP's tokens; `true` for a verified flag trusts the IdP's verification policy
export interface ClaimMapping {
    clientId: string
    uid?: string
    email: string
    emailVerified: string | true
    phone: string
    phoneVerified: string | true
    name: string
    picture: string
}

export interface ProductConfig {
    id: string
    idps: IdpBinding[]
    allowedOrigins: string[]
    events?: { url: string }
}

export interface IdpBinding {
    idp: string
    clientIds?: string[]
    authorizedParties?: string[]
}

// A union, so the organization can only be read after narrowing on type: no source can pass an organization
// check by lacking one
export type WebhookSourceConfig = ClerkSourceConfig | CasdoorSourceConfig

interface SourceConfigFields {
    id: string
    idp: string
    uidField?: string
    products: string[]
}

export interface ClerkSourceConfig extends SourceConfigFields {
    type: 'clerk'
}

export interface CasdoorSourceConfig extends SourceConfigFields {
    type: 'casdoor'
    organization: string
}

export interface Deps {
    fetch(input: Request | string, init?: RequestInit): Promise<Response>
    now(): number // ms
    randomUUID(): string
    log(line: LogLine): void
}

// Counts and identifiers only: never tokens, emails, phone numbers or payload content
export interface LogLine {
    route: 'token' | 'jwks' | 'health' | 'webhook' | 'other'
    status: number
    ms: number
    outcome: 'ok' | 'rejected' | 'error'
    code?: LogCode
    product?: string
    idp?: string
    source?: string
    delivered?: number
    failed?: number
}

export type LogCode =
    | 'bad_request'
    | 'too_large'
    | 'unsupported_grant'
    | 'unknown_product'
    | 'malformed_token'
    | 'untrusted_issuer'
    | 'bad_algorithm'
    | 'bad_signature'
    | 'unknown_key'
    | 'expired'
    | 'too_old'
    | 'not_yet_valid'
    | 'missing_claim'
    | 'claim_mismatch'
    | 'client_mismatch'
    | 'bad_uid'
    | 'jwks_unavailable'
    | 'unknown_source'
    | 'bad_webhook_auth'
    | 'bad_payload'
    | 'ignored'
    | 'delivery_failed'
    | 'runtime_unavailable'
    | 'internal_error'
    | 'client_closed'

export type OAuthErrorCode =
    | 'invalid_request'
    | 'invalid_target'
    | 'invalid_scope'
    | 'unsupported_grant_type'
    | 'temporarily_unavailable'
    | 'server_error'

// Filled in by the router and the route handlers as facts become known; dispatch turns it into the request's LogLine
export interface RouteContext {
    product?: string
    idp?: string
    source?: string
    code?: LogCode
    delivered?: number
    failed?: number
}

export type RouteHandler = (request: Request, runtime: Runtime, deps: Deps, ctx: RouteContext) => Promise<Response>

export interface Runtime {
    config: Config
    keys: SigningKeys
    // Every configured source has a secret; loading fails otherwise
    webhookSecret(sourceId: string): string
}

// `reason` is safe to log: it never contains secret material
export interface RuntimeFailure {
    reason: string
}

export interface SigningKeys {
    kid: string
    privateKey: CryptoKey
    jwks: { keys: PublicJwk[] }
}

export interface PublicJwk {
    kty: 'EC'
    crv: 'P-256'
    x: string
    y: string
    kid: string
    alg: 'ES256'
    use: 'sig'
}

// Values as read from a token or payload, still unchecked; the verified flags are already resolved
export interface RawProfile {
    email?: unknown
    emailVerified: boolean
    phone?: unknown
    phoneVerified: boolean
    name?: unknown
    picture?: unknown
}

export interface Profile {
    email?: string
    phoneNumber?: string
    name?: string
    picture?: string
}

export type EventType = 'user-created' | 'user-updated' | 'user-deleted'

export interface LifecycleEvent {
    idpEventId: string
    type: EventType
    subject: string
    uid?: unknown
    profile: Profile
}
