import type { ClaimMapping, Config, IdpAlgorithm, IdpBinding, IdpConfig, ProductConfig, WebhookSourceConfig } from './types'

// The message starts with the JSON path of the offending value, for example products.acme.idps[0].idp, and
// quotes only short configuration values, never the raw input
export class ConfigError extends Error {
    override name = 'ConfigError'

    constructor(path: string, reason: string) {
        super(path === '' ? reason : `${path}: ${reason}`)
    }
}

const ID = /^[a-z0-9][a-z0-9-]{0,62}$/
const REGION = /^[a-z][a-z0-9-]{0,31}$/
const SCHEME = /^([a-z][a-z0-9+.-]*):/i
// new URL() gives URLs of schemes other than http and https the origin "null", so those are checked by shape
const OTHER_ORIGIN = /^[a-z][a-z0-9+.-]*:\/\/[^/?#]+$/
// The URL parser strips these silently, so a raw string holding them is not the URL it parses to
const SPACE_OR_CONTROL = /[\x00-\x20\x7f]/
const PLAIN_KEY = /^[\w-]{1,64}$/
const MAX_QUOTED = 64

const ALGORITHMS: readonly IdpAlgorithm[] = ['RS256', 'RS384', 'RS512', 'PS256', 'ES256', 'ES384', 'EdDSA']
const CLAIM_KEYS = ['clientId', 'uid', 'email', 'emailVerified', 'phone', 'phoneVerified', 'name', 'picture']

export function parseConfig(json: string): Config {
    let document: unknown
    try {
        document = JSON.parse(json)
    } catch {
        // The SyntaxError message quotes the input
        throw new ConfigError('', 'invalid JSON')
    }
    return deepFreeze(parseDocument(new At(document, '')))
}

function parseDocument(at: At): Config {
    const doc = at.fields(['issuer', 'region', 'tokenTtlSeconds', 'idps', 'products', 'webhookSources'])
    const issuer = doc.required('issuer').issuer()
    const region = doc.optional('region')?.matching(REGION)
    const tokenTtlSeconds = doc.optional('tokenTtlSeconds')?.integer(60, 3600) ?? 900
    const idps = idRecord(doc.required('idps'), true, parseIdp)
    const bound: Bound[] = []
    const products = idRecord(doc.required('products'), true, (item, id) => parseProduct(item, id, idps, bound))
    requireClientBinding(bound)
    const sources = doc.optional('webhookSources')
    const webhookSources = sources
        ? idRecord(sources, false, (item, id) => parseSource(item, id, idps, products))
        : nullRecord<WebhookSourceConfig>()
    return { issuer, ...present('region', region), tokenTtlSeconds, idps, products, webhookSources }
}

function parseIdp(at: At, id: string): IdpConfig {
    const idp = at.fields(['issuer', 'jwksUri', 'algorithms', 'maxTokenAgeSeconds', 'clockToleranceSeconds', 'requiredClaims', 'claims'])
    return {
        id,
        issuer: idp.required('issuer').issuer(),
        jwksUri: idp.required('jwksUri').https(),
        algorithms: idp.optional('algorithms')?.items(true).map(algorithm) ?? ['RS256', 'ES256'],
        maxTokenAgeSeconds: idp.optional('maxTokenAgeSeconds')?.integer(30, 3600) ?? 900,
        clockToleranceSeconds: idp.optional('clockToleranceSeconds')?.integer(0, 300) ?? 60,
        requiredClaims: parseRequiredClaims(idp.optional('requiredClaims')),
        claims: parseClaims(idp.optional('claims')),
    }
}

function algorithm(at: At): IdpAlgorithm {
    const value = at.value
    return ALGORITHMS.find((known) => known === value) ?? at.fail(`must be one of ${ALGORITHMS.join(', ')}`)
}

function parseRequiredClaims(at: At | undefined): Record<string, string | number | boolean> {
    if (!at) return nullRecord()
    return record(at, true, (claim) => {
        const value = claim.value
        if (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') return value
        return claim.fail('must be a string, number or boolean')
    })
}

function parseClaims(at: At | undefined): ClaimMapping {
    const claims = at?.fields(CLAIM_KEYS)
    const name = (key: string, fallback: string) => claims?.optional(key)?.nonEmptyString() ?? fallback
    const flag = (key: string, fallback: string) => claims?.optional(key)?.nameOrTrue() ?? fallback
    return {
        clientId: name('clientId', 'aud'),
        ...present('uid', claims?.optional('uid')?.nonEmptyString()),
        email: name('email', 'email'),
        emailVerified: flag('emailVerified', 'email_verified'),
        phone: name('phone', 'phone_number'),
        phoneVerified: flag('phoneVerified', 'phone_number_verified'),
        name: name('name', 'name'),
        picture: name('picture', 'picture'),
    }
}

interface Bound {
    at: At
    idpAt: At
    issuer: string
    binding: IdpBinding
}

function parseProduct(at: At, id: string, idps: Record<string, IdpConfig>, allBound: Bound[]): ProductConfig {
    const product = at.fields(['idps', 'allowedOrigins', 'events'])
    const bound = product.required('idps').items(true).map((item) => parseBinding(item, idps))
    // The token's iss alone selects the binding
    bound.forEach(({ idpAt, issuer }, index) => {
        const first = bound.findIndex((other) => other.issuer === issuer)
        if (first !== index) idpAt.fail(`issuer ${quote(issuer)} is already bound by idps[${first}]`)
    })
    allBound.push(...bound)
    return {
        id,
        idps: bound.map(({ binding }) => binding),
        allowedOrigins: product.optional('allowedOrigins')?.items(false).map(origin) ?? [],
        ...present('events', parseEvents(product.optional('events'))),
    }
}

// Products sharing an issuer, as on one Casdoor instance, accept each other's tokens unless every binding
// names its clients. Each product binds an issuer at most once, so the count per issuer is a count of products.
function requireClientBinding(bound: Bound[]): void {
    const products = new Map<string, number>()
    for (const { issuer } of bound) products.set(issuer, (products.get(issuer) ?? 0) + 1)
    for (const { at, issuer, binding } of bound) {
        if ((products.get(issuer) ?? 0) > 1 && !binding.clientIds && !binding.authorizedParties) {
            at.fail(`must list clientIds or authorizedParties, because issuer ${quote(issuer)} is bound by several products`)
        }
    }
}

function parseEvents(at: At | undefined): ProductConfig['events'] {
    return at && { url: at.fields(['url']).required('url').https() }
}

function parseBinding(at: At, idps: Record<string, IdpConfig>): Bound {
    const fields = at.fields(['idp', 'clientIds', 'authorizedParties'])
    const idpAt = fields.required('idp')
    const idp = reference(idpAt, idps, 'idp')
    const binding = {
        idp: idp.id,
        ...present('clientIds', fields.optional('clientIds')?.items(true).map((item) => item.nonEmptyString())),
        ...present('authorizedParties', fields.optional('authorizedParties')?.items(true).map((item) => item.nonEmptyString())),
    }
    return { at, idpAt, issuer: idp.issuer, binding }
}

function origin(at: At): string {
    const value = at.value
    if (typeof value === 'string') {
        const scheme = SCHEME.exec(value)?.[1]?.toLowerCase()
        if (scheme === 'http' || scheme === 'https' ? parseUrl(value)?.origin === value : OTHER_ORIGIN.test(value)) return value
    }
    return at.fail('must be an origin')
}

function parseSource(at: At, id: string, idps: Record<string, IdpConfig>, products: Record<string, ProductConfig>): WebhookSourceConfig {
    const source = at.fields(['type', 'idp', 'organization', 'uidField', 'products'])
    const typeAt = source.required('type')
    const type = typeAt.value
    if (type !== 'clerk' && type !== 'casdoor') return typeAt.fail('must be "clerk" or "casdoor"')
    const organization =
        type === 'casdoor' ? source.required('organization', 'required for casdoor sources').nonEmptyString() : undefined
    if (type === 'clerk') source.optional('organization')?.fail('not allowed for clerk sources')
    const idp = reference(source.required('idp'), idps, 'idp')
    const uid = present('uidField', parseUidField(source, type, idp))
    // Event sub values come from this IdP, so they match only the token sub values of products that bind it
    const targets = source.required('products').items(true).map((item) => {
        const product = reference(item, products, 'product')
        if (!product.events) item.fail(`product ${quote(product.id)} has no events`)
        if (!product.idps.some((binding) => binding.idp === idp.id)) item.fail(`product ${quote(product.id)} does not bind idp ${quote(idp.id)}`)
        return product.id
    })
    if (organization === undefined) return { id, type: 'clerk', idp: idp.id, ...uid, products: targets }
    return { id, type: 'casdoor', idp: idp.id, organization, ...uid, products: targets }
}

// Webhooks derive the same user id as tokens only when they read the override the IdP's uid claim carries
function parseUidField(source: Fields, type: WebhookSourceConfig['type'], idp: IdpConfig): string | undefined {
    if (idp.claims.uid === undefined) {
        source.optional('uidField')?.fail(`not allowed, because idp ${quote(idp.id)} maps no uid claim`)
        return undefined
    }
    const at = source.required('uidField', `required, because idp ${quote(idp.id)} maps a uid claim`)
    const uidField = at.nonEmptyString()
    // Clerk's override lives in external_id, the one backend-only field in its tokens and in every user event
    if (type === 'clerk' && uidField !== 'external_id') at.fail('must be "external_id" for clerk sources')
    return uidField
}

function reference<T>(at: At, record: Record<string, T>, kind: string): T {
    const key = at.string()
    return record[key] ?? at.fail(`unknown ${kind} ${quote(key)}`)
}

// A value in the document with its JSON path, so that every check can say where it failed
class At {
    readonly value: unknown
    readonly path: string

    constructor(value: unknown, path: string) {
        this.value = value
        this.path = path
    }

    fail(reason: string): never {
        throw new ConfigError(this.path, reason)
    }

    entries(): [string, At][] {
        const value = this.value
        if (typeof value !== 'object' || value === null || Array.isArray(value)) return this.fail('must be an object')
        return Object.entries(value).map(([key, item]) => [key, new At(item, childPath(this.path, key))])
    }

    // An object with no keys but the given ones
    fields(keys: readonly string[]): Fields {
        const entries = this.entries()
        for (const [key, at] of entries) if (!keys.includes(key)) at.fail('unknown key')
        return new Fields(this.path, new Map(entries))
    }

    items(nonEmpty: boolean): At[] {
        const value = this.value
        if (!Array.isArray(value) || (nonEmpty && value.length === 0)) return this.fail(nonEmpty ? 'must be a non-empty array' : 'must be an array')
        return value.map((item, index) => new At(item, `${this.path}[${index}]`))
    }

    string(): string {
        return typeof this.value === 'string' ? this.value : this.fail('must be a string')
    }

    nonEmptyString(): string {
        return typeof this.value === 'string' && this.value !== '' ? this.value : this.fail('must be a non-empty string')
    }

    // A claim name, or literal true to trust the IdP's verification policy
    nameOrTrue(): string | true {
        const value = this.value
        return value === true || (typeof value === 'string' && value !== '') ? value : this.fail('must be a non-empty string or true')
    }

    matching(pattern: RegExp): string {
        return typeof this.value === 'string' && pattern.test(this.value) ? this.value : this.fail(`must match ${pattern.source}`)
    }

    integer(min: number, max: number): number {
        const value = this.value
        if (typeof value === 'number' && Number.isInteger(value) && value >= min && value <= max) return value
        return this.fail(`must be an integer from ${min} to ${max}`)
    }

    https(): string {
        const value = this.value
        if (typeof value === 'string' && !SPACE_OR_CONTROL.test(value) && parseUrl(value)?.protocol === 'https:') return value
        return this.fail('must be an https URL')
    }

    // Compared exactly with a token's iss. new URL() adds a trailing slash itself and reports an empty search
    // for a bare "?", so the raw string is checked, not href.
    issuer(): string {
        const value = this.https()
        if (/[/?#]$/.test(value)) this.fail('must not end with "/", "?" or "#"')
        const url = new URL(value)
        if (url.search !== '' || url.hash !== '') this.fail('must not have a query or fragment')
        return value
    }
}

class Fields {
    readonly path: string
    readonly values: Map<string, At>

    constructor(path: string, values: Map<string, At>) {
        this.path = path
        this.values = values
    }

    optional(key: string): At | undefined {
        return this.values.get(key)
    }

    required(key: string, reason = 'required'): At {
        return this.values.get(key) ?? new At(undefined, childPath(this.path, key)).fail(reason)
    }
}

// Consumers index records with untrusted keys, such as a token's audience, so no record has a prototype
function nullRecord<T>(): Record<string, T> {
    return Object.create(null)
}

function record<T>(at: At, nonEmpty: boolean, parse: (at: At, key: string) => T): Record<string, T> {
    const entries = at.entries()
    if (nonEmpty && entries.length === 0) at.fail('must not be empty')
    const result = nullRecord<T>()
    for (const [key, item] of entries) result[key] = parse(item, key)
    return result
}

function idRecord<T>(at: At, nonEmpty: boolean, parse: (at: At, id: string) => T): Record<string, T> {
    return record(at, nonEmpty, (item, id) => (ID.test(id) ? parse(item, id) : item.fail(`id must match ${ID.source}`)))
}

// With exactOptionalPropertyTypes an optional property is left out rather than set to undefined
function present<K extends string, V>(key: K, value: V | undefined): Partial<Record<K, V>> {
    return value === undefined ? {} : ({ [key]: value } as Record<K, V>)
}

// try rather than URL.parse, which not every edge runtime provides
function parseUrl(value: string): URL | undefined {
    try {
        return new URL(value)
    } catch {
        return undefined
    }
}

function childPath(path: string, key: string): string {
    if (!PLAIN_KEY.test(key)) return `${path}[${quote(key)}]`
    return path === '' ? key : `${path}.${key}`
}

function quote(value: string): string {
    return JSON.stringify(value.length > MAX_QUOTED ? `${value.slice(0, MAX_QUOTED)}…` : value)
}

function deepFreeze<T>(value: T): T {
    if (typeof value === 'object' && value !== null) {
        for (const item of Object.values(value)) deepFreeze(item)
        Object.freeze(value)
    }
    return value
}
