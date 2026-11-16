import type { ClaimMapping, Config, IdpAlgorithm, IdpBinding, IdpConfig, ProductConfig, WebhookSourceConfig } from './types'

// Prefixed with the JSON path of the offending value; quotes only short configuration values, never the raw input
export class ConfigError extends Error {
    override name = 'ConfigError'

    constructor(path: string, reason: string) {
        super(path === '' ? reason : `${path}: ${reason}`)
    }
}

const ID = /^[a-z0-9][a-z0-9-]{0,62}$/
const REGION = /^[a-z][a-z0-9-]{0,31}$/
const SCHEME = /^([a-z][a-z0-9+.-]*):/i
// new URL() gives most other schemes, such as capacitor:, the origin "null", so those are checked by shape
const OTHER_ORIGIN = /^[a-z][a-z0-9+.-]*:\/\/[^/?#]+$/
// The URL parser strips or escapes these silently, so a raw string holding them is not the URL it parses to
const SPACE_OR_CONTROL = /[\x00-\x20\x7f]/
const PLAIN_KEY = /^[\w-]{1,64}$/
const MAX_QUOTED = 64

const ALGORITHMS: readonly IdpAlgorithm[] = ['RS256', 'RS384', 'RS512', 'PS256', 'ES256', 'ES384', 'EdDSA']
const CLAIM_KEYS = ['clientId', 'uid', 'email', 'emailVerified', 'phone', 'phoneVerified', 'name', 'picture']

type Idps = Record<string, IdpConfig>
type Products = Record<string, ProductConfig>

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
    const issuers = new Map<string, string>()
    const idps = idRecord(doc.required('idps'), true, (item, id) => parseIdp(item, id, issuers))
    const bound: Bound[] = []
    const products = idRecord(doc.required('products'), true, (item, id) => parseProduct(item, id, idps, bound))
    requireClientBinding(bound)
    const sources = doc.optional('webhookSources')
    const webhookSources = sources
        ? idRecord(sources, false, (item, id) => parseSource(item, id, idps, products))
        : nullRecord<WebhookSourceConfig>()
    return { issuer, ...present('region', region), tokenTtlSeconds, idps, products, webhookSources }
}

function parseIdp(at: At, id: string, issuers: Map<string, string>): IdpConfig {
    const idp = at.fields(['issuer', 'jwksUri', 'algorithms', 'maxTokenAgeSeconds', 'clockToleranceSeconds', 'requiredClaims', 'claims'])
    return {
        id,
        issuer: distinctIssuer(idp.required('issuer'), id, issuers),
        jwksUri: idp.required('jwksUri').https(),
        algorithms: idp.optional('algorithms')?.items(true).map(algorithm) ?? ['RS256', 'ES256'],
        maxTokenAgeSeconds: idp.optional('maxTokenAgeSeconds')?.integer(30, 3600) ?? 900,
        clockToleranceSeconds: idp.optional('clockToleranceSeconds')?.integer(0, 300) ?? 60,
        requiredClaims: parseRequiredClaims(idp.optional('requiredClaims')),
        claims: parseClaims(idp.optional('claims')),
    }
}

// One issuer has one claim mapping, so each person has one user id
function distinctIssuer(at: At, id: string, issuers: Map<string, string>): string {
    const issuer = at.issuer()
    const first = issuers.get(issuer)
    if (first !== undefined) at.fail(`${quote(issuer)} is already the issuer of idp ${quote(first)}`)
    issuers.set(issuer, id)
    return issuer
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
    product: string
    binding: IdpBinding
    // The clientIds and authorizedParties entries
    clients: At[]
}

function parseProduct(at: At, id: string, idps: Idps, allBound: Bound[]): ProductConfig {
    const product = at.fields(['idps', 'allowedOrigins', 'events'])
    const bound = product.required('idps').items(true).map((item) => parseBinding(item, id, idps))
    // IdP issuers are distinct, so the token's iss selects one binding unless a record is bound twice
    bound.forEach(({ idpAt, binding }, index) => {
        const first = bound.findIndex((other) => other.binding.idp === binding.idp)
        if (first !== index) idpAt.fail(`idp ${quote(binding.idp)} is already bound at idps[${first}]`)
    })
    allBound.push(...bound)
    return {
        id,
        idps: bound.map(({ binding }) => binding),
        allowedOrigins: product.optional('allowedOrigins')?.items(false).map(origin) ?? [],
        ...present('events', parseEvents(product.optional('events'))),
    }
}

// Products sharing an IdP, as on one Casdoor instance, accept each other's tokens unless every binding names
// clients of its own. Each product binds an IdP at most once, so the count per IdP is a count of products.
function requireClientBinding(bound: Bound[]): void {
    const products = new Map<string, number>()
    for (const { binding } of bound) products.set(binding.idp, (products.get(binding.idp) ?? 0) + 1)
    // Per IdP, the product that first listed each value. A Casdoor token carries its client id as both aud and
    // azp, so a value names one client whichever of the two lists holds it.
    const owners = new Map<string, Map<string, string>>()
    for (const { at, product, binding, clients } of bound) {
        if ((products.get(binding.idp) ?? 0) < 2) continue
        if (clients.length === 0) {
            at.fail(`must list clientIds or authorizedParties, because idp ${quote(binding.idp)} is bound by several products`)
        }
        const owner = owners.get(binding.idp) ?? new Map<string, string>()
        owners.set(binding.idp, owner)
        for (const client of clients) {
            const value = client.string()
            const first = owner.get(value) ?? product
            if (first !== product) client.fail(`${quote(value)} is also a client of product ${quote(first)}`)
            owner.set(value, first)
        }
    }
}

function parseEvents(at: At | undefined): ProductConfig['events'] {
    return at && { url: at.fields(['url']).required('url').https() }
}

function parseBinding(at: At, product: string, idps: Idps): Bound {
    const fields = at.fields(['idp', 'clientIds', 'authorizedParties'])
    const idpAt = fields.required('idp')
    const idp = reference(idpAt, idps, 'idp')
    const clientIds = fields.optional('clientIds')?.items(true)
    const authorizedParties = fields.optional('authorizedParties')?.items(true)
    const binding = {
        idp: idp.id,
        ...present('clientIds', clientIds?.map((item) => item.nonEmptyString())),
        ...present('authorizedParties', authorizedParties?.map((item) => item.nonEmptyString())),
    }
    return { at, idpAt, product, binding, clients: [...(clientIds ?? []), ...(authorizedParties ?? [])] }
}

function origin(at: At): string {
    const value = at.value
    if (typeof value === 'string' && !SPACE_OR_CONTROL.test(value) && isOrigin(value)) return value
    return at.fail('must be an origin')
}

function isOrigin(value: string): boolean {
    const scheme = SCHEME.exec(value)?.[1]?.toLowerCase()
    if (scheme === 'http' || scheme === 'https') return parseUrl(value)?.origin === value
    return OTHER_ORIGIN.test(value)
}

function parseSource(at: At, id: string, idps: Idps, products: Products): WebhookSourceConfig {
    const source = at.fields(['type', 'idp', 'organization', 'uidField', 'products'])
    const typeAt = source.required('type')
    const type = typeAt.value
    if (type === 'clerk') {
        source.optional('organization')?.fail('not allowed for clerk sources')
        return { id, type, ...parseSourceFields(source, type, idps, products) }
    }
    if (type === 'casdoor') {
        const organization = source.required('organization', 'required for casdoor sources').nonEmptyString()
        return { id, type, organization, ...parseSourceFields(source, type, idps, products) }
    }
    return typeAt.fail('must be "clerk" or "casdoor"')
}

function parseSourceFields(
    source: Fields,
    type: WebhookSourceConfig['type'],
    idps: Idps,
    products: Products,
): Pick<WebhookSourceConfig, 'idp' | 'uidField' | 'products'> {
    const idp = reference(source.required('idp'), idps, 'idp')
    const uidField = parseUidField(source, type, idp)
    // Event sub values come from this IdP, so they match only the token sub values of products that bind it.
    // A repeat would deliver each event to the product twice, concurrently.
    const targets: string[] = []
    for (const item of source.required('products').items(true)) {
        const product = reference(item, products, 'product')
        if (!product.events) item.fail(`product ${quote(product.id)} has no events`)
        if (!product.idps.some((binding) => binding.idp === idp.id)) item.fail(`product ${quote(product.id)} does not bind idp ${quote(idp.id)}`)
        const first = targets.indexOf(product.id)
        if (first !== -1) item.fail(`product ${quote(product.id)} is already listed at products[${first}]`)
        targets.push(product.id)
    }
    return { idp: idp.id, ...present('uidField', uidField), products: targets }
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

    // Unknown keys fail, so a misspelled key stops the deploy rather than being ignored
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
        return this.httpsUrl().raw
    }

    // Consumers use the raw string as written, so it is returned with its parse
    httpsUrl(): { raw: string; url: URL } {
        const raw = this.value
        const url = typeof raw === 'string' && !SPACE_OR_CONTROL.test(raw) ? parseUrl(raw) : undefined
        if (typeof raw !== 'string' || url?.protocol !== 'https:') return this.fail('must be an https URL')
        // new Request() refuses URLs with credentials, and the configuration is not secret
        if (url.username !== '' || url.password !== '') this.fail('must not have a username or password')
        return { raw, url }
    }

    // Compared exactly with a token's iss. new URL() adds a trailing slash itself and reports an empty search
    // for a bare "?", so the raw string is checked, not href.
    issuer(): string {
        const { raw, url } = this.httpsUrl()
        if (/[/?#]$/.test(raw)) this.fail('must not end with "/", "?" or "#"')
        if (url.search !== '' || url.hash !== '') this.fail('must not have a query or fragment')
        return raw
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
