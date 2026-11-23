import { describe, expect, it } from 'vitest'
import { ConfigError, parseConfig } from '../src/config'
import type { Config } from '../src/types'
import { casdoorConfig, casdoorConfigJson, clerkConfig, clerkConfigJson } from './helpers/config'

// Cases edit the documents into any shape, invalid ones included
type Doc = Record<string, any>

const BASES = { clerk: clerkConfig, casdoor: casdoorConfig, minimal }

type Case = [name: string, base: keyof typeof BASES, edit: (doc: Doc) => void, message: string]
type Accepted = [name: string, base: keyof typeof BASES, edit: (doc: Doc) => void]

function minimal(): Doc {
    return {
        issuer: 'https://id.example',
        idps: { idp: { issuer: 'https://idp.example', jwksUri: 'https://idp.example/jwks' } },
        products: { app: { idps: [{ idp: 'idp' }] } },
    }
}

function edited(base: keyof typeof BASES, edit: (doc: Doc) => void): string {
    const doc: Doc = BASES[base]()
    edit(doc)
    return JSON.stringify(doc)
}

function rejection(json: string): string {
    let error: unknown
    try {
        parseConfig(json)
    } catch (caught) {
        error = caught
    }
    expect(error).toBeInstanceOf(ConfigError)
    return (error as ConfigError).message
}

// Assigning __proto__ would set the prototype, which JSON.stringify drops, instead of adding the key
function setOwn(object: Doc, key: string, value: unknown) {
    Object.defineProperty(object, key, { value, enumerable: true, configurable: true, writable: true })
}

function objectsIn(value: unknown): object[] {
    if (typeof value !== 'object' || value === null) return []
    return [value, ...Object.values(value).flatMap(objectsIn)]
}

const ID_RULE = 'id must match ^[a-z0-9][a-z0-9-]{0,62}$'
const ALGORITHM_RULE = 'must be one of RS256, RS384, RS512, PS256, ES256, ES384, EdDSA'

const CLERK: Config = {
    issuer: 'https://id.acme.example',
    region: 'us',
    tokenTtlSeconds: 900,
    idps: {
        'clerk-acme': {
            id: 'clerk-acme',
            issuer: 'https://clerk.acme.example',
            jwksUri: 'https://clerk.acme.example/.well-known/jwks.json',
            algorithms: ['RS256'],
            maxTokenAgeSeconds: 900,
            clockToleranceSeconds: 60,
            requiredClaims: {},
            claims: {
                clientId: 'aud',
                uid: 'uid',
                email: 'email',
                emailVerified: true,
                phone: 'phone_number',
                phoneVerified: 'phone_number_verified',
                name: 'name',
                picture: 'picture',
            },
        },
    },
    products: {
        acme: {
            id: 'acme',
            idps: [{ idp: 'clerk-acme' }],
            allowedOrigins: ['https://acme.example'],
            events: { url: 'https://api.acme.example/identity/events' },
        },
    },
    webhookSources: {
        'clerk-acme': { id: 'clerk-acme', type: 'clerk', idp: 'clerk-acme', uidField: 'external_id', products: ['acme'] },
    },
}

const CASDOOR: Config = {
    issuer: 'https://id.cn.acme.example',
    region: 'cn',
    tokenTtlSeconds: 900,
    idps: {
        casdoor: {
            id: 'casdoor',
            issuer: 'https://casdoor.example',
            jwksUri: 'https://casdoor.example/.well-known/jwks',
            algorithms: ['RS256'],
            maxTokenAgeSeconds: 900,
            clockToleranceSeconds: 60,
            requiredClaims: { tokenType: 'access-token' },
            claims: {
                clientId: 'aud',
                uid: 'uid',
                email: 'email',
                emailVerified: 'emailVerified',
                phone: 'phone_number',
                phoneVerified: 'phone_number_verified',
                name: 'displayName',
                picture: 'avatar',
            },
        },
    },
    products: {
        acme: {
            id: 'acme',
            idps: [{ idp: 'casdoor', clientIds: ['acme-web-client', 'acme-app-client', 'acme-mini-program-client'] }],
            allowedOrigins: ['https://cn.acme.example'],
            events: { url: 'https://api.cn.acme.example/identity/events' },
        },
        globex: { id: 'globex', idps: [{ idp: 'casdoor', clientIds: ['globex-web-client'] }], allowedOrigins: [] },
    },
    webhookSources: {
        'casdoor-acme': { id: 'casdoor-acme', type: 'casdoor', idp: 'casdoor', organization: 'acme', uidField: 'uid', products: ['acme'] },
    },
}

describe('parseConfig documents', () => {
    it('parses the Clerk deployment, resolving the claim mapping', () => {
        expect(parseConfig(clerkConfigJson)).toEqual(CLERK)
    })

    it('parses the Casdoor deployment, resolving the claim mapping', () => {
        expect(parseConfig(casdoorConfigJson)).toEqual(CASDOOR)
    })

    it('applies every default, leaving absent optional fields out', () => {
        const config = parseConfig(JSON.stringify(minimal()))
        expect(config).toEqual({
            issuer: 'https://id.example',
            tokenTtlSeconds: 900,
            idps: {
                idp: {
                    id: 'idp',
                    issuer: 'https://idp.example',
                    jwksUri: 'https://idp.example/jwks',
                    algorithms: ['RS256', 'ES256'],
                    maxTokenAgeSeconds: 900,
                    clockToleranceSeconds: 60,
                    requiredClaims: {},
                    claims: {
                        clientId: 'aud',
                        email: 'email',
                        emailVerified: 'email_verified',
                        phone: 'phone_number',
                        phoneVerified: 'phone_number_verified',
                        name: 'name',
                        picture: 'picture',
                    },
                },
            },
            products: { app: { id: 'app', idps: [{ idp: 'idp' }], allowedOrigins: [] } },
            webhookSources: {},
        })
        expect(Object.keys(config)).toEqual(['issuer', 'tokenTtlSeconds', 'idps', 'products', 'webhookSources'])
        expect(Object.keys(config.idps.idp!.claims)).not.toContain('uid')
        expect(Object.keys(config.idps.idp!.claims)).not.toContain('phoneRegion')
        expect(Object.keys(config.idps.idp!.claims)).not.toContain('updatedAt')
        expect(Object.keys(config.products.app!)).toEqual(['id', 'idps', 'allowedOrigins'])
        expect(Object.keys(config.products.app!.idps[0]!)).toEqual(['idp'])
    })

    it('leaves a source without uidField out of the result too', () => {
        const json = edited('clerk', (doc) => {
            delete doc.idps['clerk-acme'].claims.uid
            delete doc.webhookSources['clerk-acme'].uidField
        })
        expect(Object.keys(parseConfig(json).webhookSources['clerk-acme']!)).toEqual(['id', 'type', 'idp', 'products'])
    })

    it.each<Accepted>([
        ['tokenTtlSeconds 60', 'clerk', (doc) => (doc.tokenTtlSeconds = 60)],
        ['tokenTtlSeconds 3600', 'clerk', (doc) => (doc.tokenTtlSeconds = 3600)],
        ['maxTokenAgeSeconds 30', 'clerk', (doc) => (doc.idps['clerk-acme'].maxTokenAgeSeconds = 30)],
        ['maxTokenAgeSeconds 3600', 'clerk', (doc) => (doc.idps['clerk-acme'].maxTokenAgeSeconds = 3600)],
        ['clockToleranceSeconds 0', 'clerk', (doc) => (doc.idps['clerk-acme'].clockToleranceSeconds = 0)],
        ['clockToleranceSeconds 300', 'clerk', (doc) => (doc.idps['clerk-acme'].clockToleranceSeconds = 300)],
        ['an issuer with a path', 'casdoor', (doc) => (doc.idps.casdoor.issuer = 'https://casdoor.example/orgs/acme')],
        ['an issuer with a port', 'clerk', (doc) => (doc.issuer = 'https://id.acme.example:8443')],
        ['a jwksUri with a query', 'clerk', (doc) => (doc.idps['clerk-acme'].jwksUri = 'https://clerk.acme.example/jwks?v=2')],
        ['every algorithm', 'clerk', (doc) => (doc.idps['clerk-acme'].algorithms = ['RS256', 'RS384', 'RS512', 'PS256', 'ES256', 'ES384', 'EdDSA'])],
        [
            'number and boolean required claims',
            'casdoor',
            (doc) => (doc.idps.casdoor.requiredClaims = { ver: 2, admin: false, tokenType: 'access-token' }),
        ],
        ['literal true for both verified flags', 'clerk', (doc) => (doc.idps['clerk-acme'].claims.phoneVerified = true)],
        ['a phone region claim', 'casdoor', (doc) => Object.assign(doc.idps.casdoor.claims, { phone: 'phone', phoneRegion: 'countryCode', phoneVerified: true })],
        ['an updatedAt claim', 'clerk', (doc) => (doc.idps['clerk-acme'].claims.updatedAt = 'updated_at')],
        ['iat as the updatedAt claim', 'casdoor', (doc) => (doc.idps.casdoor.claims.updatedAt = 'iat')],
        [
            'updatedAt on an IdP that several single-IdP products bind',
            'casdoor',
            (doc) => (doc.idps.casdoor.claims.updatedAt = 'iat'),
        ],
        [
            'a product bound to several IdPs, none mapping updatedAt',
            'clerk',
            (doc) => {
                doc.idps.other = { issuer: 'https://other.example', jwksUri: 'https://other.example/jwks' }
                doc.products.acme.idps.push({ idp: 'other' })
            },
        ],
        ['an id of 63 characters', 'minimal', (doc) => (doc.products = { ['a'.repeat(63)]: { idps: [{ idp: 'idp' }] } })],
        ['a one-digit id', 'minimal', (doc) => (doc.products = { '0': { idps: [{ idp: 'idp' }] } })],
        ['capacitor://localhost', 'clerk', (doc) => (doc.products.acme.allowedOrigins = ['capacitor://localhost'])],
        ['ionic://localhost', 'clerk', (doc) => (doc.products.acme.allowedOrigins = ['ionic://localhost'])],
        ['http://localhost:5173', 'clerk', (doc) => (doc.products.acme.allowedOrigins = ['http://localhost:5173'])],
        ['an https origin with a port', 'clerk', (doc) => (doc.products.acme.allowedOrigins = ['https://acme.example:8443'])],
        ['empty allowedOrigins', 'clerk', (doc) => (doc.products.acme.allowedOrigins = [])],
        ['empty webhookSources', 'clerk', (doc) => (doc.webhookSources = {})],
    ])('accepts %s', (_name, base, edit) => {
        expect(() => parseConfig(edited(base, edit))).not.toThrow()
    })

    it('keeps the values it accepts', () => {
        const config = parseConfig(
            edited('casdoor', (doc) => {
                doc.idps.casdoor.requiredClaims = { ver: 2, admin: false }
                doc.idps.casdoor.claims.phoneVerified = true
                doc.idps.casdoor.claims.phoneRegion = 'countryCode'
                doc.idps.casdoor.claims.updatedAt = 'iat'
                doc.products.acme.allowedOrigins = ['capacitor://localhost', 'http://localhost:5173']
            }),
        )
        expect(config.idps.casdoor!.requiredClaims).toEqual({ ver: 2, admin: false })
        expect(config.idps.casdoor!.claims.phoneVerified).toBe(true)
        expect(config.idps.casdoor!.claims.phoneRegion).toBe('countryCode')
        expect(config.idps.casdoor!.claims.updatedAt).toBe('iat')
        expect(config.products.acme!.allowedOrigins).toEqual(['capacitor://localhost', 'http://localhost:5173'])
    })
})

describe('parseConfig records and freezing', () => {
    it('builds every record without a prototype, so any key indexes safely', () => {
        const config = parseConfig(casdoorConfigJson)
        const defaulted = parseConfig(JSON.stringify(minimal()))
        const records = [
            config.idps,
            config.products,
            config.webhookSources,
            config.idps.casdoor!.requiredClaims,
            defaulted.webhookSources,
            defaulted.idps.idp!.requiredClaims,
        ]
        for (const record of records) expect(Object.getPrototypeOf(record)).toBeNull()
        expect(config.products.constructor).toBeUndefined()
        expect(config.idps['toString']).toBeUndefined()
        expect(config.webhookSources['__proto__']).toBeUndefined()
        expect(config.idps.casdoor!.requiredClaims['hasOwnProperty']).toBeUndefined()
    })

    it('returns a deeply frozen result', () => {
        const config = parseConfig(casdoorConfigJson)
        const objects = objectsIn(config)
        expect(objects.length).toBeGreaterThan(20)
        for (const object of objects) expect(Object.isFrozen(object)).toBe(true)
        expect(() => config.products.acme!.allowedOrigins.push('https://evil.example')).toThrow(TypeError)
        expect(() => {
            config.idps.casdoor!.claims.uid = 'sub'
        }).toThrow(TypeError)
    })

    it('freezes the defaults too', () => {
        const config = parseConfig(JSON.stringify(minimal()))
        for (const object of objectsIn(config)) expect(Object.isFrozen(object)).toBe(true)
    })

    it('gives each parse its own result', () => {
        expect(parseConfig(clerkConfigJson)).not.toBe(parseConfig(clerkConfigJson))
        expect(parseConfig(clerkConfigJson).idps['clerk-acme']).not.toBe(parseConfig(clerkConfigJson).idps['clerk-acme'])
    })
})

describe('parseConfig errors', () => {
    it('throws a ConfigError whose message starts with the path', () => {
        let error: unknown
        try {
            parseConfig(edited('clerk', (doc) => (doc.idps['clerk-acme'].jwksUri = 'http://clerk.acme.example/jwks')))
        } catch (caught) {
            error = caught
        }
        expect(error).toBeInstanceOf(ConfigError)
        expect(error).toBeInstanceOf(Error)
        expect(String(error)).toBe('ConfigError: idps.clerk-acme.jwksUri: must be an https URL')
    })

    it.each(['', '{', '{"issuer": "https://id.example",}', 'undefined', "{'issuer': 'https://id.example'}", '{"issuer": "secret-looking"'])(
        'reports %j as invalid JSON without quoting it',
        (json) => {
            expect(rejection(json)).toBe('invalid JSON')
        },
    )

    it.each(['[]', 'null', '"config"', '1', 'true'])('rejects %s as the document', (json) => {
        expect(rejection(json)).toBe('must be an object')
    })
})

describe('parseConfig unknown keys', () => {
    it.each<Case>([
        ['an input id at the top level', 'clerk', (doc) => (doc.id = 'bridge'), 'id: unknown key'],
        ['a misspelled top-level key', 'clerk', (doc) => (doc.tokenTTLSeconds = 900), 'tokenTTLSeconds: unknown key'],
        ['an input id on an IdP', 'clerk', (doc) => (doc.idps['clerk-acme'].id = 'clerk-acme'), 'idps.clerk-acme.id: unknown key'],
        ['a misspelled IdP key', 'clerk', (doc) => (doc.idps['clerk-acme'].jwksUrl = 'https://x.example'), 'idps.clerk-acme.jwksUrl: unknown key'],
        [
            'a misspelled claim mapping key',
            'clerk',
            (doc) => (doc.idps['clerk-acme'].claims.emailverified = true),
            'idps.clerk-acme.claims.emailverified: unknown key',
        ],
        ['an input id on a product', 'clerk', (doc) => (doc.products.acme.id = 'acme'), 'products.acme.id: unknown key'],
        ['a misspelled binding key', 'clerk', (doc) => (doc.products.acme.idps[0].clientId = 'x'), 'products.acme.idps[0].clientId: unknown key'],
        ['an extra events key', 'clerk', (doc) => (doc.products.acme.events.secret = 'x'), 'products.acme.events.secret: unknown key'],
        [
            'an input id on a source',
            'clerk',
            (doc) => (doc.webhookSources['clerk-acme'].id = 'clerk-acme'),
            'webhookSources.clerk-acme.id: unknown key',
        ],
        [
            'a key that needs quoting',
            'clerk',
            (doc) => (doc.webhookSources['clerk-acme']['signing secret'] = 'x'),
            'webhookSources.clerk-acme["signing secret"]: unknown key',
        ],
    ])('rejects %s', (_name, base, edit, message) => {
        expect(rejection(edited(base, edit))).toBe(message)
    })
})

describe('parseConfig field rules', () => {
    it.each<Case>([
        ['a missing issuer', 'clerk', (doc) => delete doc.issuer, 'issuer: required'],
        ['an issuer that is not a string', 'clerk', (doc) => (doc.issuer = 42), 'issuer: must be an https URL'],
        ['an http issuer', 'clerk', (doc) => (doc.issuer = 'http://id.acme.example'), 'issuer: must be an https URL'],
        ['an issuer that is not a URL', 'clerk', (doc) => (doc.issuer = 'id.acme.example'), 'issuer: must be an https URL'],
        ['an issuer with trailing space', 'clerk', (doc) => (doc.issuer = 'https://id.acme.example/ '), 'issuer: must be an https URL'],
        ['the issuer https://x/', 'clerk', (doc) => (doc.issuer = 'https://id.acme.example/'), 'issuer: must not end with "/", "?" or "#"'],
        ['the issuer https://x?', 'clerk', (doc) => (doc.issuer = 'https://id.acme.example?'), 'issuer: must not end with "/", "?" or "#"'],
        ['the issuer https://x#', 'clerk', (doc) => (doc.issuer = 'https://id.acme.example#'), 'issuer: must not end with "/", "?" or "#"'],
        [
            'an issuer path ending in /',
            'clerk',
            (doc) => (doc.issuer = 'https://id.acme.example/bridge/'),
            'issuer: must not end with "/", "?" or "#"',
        ],
        [
            'an issuer with a query',
            'clerk',
            (doc) => (doc.issuer = 'https://id.acme.example?tenant=acme'),
            'issuer: must not have a query or fragment',
        ],
        ['an issuer with a fragment', 'clerk', (doc) => (doc.issuer = 'https://id.acme.example#acme'), 'issuer: must not have a query or fragment'],
        [
            'an issuer with a username',
            'clerk',
            (doc) => (doc.issuer = 'https://bridge@id.acme.example'),
            'issuer: must not have a username or password',
        ],
        [
            'an issuer with only a password',
            'clerk',
            (doc) => (doc.issuer = 'https://:secret@id.acme.example'),
            'issuer: must not have a username or password',
        ],
        [
            'an IdP issuer with credentials',
            'clerk',
            (doc) => (doc.idps['clerk-acme'].issuer = 'https://user:pass@clerk.acme.example'),
            'idps.clerk-acme.issuer: must not have a username or password',
        ],
        [
            'a jwksUri with credentials',
            'clerk',
            (doc) => (doc.idps['clerk-acme'].jwksUri = 'https://user:pass@clerk.acme.example/jwks'),
            'idps.clerk-acme.jwksUri: must not have a username or password',
        ],
        [
            'an events url with credentials',
            'clerk',
            (doc) => (doc.products.acme.events.url = 'https://hook:secret@api.acme.example/events'),
            'products.acme.events.url: must not have a username or password',
        ],
        ['a region with capitals', 'clerk', (doc) => (doc.region = 'US'), 'region: must match ^[a-z][a-z0-9-]{0,31}$'],
        ['a null region', 'clerk', (doc) => (doc.region = null), 'region: must match ^[a-z][a-z0-9-]{0,31}$'],
        ['a region of 33 characters', 'clerk', (doc) => (doc.region = 'a'.repeat(33)), 'region: must match ^[a-z][a-z0-9-]{0,31}$'],
        ['a non-integer tokenTtlSeconds', 'clerk', (doc) => (doc.tokenTtlSeconds = 900.5), 'tokenTtlSeconds: must be an integer from 60 to 3600'],
        ['a string tokenTtlSeconds', 'clerk', (doc) => (doc.tokenTtlSeconds = '900'), 'tokenTtlSeconds: must be an integer from 60 to 3600'],
        ['tokenTtlSeconds 59', 'clerk', (doc) => (doc.tokenTtlSeconds = 59), 'tokenTtlSeconds: must be an integer from 60 to 3600'],
        ['tokenTtlSeconds 3601', 'clerk', (doc) => (doc.tokenTtlSeconds = 3601), 'tokenTtlSeconds: must be an integer from 60 to 3600'],
        ['missing idps', 'clerk', (doc) => delete doc.idps, 'idps: required'],
        ['empty idps', 'clerk', (doc) => (doc.idps = {}), 'idps: must not be empty'],
        ['idps as an array', 'clerk', (doc) => (doc.idps = []), 'idps: must be an object'],
        ['an IdP id with capitals', 'minimal', (doc) => (doc.idps = { Idp: doc.idps.idp }), `idps.Idp: ${ID_RULE}`],
        ['an IdP id starting with a hyphen', 'minimal', (doc) => (doc.idps = { '-idp': doc.idps.idp }), `idps.-idp: ${ID_RULE}`],
        ['an IdP id of 64 characters', 'minimal', (doc) => (doc.idps = { ['a'.repeat(64)]: doc.idps.idp }), `idps.${'a'.repeat(64)}: ${ID_RULE}`],
        ['an IdP id with a dot', 'minimal', (doc) => (doc.idps = { 'idp.example': doc.idps.idp }), `idps["idp.example"]: ${ID_RULE}`],
        [
            'an IdP that is not an object',
            'clerk',
            (doc) => (doc.idps['clerk-acme'] = 'https://clerk.acme.example'),
            'idps.clerk-acme: must be an object',
        ],
        ['an IdP without issuer', 'clerk', (doc) => delete doc.idps['clerk-acme'].issuer, 'idps.clerk-acme.issuer: required'],
        [
            'an IdP issuer https://x/',
            'clerk',
            (doc) => (doc.idps['clerk-acme'].issuer = 'https://clerk.acme.example/'),
            'idps.clerk-acme.issuer: must not end with "/", "?" or "#"',
        ],
        [
            'an IdP issuer https://x?',
            'clerk',
            (doc) => (doc.idps['clerk-acme'].issuer = 'https://clerk.acme.example?'),
            'idps.clerk-acme.issuer: must not end with "/", "?" or "#"',
        ],
        [
            'an IdP issuer https://x#',
            'clerk',
            (doc) => (doc.idps['clerk-acme'].issuer = 'https://clerk.acme.example#'),
            'idps.clerk-acme.issuer: must not end with "/", "?" or "#"',
        ],
        [
            'an IdP issuer with a query',
            'clerk',
            (doc) => (doc.idps['clerk-acme'].issuer = 'https://clerk.acme.example?x=1'),
            'idps.clerk-acme.issuer: must not have a query or fragment',
        ],
        [
            'an IdP issuer with a fragment',
            'clerk',
            (doc) => (doc.idps['clerk-acme'].issuer = 'https://clerk.acme.example#clerk'),
            'idps.clerk-acme.issuer: must not have a query or fragment',
        ],
        [
            'an http IdP issuer',
            'clerk',
            (doc) => (doc.idps['clerk-acme'].issuer = 'http://clerk.acme.example'),
            'idps.clerk-acme.issuer: must be an https URL',
        ],
        ['an IdP without jwksUri', 'clerk', (doc) => delete doc.idps['clerk-acme'].jwksUri, 'idps.clerk-acme.jwksUri: required'],
        [
            'an http jwksUri',
            'clerk',
            (doc) => (doc.idps['clerk-acme'].jwksUri = 'http://clerk.acme.example/jwks'),
            'idps.clerk-acme.jwksUri: must be an https URL',
        ],
        [
            'a jwksUri that is not a URL',
            'clerk',
            (doc) => (doc.idps['clerk-acme'].jwksUri = 'jwks.json'),
            'idps.clerk-acme.jwksUri: must be an https URL',
        ],
        ['empty algorithms', 'clerk', (doc) => (doc.idps['clerk-acme'].algorithms = []), 'idps.clerk-acme.algorithms: must be a non-empty array'],
        [
            'algorithms as a string',
            'clerk',
            (doc) => (doc.idps['clerk-acme'].algorithms = 'RS256'),
            'idps.clerk-acme.algorithms: must be a non-empty array',
        ],
        ['HS256', 'clerk', (doc) => (doc.idps['clerk-acme'].algorithms = ['RS256', 'HS256']), `idps.clerk-acme.algorithms[1]: ${ALGORITHM_RULE}`],
        ['the none algorithm', 'clerk', (doc) => (doc.idps['clerk-acme'].algorithms = ['none']), `idps.clerk-acme.algorithms[0]: ${ALGORITHM_RULE}`],
        [
            'a lowercase algorithm',
            'clerk',
            (doc) => (doc.idps['clerk-acme'].algorithms = ['rs256']),
            `idps.clerk-acme.algorithms[0]: ${ALGORITHM_RULE}`,
        ],
        [
            'a non-integer maxTokenAgeSeconds',
            'clerk',
            (doc) => (doc.idps['clerk-acme'].maxTokenAgeSeconds = 900.5),
            'idps.clerk-acme.maxTokenAgeSeconds: must be an integer from 30 to 3600',
        ],
        [
            'maxTokenAgeSeconds 29',
            'clerk',
            (doc) => (doc.idps['clerk-acme'].maxTokenAgeSeconds = 29),
            'idps.clerk-acme.maxTokenAgeSeconds: must be an integer from 30 to 3600',
        ],
        [
            'maxTokenAgeSeconds 3601',
            'clerk',
            (doc) => (doc.idps['clerk-acme'].maxTokenAgeSeconds = 3601),
            'idps.clerk-acme.maxTokenAgeSeconds: must be an integer from 30 to 3600',
        ],
        [
            'a non-integer clockToleranceSeconds',
            'clerk',
            (doc) => (doc.idps['clerk-acme'].clockToleranceSeconds = 1.5),
            'idps.clerk-acme.clockToleranceSeconds: must be an integer from 0 to 300',
        ],
        [
            'clockToleranceSeconds -1',
            'clerk',
            (doc) => (doc.idps['clerk-acme'].clockToleranceSeconds = -1),
            'idps.clerk-acme.clockToleranceSeconds: must be an integer from 0 to 300',
        ],
        [
            'clockToleranceSeconds 301',
            'clerk',
            (doc) => (doc.idps['clerk-acme'].clockToleranceSeconds = 301),
            'idps.clerk-acme.clockToleranceSeconds: must be an integer from 0 to 300',
        ],
        ['empty requiredClaims', 'casdoor', (doc) => (doc.idps.casdoor.requiredClaims = {}), 'idps.casdoor.requiredClaims: must not be empty'],
        [
            'requiredClaims as an array',
            'casdoor',
            (doc) => (doc.idps.casdoor.requiredClaims = ['tokenType']),
            'idps.casdoor.requiredClaims: must be an object',
        ],
        [
            'a null required claim',
            'casdoor',
            (doc) => (doc.idps.casdoor.requiredClaims.tokenType = null),
            'idps.casdoor.requiredClaims.tokenType: must be a string, number or boolean',
        ],
        [
            'an array required claim',
            'casdoor',
            (doc) => (doc.idps.casdoor.requiredClaims.tokenType = ['access-token']),
            'idps.casdoor.requiredClaims.tokenType: must be a string, number or boolean',
        ],
        [
            'an object required claim',
            'casdoor',
            (doc) => (doc.idps.casdoor.requiredClaims.tokenType = {}),
            'idps.casdoor.requiredClaims.tokenType: must be a string, number or boolean',
        ],
        ['claims that are not an object', 'clerk', (doc) => (doc.idps['clerk-acme'].claims = 'default'), 'idps.clerk-acme.claims: must be an object'],
        [
            'an empty claim name',
            'clerk',
            (doc) => (doc.idps['clerk-acme'].claims.email = ''),
            'idps.clerk-acme.claims.email: must be a non-empty string',
        ],
        ['a null uid claim', 'clerk', (doc) => (doc.idps['clerk-acme'].claims.uid = null), 'idps.clerk-acme.claims.uid: must be a non-empty string'],
        [
            'a numeric clientId claim',
            'clerk',
            (doc) => (doc.idps['clerk-acme'].claims.clientId = 1),
            'idps.clerk-acme.claims.clientId: must be a non-empty string',
        ],
        [
            'literal true for a name claim',
            'clerk',
            (doc) => (doc.idps['clerk-acme'].claims.name = true),
            'idps.clerk-acme.claims.name: must be a non-empty string',
        ],
        [
            'an empty phoneRegion claim',
            'casdoor',
            (doc) => (doc.idps.casdoor.claims.phoneRegion = ''),
            'idps.casdoor.claims.phoneRegion: must be a non-empty string',
        ],
        [
            'literal true for the phoneRegion claim',
            'casdoor',
            (doc) => (doc.idps.casdoor.claims.phoneRegion = true),
            'idps.casdoor.claims.phoneRegion: must be a non-empty string',
        ],
        [
            'an empty updatedAt claim',
            'clerk',
            (doc) => (doc.idps['clerk-acme'].claims.updatedAt = ''),
            'idps.clerk-acme.claims.updatedAt: must be a non-empty string',
        ],
        [
            'literal true for the updatedAt claim',
            'clerk',
            (doc) => (doc.idps['clerk-acme'].claims.updatedAt = true),
            'idps.clerk-acme.claims.updatedAt: must be a non-empty string',
        ],
        [
            'a snake_case updatedAt key',
            'clerk',
            (doc) => (doc.idps['clerk-acme'].claims.updated_at = 'updated_at'),
            'idps.clerk-acme.claims.updated_at: unknown key',
        ],
        [
            'a misspelled phoneRegion key',
            'casdoor',
            (doc) => (doc.idps.casdoor.claims.phoneregion = 'countryCode'),
            'idps.casdoor.claims.phoneregion: unknown key',
        ],
        [
            'emailVerified false',
            'clerk',
            (doc) => (doc.idps['clerk-acme'].claims.emailVerified = false),
            'idps.clerk-acme.claims.emailVerified: must be a non-empty string or true',
        ],
        [
            'an empty phoneVerified',
            'clerk',
            (doc) => (doc.idps['clerk-acme'].claims.phoneVerified = ''),
            'idps.clerk-acme.claims.phoneVerified: must be a non-empty string or true',
        ],
        ['missing products', 'clerk', (doc) => delete doc.products, 'products: required'],
        ['empty products', 'clerk', (doc) => (doc.products = {}), 'products: must not be empty'],
        ['products as an array', 'clerk', (doc) => (doc.products = []), 'products: must be an object'],
        ['a product id with an underscore', 'minimal', (doc) => (doc.products = { my_app: doc.products.app }), `products.my_app: ${ID_RULE}`],
        ['a product that is not an object', 'clerk', (doc) => (doc.products.acme = null), 'products.acme: must be an object'],
        ['a product without idps', 'clerk', (doc) => delete doc.products.acme.idps, 'products.acme.idps: required'],
        ['a product with empty idps', 'clerk', (doc) => (doc.products.acme.idps = []), 'products.acme.idps: must be a non-empty array'],
        ['a binding that is not an object', 'clerk', (doc) => (doc.products.acme.idps = ['clerk-acme']), 'products.acme.idps[0]: must be an object'],
        ['a binding without idp', 'clerk', (doc) => (doc.products.acme.idps = [{}]), 'products.acme.idps[0].idp: required'],
        ['a binding idp that is not a string', 'clerk', (doc) => (doc.products.acme.idps[0].idp = 1), 'products.acme.idps[0].idp: must be a string'],
        [
            'empty clientIds',
            'casdoor',
            (doc) => (doc.products.acme.idps[0].clientIds = []),
            'products.acme.idps[0].clientIds: must be a non-empty array',
        ],
        [
            'clientIds that are not an array',
            'casdoor',
            (doc) => (doc.products.acme.idps[0].clientIds = 'acme-web-client'),
            'products.acme.idps[0].clientIds: must be a non-empty array',
        ],
        [
            'an empty client id',
            'casdoor',
            (doc) => (doc.products.acme.idps[0].clientIds = ['acme-web-client', '']),
            'products.acme.idps[0].clientIds[1]: must be a non-empty string',
        ],
        [
            'empty authorizedParties',
            'clerk',
            (doc) => (doc.products.acme.idps[0].authorizedParties = []),
            'products.acme.idps[0].authorizedParties: must be a non-empty array',
        ],
        [
            'a numeric authorized party',
            'clerk',
            (doc) => (doc.products.acme.idps[0].authorizedParties = [1]),
            'products.acme.idps[0].authorizedParties[0]: must be a non-empty string',
        ],
        [
            'allowedOrigins as a string',
            'clerk',
            (doc) => (doc.products.acme.allowedOrigins = 'https://acme.example'),
            'products.acme.allowedOrigins: must be an array',
        ],
        [
            'the origin https://a.example/',
            'clerk',
            (doc) => doc.products.acme.allowedOrigins.push('https://a.example/'),
            'products.acme.allowedOrigins[1]: must be an origin',
        ],
        [
            'an origin with a path',
            'clerk',
            (doc) => doc.products.acme.allowedOrigins.push('https://a.example/app'),
            'products.acme.allowedOrigins[1]: must be an origin',
        ],
        [
            'an origin with the default port',
            'clerk',
            (doc) => doc.products.acme.allowedOrigins.push('https://a.example:443'),
            'products.acme.allowedOrigins[1]: must be an origin',
        ],
        [
            'an origin with a capital scheme',
            'clerk',
            (doc) => doc.products.acme.allowedOrigins.push('HTTPS://a.example'),
            'products.acme.allowedOrigins[1]: must be an origin',
        ],
        [
            'an origin with a capital host',
            'clerk',
            (doc) => doc.products.acme.allowedOrigins.push('https://A.example'),
            'products.acme.allowedOrigins[1]: must be an origin',
        ],
        [
            'an unparsable http origin',
            'clerk',
            (doc) => doc.products.acme.allowedOrigins.push('http://a b'),
            'products.acme.allowedOrigins[1]: must be an origin',
        ],
        ['the null origin', 'clerk', (doc) => doc.products.acme.allowedOrigins.push('null'), 'products.acme.allowedOrigins[1]: must be an origin'],
        ['a wildcard origin', 'clerk', (doc) => doc.products.acme.allowedOrigins.push('*'), 'products.acme.allowedOrigins[1]: must be an origin'],
        [
            'an origin without a scheme',
            'clerk',
            (doc) => doc.products.acme.allowedOrigins.push('acme.example'),
            'products.acme.allowedOrigins[1]: must be an origin',
        ],
        [
            'capacitor:// without a host',
            'clerk',
            (doc) => doc.products.acme.allowedOrigins.push('capacitor://'),
            'products.acme.allowedOrigins[1]: must be an origin',
        ],
        [
            'capacitor://localhost/',
            'clerk',
            (doc) => doc.products.acme.allowedOrigins.push('capacitor://localhost/'),
            'products.acme.allowedOrigins[1]: must be an origin',
        ],
        [
            'Capacitor://localhost',
            'clerk',
            (doc) => doc.products.acme.allowedOrigins.push('Capacitor://localhost'),
            'products.acme.allowedOrigins[1]: must be an origin',
        ],
        [
            'capacitor://local host',
            'clerk',
            (doc) => doc.products.acme.allowedOrigins.push('capacitor://local host'),
            'products.acme.allowedOrigins[1]: must be an origin',
        ],
        [
            'an other-scheme origin with a tab',
            'clerk',
            (doc) => doc.products.acme.allowedOrigins.push('capacitor://localhost\t'),
            'products.acme.allowedOrigins[1]: must be an origin',
        ],
        [
            'an https origin with a trailing space',
            'clerk',
            (doc) => doc.products.acme.allowedOrigins.push('https://a.example '),
            'products.acme.allowedOrigins[1]: must be an origin',
        ],
        ['a numeric origin', 'clerk', (doc) => doc.products.acme.allowedOrigins.push(443), 'products.acme.allowedOrigins[1]: must be an origin'],
        [
            'events that are not an object',
            'clerk',
            (doc) => (doc.products.acme.events = 'https://api.acme.example'),
            'products.acme.events: must be an object',
        ],
        ['events without url', 'clerk', (doc) => (doc.products.acme.events = {}), 'products.acme.events.url: required'],
        [
            'an http events url',
            'clerk',
            (doc) => (doc.products.acme.events.url = 'http://api.acme.example/events'),
            'products.acme.events.url: must be an https URL',
        ],
        ['webhookSources as an array', 'clerk', (doc) => (doc.webhookSources = []), 'webhookSources: must be an object'],
        [
            'a source id with capitals',
            'clerk',
            (doc) => (doc.webhookSources = { Clerk: doc.webhookSources['clerk-acme'] }),
            `webhookSources.Clerk: ${ID_RULE}`,
        ],
        [
            'a source that is not an object',
            'clerk',
            (doc) => (doc.webhookSources['clerk-acme'] = 'clerk'),
            'webhookSources.clerk-acme: must be an object',
        ],
        ['a source without type', 'clerk', (doc) => delete doc.webhookSources['clerk-acme'].type, 'webhookSources.clerk-acme.type: required'],
        [
            'an unknown source type',
            'clerk',
            (doc) => (doc.webhookSources['clerk-acme'].type = 'svix'),
            'webhookSources.clerk-acme.type: must be "clerk" or "casdoor"',
        ],
        [
            'a Casdoor source without organization',
            'casdoor',
            (doc) => delete doc.webhookSources['casdoor-acme'].organization,
            'webhookSources.casdoor-acme.organization: required for casdoor sources',
        ],
        [
            'a Casdoor source with an empty organization',
            'casdoor',
            (doc) => (doc.webhookSources['casdoor-acme'].organization = ''),
            'webhookSources.casdoor-acme.organization: must be a non-empty string',
        ],
        [
            'a Clerk source with an organization',
            'clerk',
            (doc) => (doc.webhookSources['clerk-acme'].organization = 'acme'),
            'webhookSources.clerk-acme.organization: not allowed for clerk sources',
        ],
        ['a source without idp', 'clerk', (doc) => delete doc.webhookSources['clerk-acme'].idp, 'webhookSources.clerk-acme.idp: required'],
        [
            'a source idp that is not a string',
            'clerk',
            (doc) => (doc.webhookSources['clerk-acme'].idp = ['clerk-acme']),
            'webhookSources.clerk-acme.idp: must be a string',
        ],
        [
            'a Clerk source with a uidField other than external_id',
            'clerk',
            (doc) => (doc.webhookSources['clerk-acme'].uidField = 'uid'),
            'webhookSources.clerk-acme.uidField: must be "external_id" for clerk sources',
        ],
        [
            'a Casdoor source with an empty uidField',
            'casdoor',
            (doc) => (doc.webhookSources['casdoor-acme'].uidField = ''),
            'webhookSources.casdoor-acme.uidField: must be a non-empty string',
        ],
        [
            'a source without products',
            'clerk',
            (doc) => delete doc.webhookSources['clerk-acme'].products,
            'webhookSources.clerk-acme.products: required',
        ],
        [
            'a source with empty products',
            'clerk',
            (doc) => (doc.webhookSources['clerk-acme'].products = []),
            'webhookSources.clerk-acme.products: must be a non-empty array',
        ],
        [
            'a source product that is not a string',
            'clerk',
            (doc) => (doc.webhookSources['clerk-acme'].products = [1]),
            'webhookSources.clerk-acme.products[0]: must be a string',
        ],
    ])('rejects %s', (_name, base, edit, message) => {
        expect(rejection(edited(base, edit))).toBe(message)
    })
})

const SHARED_IDP = 'must list clientIds or authorizedParties, because idp "casdoor" is bound by several products'

// A second IdP record with the Casdoor example's issuer, as when two applications of one instance are configured apart
function secondCasdoorRecord(doc: Doc) {
    doc.idps['casdoor-globex'] = { ...doc.idps.casdoor }
    doc.products.globex.idps = [{ idp: 'casdoor-globex' }]
}

function otherIdp(doc: Doc) {
    doc.idps.other = { issuer: 'https://other.example', jwksUri: 'https://other.example/jwks', claims: { uid: 'uid' } }
}

// A product with events that binds an IdP other than the Casdoor source's
function betaProduct(doc: Doc) {
    otherIdp(doc)
    doc.products.beta = { idps: [{ idp: 'other' }], events: { url: 'https://beta.example/events' } }
}

describe('parseConfig cross-references', () => {
    it.each<Case>([
        [
            'an unknown binding idp',
            'clerk',
            (doc) => (doc.products.acme.idps[0].idp = 'clerk-acm'),
            'products.acme.idps[0].idp: unknown idp "clerk-acm"',
        ],
        [
            'a binding idp named constructor',
            'clerk',
            (doc) => (doc.products.acme.idps[0].idp = 'constructor'),
            'products.acme.idps[0].idp: unknown idp "constructor"',
        ],
        [
            'a binding idp named __proto__',
            'clerk',
            (doc) => (doc.products.acme.idps[0].idp = '__proto__'),
            'products.acme.idps[0].idp: unknown idp "__proto__"',
        ],
        [
            'one IdP bound twice by a product',
            'clerk',
            (doc) => doc.products.acme.idps.push({ idp: 'clerk-acme' }),
            'products.acme.idps[1].idp: idp "clerk-acme" is already bound at idps[0]',
        ],
        [
            'updatedAt on an IdP of a product bound to several IdPs',
            'clerk',
            (doc) => {
                doc.idps.other = { issuer: 'https://other.example', jwksUri: 'https://other.example/jwks' }
                doc.products.acme.idps.push({ idp: 'other' })
                doc.idps['clerk-acme'].claims.updatedAt = 'updated_at'
            },
            'products.acme.idps[0].idp: idp "clerk-acme" maps updatedAt, which needs a product bound to it alone: times of different idps cannot be compared',
        ],
        [
            'updatedAt on the second IdP of a product bound to several IdPs',
            'clerk',
            (doc) => {
                doc.idps.other = { issuer: 'https://other.example', jwksUri: 'https://other.example/jwks', claims: { updatedAt: 'iat' } }
                doc.products.acme.idps.push({ idp: 'other' })
            },
            'products.acme.idps[1].idp: idp "other" maps updatedAt, which needs a product bound to it alone: times of different idps cannot be compared',
        ],
        [
            'two IdP records with one issuer',
            'clerk',
            (doc) => (doc.idps['clerk-acme-staging'] = { ...doc.idps['clerk-acme'], jwksUri: 'https://clerk.acme.example/staging/jwks' }),
            'idps.clerk-acme-staging.issuer: "https://clerk.acme.example" is already the issuer of idp "clerk-acme"',
        ],
        [
            'two IdP records with one issuer bound by two products',
            'casdoor',
            secondCasdoorRecord,
            'idps.casdoor-globex.issuer: "https://casdoor.example" is already the issuer of idp "casdoor"',
        ],
        [
            'a shared IdP without client binding',
            'casdoor',
            (doc) => delete doc.products.globex.idps[0].clientIds,
            `products.globex.idps[0]: ${SHARED_IDP}`,
        ],
        [
            'a shared IdP without client binding on the first product',
            'casdoor',
            (doc) => delete doc.products.acme.idps[0].clientIds,
            `products.acme.idps[0]: ${SHARED_IDP}`,
        ],
        [
            'a client id shared by two products of one IdP',
            'casdoor',
            (doc) => doc.products.globex.idps[0].clientIds.push('acme-app-client'),
            'products.globex.idps[0].clientIds[1]: "acme-app-client" is also a client of product "acme"',
        ],
        [
            'an authorized party shared by two products of one IdP',
            'casdoor',
            (doc) => {
                doc.products.acme.idps[0].authorizedParties = ['https://acme.example']
                doc.products.globex.idps[0].authorizedParties = ['https://acme.example']
            },
            'products.globex.idps[0].authorizedParties[0]: "https://acme.example" is also a client of product "acme"',
        ],
        [
            "a client id of one product listed as another's authorized party",
            'casdoor',
            (doc) => (doc.products.globex.idps[0].authorizedParties = ['acme-web-client']),
            'products.globex.idps[0].authorizedParties[0]: "acme-web-client" is also a client of product "acme"',
        ],
        [
            'a third product reusing a client id of the first',
            'casdoor',
            (doc) => (doc.products.initech = { idps: [{ idp: 'casdoor', clientIds: ['initech-web-client', 'acme-web-client'] }] }),
            'products.initech.idps[0].clientIds[1]: "acme-web-client" is also a client of product "acme"',
        ],
        [
            'an unknown source idp',
            'clerk',
            (doc) => (doc.webhookSources['clerk-acme'].idp = 'clerk-acm'),
            'webhookSources.clerk-acme.idp: unknown idp "clerk-acm"',
        ],
        [
            'a uidField without claims.uid',
            'clerk',
            (doc) => delete doc.idps['clerk-acme'].claims.uid,
            'webhookSources.clerk-acme.uidField: not allowed, because idp "clerk-acme" maps no uid claim',
        ],
        [
            'claims.uid without a uidField',
            'clerk',
            (doc) => delete doc.webhookSources['clerk-acme'].uidField,
            'webhookSources.clerk-acme.uidField: required, because idp "clerk-acme" maps a uid claim',
        ],
        [
            'a Casdoor uidField without claims.uid',
            'casdoor',
            (doc) => delete doc.idps.casdoor.claims.uid,
            'webhookSources.casdoor-acme.uidField: not allowed, because idp "casdoor" maps no uid claim',
        ],
        [
            'Casdoor claims.uid without a uidField',
            'casdoor',
            (doc) => delete doc.webhookSources['casdoor-acme'].uidField,
            'webhookSources.casdoor-acme.uidField: required, because idp "casdoor" maps a uid claim',
        ],
        [
            'an unknown source product',
            'clerk',
            (doc) => (doc.webhookSources['clerk-acme'].products = ['acm']),
            'webhookSources.clerk-acme.products[0]: unknown product "acm"',
        ],
        [
            'a repeated source product',
            'clerk',
            (doc) => doc.webhookSources['clerk-acme'].products.push('acme'),
            'webhookSources.clerk-acme.products[1]: product "acme" is already listed at products[0]',
        ],
        [
            'a source product without events',
            'casdoor',
            (doc) => doc.webhookSources['casdoor-acme'].products.push('globex'),
            'webhookSources.casdoor-acme.products[1]: product "globex" has no events',
        ],
        [
            "a source product not binding the source's IdP",
            'casdoor',
            (doc) => {
                betaProduct(doc)
                doc.webhookSources['casdoor-acme'].products.push('beta')
            },
            'webhookSources.casdoor-acme.products[1]: product "beta" does not bind idp "casdoor"',
        ],
    ])('rejects %s', (_name, base, edit, message) => {
        expect(rejection(edited(base, edit))).toBe(message)
    })

    it.each<Accepted>([
        [
            'a shared IdP bound through authorizedParties',
            'casdoor',
            (doc) => (doc.products.globex.idps = [{ idp: 'casdoor', authorizedParties: ['globex-web-client'] }]),
        ],
        [
            'a client value repeated within one binding',
            'casdoor',
            (doc) => {
                doc.products.acme.idps[0].clientIds.push('acme-web-client')
                doc.products.acme.idps[0].authorizedParties = ['acme-web-client']
            },
        ],
        [
            'one client id on bindings of different IdPs',
            'casdoor',
            (doc) => {
                betaProduct(doc)
                doc.products.beta.idps[0].clientIds = ['acme-web-client']
            },
        ],
        [
            'two products on distinct issuers without client binding',
            'casdoor',
            (doc) => {
                betaProduct(doc)
                delete doc.products.globex
                delete doc.products.acme.idps[0].clientIds
            },
        ],
        [
            'a product binding IdPs with distinct issuers',
            'casdoor',
            (doc) => {
                otherIdp(doc)
                doc.products.acme.idps.push({ idp: 'other' })
            },
        ],
        [
            'a source without uidField for an IdP without claims.uid',
            'clerk',
            (doc) => {
                delete doc.idps['clerk-acme'].claims.uid
                delete doc.webhookSources['clerk-acme'].uidField
            },
        ],
        ['a Casdoor source with any Properties key as uidField', 'casdoor', (doc) => (doc.webhookSources['casdoor-acme'].uidField = 'bridge-uid')],
    ])('accepts %s', (_name, base, edit) => {
        expect(() => parseConfig(edited(base, edit))).not.toThrow()
    })
})

describe('parseConfig edge cases', () => {
    it('keeps a required claim named __proto__ as a plain entry', () => {
        const json = casdoorConfigJson.replace('"requiredClaims":{', '"requiredClaims":{"__proto__":"x",')
        const claims = parseConfig(json).idps.casdoor!.requiredClaims
        expect(Object.keys(claims)).toEqual(['__proto__', 'tokenType'])
        expect(claims['__proto__']).toBe('x')
        expect(Object.getPrototypeOf(claims)).toBeNull()
    })

    it.each<Case>([
        ['the document', 'clerk', (doc) => setOwn(doc, '__proto__', {}), '__proto__: unknown key'],
        ['an IdP', 'clerk', (doc) => setOwn(doc.idps['clerk-acme'], '__proto__', {}), 'idps.clerk-acme.__proto__: unknown key'],
        [
            'a claim mapping',
            'clerk',
            (doc) => setOwn(doc.idps['clerk-acme'].claims, '__proto__', 'x'),
            'idps.clerk-acme.claims.__proto__: unknown key',
        ],
        ['a product', 'clerk', (doc) => setOwn(doc.products.acme, '__proto__', {}), 'products.acme.__proto__: unknown key'],
        ['a binding', 'clerk', (doc) => setOwn(doc.products.acme.idps[0], '__proto__', {}), 'products.acme.idps[0].__proto__: unknown key'],
        ['events', 'clerk', (doc) => setOwn(doc.products.acme.events, '__proto__', {}), 'products.acme.events.__proto__: unknown key'],
        ['a source', 'clerk', (doc) => setOwn(doc.webhookSources['clerk-acme'], '__proto__', {}), 'webhookSources.clerk-acme.__proto__: unknown key'],
    ])('rejects __proto__ as a key of %s', (_name, base, edit, message) => {
        expect(rejection(edited(base, edit))).toBe(message)
    })

    it.each<Case>([
        ['an IdP id', 'clerk', (doc) => setOwn(doc.idps, '__proto__', {}), `idps.__proto__: ${ID_RULE}`],
        ['a product id', 'clerk', (doc) => setOwn(doc.products, '__proto__', { idps: [{ idp: 'clerk-acme' }] }), `products.__proto__: ${ID_RULE}`],
        ['a source id', 'clerk', (doc) => setOwn(doc.webhookSources, '__proto__', {}), `webhookSources.__proto__: ${ID_RULE}`],
    ])('rejects __proto__ as %s', (_name, base, edit, message) => {
        expect(rejection(edited(base, edit))).toBe(message)
    })

    it('accepts constructor as a product id and indexes it like any other', () => {
        const config = parseConfig(edited('minimal', (doc) => (doc.products = { constructor: doc.products.app })))
        expect(config.products.constructor).toMatchObject({ id: 'constructor' })
    })

    it('treats prototype member names as unknown references', () => {
        expect(rejection(edited('clerk', (doc) => (doc.webhookSources['clerk-acme'].products = ['constructor'])))).toBe(
            'webhookSources.clerk-acme.products[0]: unknown product "constructor"',
        )
        expect(rejection(edited('clerk', (doc) => (doc.webhookSources['clerk-acme'].idp = 'hasOwnProperty')))).toBe(
            'webhookSources.clerk-acme.idp: unknown idp "hasOwnProperty"',
        )
    })

    it('quotes claim names that are not plain keys in the path', () => {
        const role = 'https://acme.example/claims/role'
        const accepted = parseConfig(edited('casdoor', (doc) => (doc.idps.casdoor.requiredClaims[role] = 'member')))
        expect(accepted.idps.casdoor!.requiredClaims[role]).toBe('member')
        expect(rejection(edited('casdoor', (doc) => (doc.idps.casdoor.requiredClaims[role] = null)))).toBe(
            `idps.casdoor.requiredClaims["${role}"]: must be a string, number or boolean`,
        )
    })

    it('shortens the long values and keys it quotes', () => {
        const long = 'x'.repeat(200)
        expect(rejection(edited('clerk', (doc) => (doc.products.acme.idps[0].idp = long)))).toBe(
            `products.acme.idps[0].idp: unknown idp "${'x'.repeat(64)}…"`,
        )
        expect(rejection(edited('clerk', (doc) => (doc[long] = 1)))).toBe(`["${'x'.repeat(64)}…"]: unknown key`)
    })

    it.each(['9e2', '900.0', '9.0e2'])('reads the duration %s as the integer 900', (written) => {
        const json = clerkConfigJson.replace('"tokenTtlSeconds":900', `"tokenTtlSeconds":${written}`)
        expect(json).not.toBe(clerkConfigJson)
        expect(parseConfig(json).tokenTtlSeconds).toBe(900)
    })

    it('reports a missing document as invalid JSON', () => {
        expect(rejection(undefined as unknown as string)).toBe('invalid JSON')
    })

    it('reports unknown keys before the other fields of their object', () => {
        expect(rejection(edited('clerk', (doc) => Object.assign(doc, { issuer: 'http://id.acme.example', issuers: [] })))).toBe(
            'issuers: unknown key',
        )
    })

    it.each<Case>([
        ['a leading space', 'clerk', (doc) => (doc.issuer = ' https://id.acme.example'), 'issuer: must be an https URL'],
        ['a newline inside', 'clerk', (doc) => (doc.issuer = 'https://id.acme\n.example'), 'issuer: must be an https URL'],
        [
            'a tab',
            'clerk',
            (doc) => (doc.idps['clerk-acme'].jwksUri = 'https://clerk.acme.example/\tjwks'),
            'idps.clerk-acme.jwksUri: must be an https URL',
        ],
        [
            'a trailing newline',
            'clerk',
            (doc) => (doc.products.acme.events.url = 'https://api.acme.example/events\n'),
            'products.acme.events.url: must be an https URL',
        ],
    ])('rejects a URL with %s, which the URL parser would strip', (_name, base, edit, message) => {
        expect(rejection(edited(base, edit))).toBe(message)
    })

    it('reports the first product without client binding among three sharing an IdP', () => {
        const json = edited('casdoor', (doc) => {
            doc.products.initech = { idps: [{ idp: 'casdoor', clientIds: ['initech-web-client'] }] }
            delete doc.products.globex.idps[0].clientIds
        })
        expect(rejection(json)).toBe(`products.globex.idps[0]: ${SHARED_IDP}`)
    })

    it('rejects a second IdP record with an issuer even when no product binds it', () => {
        const json = edited('casdoor', (doc) => (doc.idps.spare = { ...doc.idps.casdoor }))
        expect(rejection(json)).toBe('idps.spare.issuer: "https://casdoor.example" is already the issuer of idp "casdoor"')
    })
})
