import { describe, expect, it } from 'vitest'
import { parseConfig } from '../src/config'
import { claim, mapClaims } from '../src/idp/claims'
import type { ClaimMapping } from '../src/types'
import { casdoorConfigJson, clerkConfig, clerkConfigJson } from './helpers/config'

type Doc = Record<string, any>

// The webhook source goes, as its uidField requires a mapped uid
function mapping(claims?: Doc): ClaimMapping {
    const doc: Doc = clerkConfig()
    delete doc.webhookSources
    if (claims === undefined) delete doc.idps['clerk-acme'].claims
    else doc.idps['clerk-acme'].claims = claims
    return parseConfig(JSON.stringify(doc)).idps['clerk-acme']!.claims
}

const DEFAULTS = mapping()
const CLERK = parseConfig(clerkConfigJson).idps['clerk-acme']!.claims
const CASDOOR = parseConfig(casdoorConfigJson).idps.casdoor!.claims

// Names that Object.prototype answers for when read without checking ownership
const PROTOTYPE_NAMES = ['__proto__', 'constructor', 'toString', 'valueOf', 'hasOwnProperty', 'isPrototypeOf']

describe('claim', () => {
    it('reads a member of the payload', () => {
        expect(claim({ sub: 'user_1', aud: ['a', 'b'] }, 'aud')).toEqual(['a', 'b'])
    })

    it('gives undefined for a missing member', () => {
        expect(claim({ sub: 'user_1' }, 'email')).toBeUndefined()
    })

    it.each(PROTOTYPE_NAMES)('gives undefined for %s when the payload lacks it', (name) => {
        expect(claim(JSON.parse('{"sub": "user_1"}'), name)).toBeUndefined()
    })

    it.each(PROTOTYPE_NAMES)('reads %s when the payload has it as its own member', (name) => {
        expect(claim(JSON.parse(`{${JSON.stringify(name)}: "value"}`), name)).toBe('value')
    })
})

describe('mapClaims', () => {
    it('reads the default claim names', () => {
        const payload = {
            aud: 'web-client',
            email: 'ada@acme.example',
            email_verified: true,
            phone_number: '+14155550123',
            phone_number_verified: true,
            name: 'Ada Lovelace',
            picture: 'https://img.acme.example/ada.png',
            uid: 'not mapped',
        }
        expect(mapClaims(payload, DEFAULTS)).toStrictEqual({
            clientIds: ['web-client'],
            profile: {
                email: 'ada@acme.example',
                emailVerified: true,
                phone: '+14155550123',
                phoneVerified: true,
                name: 'Ada Lovelace',
                picture: 'https://img.acme.example/ada.png',
            },
        })
    })

    it('reads the names a Casdoor JWT-Custom mapping gives', () => {
        const payload = {
            aud: ['acme-web-client'],
            email: 'ada@acme.example',
            emailVerified: true,
            displayName: 'Ada Lovelace',
            avatar: 'https://cdn.casdoor.example/ada.png',
            uid: '6f1c9e2a-3b4d-4e5f-8a6b-7c8d9e0f1a2b',
        }
        expect(mapClaims(payload, CASDOOR)).toStrictEqual({
            clientIds: ['acme-web-client'],
            uid: '6f1c9e2a-3b4d-4e5f-8a6b-7c8d9e0f1a2b',
            profile: {
                email: 'ada@acme.example',
                emailVerified: true,
                phone: undefined,
                phoneVerified: false,
                name: 'Ada Lovelace',
                picture: 'https://cdn.casdoor.example/ada.png',
            },
        })
    })

    it('leaves values unchecked, for cleanProfile and deriveUserId to judge', () => {
        const payload = { email: 42, name: { first: 'Ada' }, picture: ['https://img.acme.example/ada.png'], uid: 7 }
        const { uid, profile } = mapClaims(payload, CLERK)
        expect(uid).toBe(7)
        expect(profile).toMatchObject({ email: 42, name: { first: 'Ada' }, picture: ['https://img.acme.example/ada.png'] })
    })

    describe('client ids', () => {
        it.each([
            ['a string', 'web-client', ['web-client']],
            ['an array', ['web-client', 'app-client'], ['web-client', 'app-client']],
            ['an array holding other values', ['web-client', 7, null, { id: 'x' }, 'app-client'], ['web-client', 'app-client']],
            ['an empty array', [], []],
            ['a number', 7, []],
            ['null', null, []],
            ['an object', { 'web-client': true }, []],
        ])('reads %s', (_, aud, expected) => {
            expect(mapClaims({ aud }, DEFAULTS).clientIds).toEqual(expected)
        })

        it('reads none when the claim is missing', () => {
            expect(mapClaims({ azp: 'web-client' }, DEFAULTS).clientIds).toEqual([])
        })

        it('reads the configured claim instead of aud', () => {
            expect(mapClaims({ aud: 'resource', azp: 'web-client' }, mapping({ clientId: 'azp' })).clientIds).toEqual(['web-client'])
        })
    })

    describe('verified flags', () => {
        it.each([
            ['true', true, true],
            ['false', false, false],
            ['the string "true"', 'true', false],
            ['1', 1, false],
            ['an object', {}, false],
        ])('counts a claim of %s as verified only when it is true', (_, value, expected) => {
            const { profile } = mapClaims({ email_verified: value, phone_number_verified: value }, DEFAULTS)
            expect(profile.emailVerified).toBe(expected)
            expect(profile.phoneVerified).toBe(expected)
        })

        it('counts a missing claim as not verified', () => {
            const { profile } = mapClaims({}, DEFAULTS)
            expect(profile.emailVerified).toBe(false)
            expect(profile.phoneVerified).toBe(false)
        })

        it('trusts the IdP when the mapping is literally true, whatever the token says', () => {
            const trusting = mapping({ emailVerified: true, phoneVerified: true })
            const { profile } = mapClaims({ email_verified: false }, trusting)
            expect(profile.emailVerified).toBe(true)
            expect(profile.phoneVerified).toBe(true)
        })
    })

    describe('uid', () => {
        it('is the raw value of the mapped claim, null included', () => {
            expect(mapClaims({ uid: null }, CLERK)).toHaveProperty('uid', null)
            expect(mapClaims({ uid: '' }, CLERK)).toHaveProperty('uid', '')
        })

        it('is absent when the mapped claim is missing', () => {
            expect(mapClaims({ sub: 'user_1' }, CLERK)).not.toHaveProperty('uid')
        })

        it('is absent when no uid claim is mapped, even if the token has one', () => {
            expect(mapClaims({ uid: '6f1c9e2a-3b4d-4e5f-8a6b-7c8d9e0f1a2b' }, DEFAULTS)).not.toHaveProperty('uid')
        })
    })

    describe('prototype member names', () => {
        it.each(PROTOTYPE_NAMES)('reads nothing through the prototype when every claim is named %s', (name) => {
            const named = mapping({
                clientId: name,
                uid: name,
                email: name,
                emailVerified: name,
                phone: name,
                phoneVerified: name,
                name,
                picture: name,
            })
            expect(mapClaims(JSON.parse('{"sub": "user_1"}'), named)).toStrictEqual({
                clientIds: [],
                profile: {
                    email: undefined,
                    emailVerified: false,
                    phone: undefined,
                    phoneVerified: false,
                    name: undefined,
                    picture: undefined,
                },
            })
        })

        it.each(PROTOTYPE_NAMES)('reads a claim named %s that the payload has', (name) => {
            const payload = JSON.parse(`{${JSON.stringify(name)}: "web-client"}`)
            const { clientIds, uid, profile } = mapClaims(payload, mapping({ clientId: name, uid: name, name }))
            expect(clientIds).toEqual(['web-client'])
            expect(uid).toBe('web-client')
            expect(profile.name).toBe('web-client')
        })
    })
})
