import { describe, expect, it } from 'vitest'
import { BadUidError, deriveUserId, EVENT_ID_NAMESPACE, eventId, USER_ID_NAMESPACE, uuidV5 } from '../src/ids'
import golden from './fixtures/golden-ids.json'

const DNS_NAMESPACE = '6ba7b810-9dad-11d1-80b4-00c04fd430c8'
const V5 = /^[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/
const CLERK = 'https://clerk.acme.example'
const SUBJECT = 'user_2pXk7QmZbLr9TfWc4NvHs8YdJe1'

describe('uuidV5', () => {
    it('matches the RFC 9562 vector', async () => {
        expect(await uuidV5(DNS_NAMESPACE, 'www.example.com')).toBe('2ed6657d-e927-568b-95e1-2665a8aea6a2')
    })

    it('reads the namespace case-insensitively', async () => {
        expect(await uuidV5(DNS_NAMESPACE.toUpperCase(), 'www.example.com')).toBe('2ed6657d-e927-568b-95e1-2665a8aea6a2')
    })

    it('sets the version and variant bits and formats lowercase', async () => {
        const names = ['', 'a', 'www.example.com', 'José-用户', 'x'.repeat(1000)]
        for (const name of names) expect(await uuidV5(USER_ID_NAMESPACE, name)).toMatch(V5)
    })

    it.each(['', 'www.example.com', '6ba7b8109dad11d180b400c04fd430c8', `{${DNS_NAMESPACE}}`, `${DNS_NAMESPACE.slice(0, -1)}g`])(
        'refuses the namespace %j',
        async (namespace) => {
            await expect(uuidV5(namespace, 'www.example.com')).rejects.toThrow(TypeError)
        },
    )
})

describe('namespaces', () => {
    it('are fixed forever', () => {
        expect(USER_ID_NAMESPACE).toBe('95c1f512-a23b-48f7-8328-199bb33cc0b4')
        expect(EVENT_ID_NAMESPACE).toBe('73c4ff75-fed7-4a0c-8541-3ff240e8f331')
    })
})

describe('deriveUserId', () => {
    it.each(golden.userIds)('gives the golden id for $case', async (entry) => {
        const id = 'uid' in entry ? deriveUserId(entry.issuer, entry.subject, entry.uid) : deriveUserId(entry.issuer, entry.subject)
        expect(await id).toBe(entry.expected)
    })

    it('treats an absent, undefined or null override as no override', async () => {
        const derived = await uuidV5(USER_ID_NAMESPACE, JSON.stringify([CLERK, SUBJECT]))
        expect(await deriveUserId(CLERK, SUBJECT)).toBe(derived)
        expect(await deriveUserId(CLERK, SUBJECT, undefined)).toBe(derived)
        expect(await deriveUserId(CLERK, SUBJECT, null)).toBe(derived)
    })

    it('gives other ids for another issuer or subject', async () => {
        const ids = await Promise.all([
            deriveUserId(CLERK, SUBJECT),
            deriveUserId('https://clerk.globex.example', SUBJECT),
            deriveUserId(CLERK, `${SUBJECT}x`),
        ])
        expect(new Set(ids).size).toBe(3)
    })

    // TextEncoder alone would turn a lone surrogate into U+FFFD; JSON.stringify escapes it first
    it('keeps subjects apart that differ only in a lone surrogate', async () => {
        const ids = await Promise.all([deriveUserId(CLERK, 'a\ud800'), deriveUserId(CLERK, 'a�'), deriveUserId(CLERK, 'a\udc00')])
        expect(new Set(ids).size).toBe(3)
        for (const id of ids) expect(id).toMatch(V5)
    })

    it('returns an override of any version lowercased, ignoring the issuer and subject', async () => {
        for (const uid of ['00000000-0000-0000-0000-000000000000', '6F9619FF-8B86-1D01-B42D-00CF4FC964FF', 'aBcDeF01-2345-6789-abcd-ef0123456789']) {
            expect(await deriveUserId(CLERK, SUBJECT, uid)).toBe(uid.toLowerCase())
            expect(await deriveUserId('https://casdoor.example', 'other', uid)).toBe(uid.toLowerCase())
        }
    })

    const VALID = '6f9619ff-8b86-4d01-b42d-00cf4fc964ff'
    const MALFORMED: [string, unknown][] = [
        ['an empty string', ''],
        ['a word', 'admin'],
        ['a UUID without hyphens', VALID.replace(/-/g, '')],
        ['a UUID in braces', `{${VALID}}`],
        ['a UUID URN', `urn:uuid:${VALID}`],
        ['a UUID with a leading space', ` ${VALID}`],
        ['a UUID with a trailing newline', `${VALID}\n`],
        ['a UUID with a non-hex digit', `${VALID.slice(0, -1)}g`],
        ['a UUID with hyphens moved', '6f9619ff8-b86-4d01-b42d-00cf4fc964ff'],
        ['a UUID with fullwidth digits', '６f9619ff-8b86-4d01-b42d-00cf4fc964ff'],
        ['a number', 42],
        ['zero', 0],
        ['true', true],
        ['false', false],
        ['an object', { uid: VALID }],
        ['an array', [VALID]],
    ]

    it.each(MALFORMED)('refuses %s as an override', async (_, uid) => {
        await expect(deriveUserId(CLERK, SUBJECT, uid)).rejects.toBeInstanceOf(BadUidError)
    })

    it('never quotes the override in the error', async () => {
        const uid = 'secret-admin-value'
        const error = await deriveUserId(CLERK, SUBJECT, uid).catch((caught: unknown) => caught)
        expect(error).toBeInstanceOf(BadUidError)
        expect(error).toMatchObject({ name: 'BadUidError', message: 'uid override must be a canonical UUID' })
        expect((error as Error).message).not.toContain(uid)
    })
})

describe('eventId', () => {
    it.each(golden.eventIds)('gives the golden id for $case', async (entry) => {
        expect(await eventId(entry.sourceId, entry.idpEventId)).toBe(entry.expected)
    })

    it('is the same on every redelivery', async () => {
        const [a, b] = await Promise.all([eventId('clerk-acme', 'msg_1'), eventId('clerk-acme', 'msg_1')])
        expect(a).toBe(b)
        expect(a).toMatch(V5)
    })

    it('separates sources and keeps the source and event id apart', async () => {
        const ids = await Promise.all([
            eventId('clerk-acme', 'msg_1'),
            eventId('clerk-globex', 'msg_1'),
            eventId('casdoor-acme', 'new-user:a'),
            eventId('casdoor-acme', 'signup:a'),
            eventId('a', 'b,c'),
            eventId('a,b', 'c'),
        ])
        expect(new Set(ids).size).toBe(ids.length)
    })

    it('uses its own namespace, apart from user ids', async () => {
        expect(await eventId(CLERK, SUBJECT)).not.toBe(await deriveUserId(CLERK, SUBJECT))
        expect(await eventId(CLERK, SUBJECT)).toBe(await uuidV5(EVENT_ID_NAMESPACE, JSON.stringify([CLERK, SUBJECT])))
    })
})
