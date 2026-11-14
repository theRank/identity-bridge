import { describe, expect, it } from 'vitest'
import { parseConfig } from '../src/config'
import type { LifecycleEvent, WebhookSourceConfig } from '../src/types'
import { BadPayloadError } from '../src/webhooks/adapter'
import { clerk } from '../src/webhooks/clerk'
import { clerkConfig } from './helpers/config'
import { CLERK_NOW_MS, CLERK_SECRET, deliveryRequest, resignClerk, svixSignature, type Delivery, type Doc } from './helpers/webhooks'
import createdWithoutExternalId from './fixtures/clerk/user-created-without-external-id.json'
import created from './fixtures/clerk/user-created.json'
import deletedWithoutExternalId from './fixtures/clerk/user-deleted-without-external-id.json'
import deleted from './fixtures/clerk/user-deleted.json'
import updated from './fixtures/clerk/user-updated.json'

const SOURCE = parseConfig(JSON.stringify(clerkConfig())).webhookSources['clerk-acme']!

// The same source for an IdP that maps no uid claim, which therefore has no uidField
function sourceWithoutUid(): WebhookSourceConfig {
    const doc = clerkConfig()
    delete (doc.idps['clerk-acme'].claims as Doc).uid
    delete (doc.webhookSources['clerk-acme'] as Doc).uidField
    return parseConfig(JSON.stringify(doc)).webhookSources['clerk-acme']!
}

const ADA = 'user_2pXkLm4NqR7sT9vW1xY3zB5cD8f'
const ADA_UID = '2f6d1c8e-4b7a-4e3f-9a5d-7c1b0e9f8a6d'
const ADA_EMAIL = 'ada+clerk_test@acme.example'
const GRACE = 'user_2pXk7QmZbLr9TfWc4NvHs8YdJe1'
const GRACE_EMAIL = 'grace+clerk_test@acme.example'

const imageUrl = (fixture: Delivery) => (JSON.parse(fixture.body) as Doc).data.image_url as string
const timestampOf = (fixture: Delivery) => Number(fixture.headers['Svix-Timestamp'])

interface AuthOptions {
    nowMs?: number
    secret?: string
    headers?: Record<string, string | null>
    body?: string
}

function authenticate(delivery: Delivery, options: AuthOptions = {}): Promise<boolean> {
    const request = deliveryRequest('clerk-acme', delivery, options.headers)
    return clerk.authenticate(request, options.body ?? delivery.body, options.secret ?? CLERK_SECRET, options.nowMs ?? CLERK_NOW_MS)
}

function parse(delivery: Delivery, source: WebhookSourceConfig = SOURCE): LifecycleEvent[] {
    return clerk.parse(deliveryRequest('clerk-acme', delivery), delivery.body, source)
}

function parseEdited(edit: (event: Doc) => void, fixture: Delivery = created): Promise<LifecycleEvent[]> {
    return resignClerk(fixture, { event: edit }).then((delivery) => parse(delivery))
}

function badPayload(run: () => unknown): unknown {
    try {
        run()
    } catch (error) {
        return error
    }
    throw new Error('expected a BadPayloadError')
}

// A phone number entry as Clerk serializes it, added to a user for the phone cases
function phoneEntry(verification: Doc | null): Doc {
    return {
        backup_codes: null,
        created_at: 1794608377720,
        default_second_factor: false,
        id: 'idn_2pXkPh0nE1aBcDeFgHiJkLmNoPq',
        linked_to: [],
        object: 'phone_number',
        phone_number: '+15555550100',
        reserved: false,
        reserved_for_second_factor: false,
        updated_at: 1794608377720,
        verification,
    }
}

describe('Clerk webhooks', () => {
    describe('authenticate', () => {
        it.each([
            ['user.created', created],
            ['user.updated', updated],
            ['user.deleted', deleted],
            ['user.created without external_id', createdWithoutExternalId],
            ['user.deleted without external_id', deletedWithoutExternalId],
        ])('accepts the signed %s delivery', async (_, fixture) => {
            expect(await authenticate(fixture)).toBe(true)
        })

        it('accepts either signature while a secret is rotated', async () => {
            const previous = `whsec_${btoa('the previous test secret')}`
            const { 'Svix-Id': id, 'Svix-Timestamp': timestamp } = created.headers
            const both = `${await svixSignature(previous, id, timestamp, created.body)} ${created.headers['Svix-Signature']}`
            const headers = { 'svix-signature': both }
            expect(await authenticate(created, { headers })).toBe(true)
            expect(await authenticate(created, { headers, secret: previous })).toBe(true)
            expect(await authenticate(created, { headers, secret: `whsec_${btoa('a third test secret here')}` })).toBe(false)
        })

        it('skips entries of other versions and malformed entries', async () => {
            const signature = created.headers['Svix-Signature']
            const valid = signature.slice('v1,'.length)
            expect(await authenticate(created, { headers: { 'svix-signature': `v1a,xyz v2,${valid} ${signature}` } })).toBe(true)
            expect(await authenticate(created, { headers: { 'svix-signature': `v2,${valid}` } })).toBe(false)
            expect(await authenticate(created, { headers: { 'svix-signature': valid } })).toBe(false)
            expect(await authenticate(created, { headers: { 'svix-signature': `v1,${valid}x` } })).toBe(false)
            expect(await authenticate(created, { headers: { 'svix-signature': `v1,${valid.toLowerCase()}` } })).toBe(false)
        })

        it('rejects a tampered body', async () => {
            const body = created.body.replace('"first_name":"Bridge"', '"first_name":"Bridgf"')
            expect(body).not.toBe(created.body)
            expect(await authenticate(created, { body })).toBe(false)
        })

        it('rejects a signature made for another svix-id or timestamp', async () => {
            expect(await authenticate(created, { headers: { 'svix-id': deleted.headers['Svix-Id'] } })).toBe(false)
            expect(await authenticate(created, { headers: { 'svix-timestamp': String(timestampOf(created) + 1) } })).toBe(false)
        })

        it('rejects a delivery signed with another secret', async () => {
            expect(await authenticate(created, { secret: `whsec_${btoa('another endpoint secret!!')}` })).toBe(false)
        })

        it.each([
            ['300 s after', 300, true],
            ['301 s after', 301, false],
            ['300 s before', -300, true],
            ['301 s before', -301, false],
        ])('checks the timestamp against a clock %s it', async (_, offset, accepted) => {
            const nowMs = (timestampOf(created) + offset) * 1000
            expect(await authenticate(created, { nowMs })).toBe(accepted)
        })

        it('compares whole seconds, as Svix does', async () => {
            expect(await authenticate(created, { nowMs: (timestampOf(created) + 300) * 1000 + 999 })).toBe(true)
            expect(await authenticate(created, { nowMs: (timestampOf(created) - 300) * 1000 - 1 })).toBe(false)
        })

        it.each(['1794608378.5', '+1794608378', '1794608378e0', '0x6af6a5fa', 'now'])('rejects the timestamp %j even when signed', async (timestamp) => {
            const delivery = await resignClerk(created, { timestamp })
            expect(await authenticate(delivery, { nowMs: timestampOf(created) * 1000 })).toBe(false)
        })

        it.each(['svix-id', 'svix-timestamp', 'svix-signature'])('rejects a delivery without %s', async (name) => {
            expect(await authenticate(created, { headers: { [name]: null } })).toBe(false)
            expect(await authenticate(created, { headers: { [name]: '' } })).toBe(false)
        })

        it('takes the secret with or without its whsec_ prefix, as the Svix libraries do', async () => {
            expect(await authenticate(created, { secret: CLERK_SECRET.slice('whsec_'.length) })).toBe(true)
        })
    })

    describe('parse', () => {
        it('maps user.created to user-created with the uid and the verified primary email', () => {
            expect(parse(created)).toStrictEqual([
                {
                    idpEventId: 'msg_2pXk8AbCdEfGhIjKlMnOpQrStUv',
                    type: 'user-created',
                    subject: ADA,
                    uid: ADA_UID,
                    profile: { email: ADA_EMAIL, name: 'Bridge Test', picture: imageUrl(created) },
                },
            ])
        })

        it('maps user.updated to user-updated with the current profile', () => {
            expect(parse(updated)).toStrictEqual([
                {
                    idpEventId: 'msg_2pXk9QwErTyUiOpAsDfGhJkLzXc',
                    type: 'user-updated',
                    subject: ADA,
                    uid: ADA_UID,
                    profile: { email: ADA_EMAIL, name: 'Bridged Test', picture: imageUrl(updated) },
                },
            ])
        })

        it('maps user.deleted, which carries only the id and external_id, to user-deleted with the uid', () => {
            expect(parse(deleted)).toStrictEqual([
                { idpEventId: 'msg_2pXkA1b2C3d4E5f6G7h8I9j0KlM', type: 'user-deleted', subject: ADA, uid: ADA_UID, profile: {} },
            ])
        })

        it('passes a null external_id on, which means no override', () => {
            expect(parse(createdWithoutExternalId)).toStrictEqual([
                {
                    idpEventId: 'msg_2pXkB4nM7qW2eR5tY8uI1oP3aSd',
                    type: 'user-created',
                    subject: GRACE,
                    uid: null,
                    profile: { email: GRACE_EMAIL, name: 'Bridge Test', picture: imageUrl(createdWithoutExternalId) },
                },
            ])
        })

        it('gives no uid for a deleted user whose external_id is absent', () => {
            expect(parse(deletedWithoutExternalId)).toStrictEqual([
                { idpEventId: 'msg_2pXkC6vB9nM2lK5jH8gF1dS4aQw', type: 'user-deleted', subject: GRACE, profile: {} },
            ])
        })

        it('ignores external_id when the source has no uidField', () => {
            const source = sourceWithoutUid()
            expect(parse(created, source)[0]).not.toHaveProperty('uid')
            expect(parse(deleted, source)[0]).not.toHaveProperty('uid')
        })

        it('passes a malformed external_id on unchanged, for the user id derivation to refuse', async () => {
            const [event] = await parseEdited((event) => {
                event.data.external_id = 'admin'
            }, deleted)
            expect(event!.uid).toBe('admin')
        })

        it.each(['session.created', 'email.created', 'organization.deleted', 'user.Created', 'constructor', '__proto__', 'toString'])(
            'ignores an event of type %j',
            async (type) => {
                expect(
                    await parseEdited((event) => {
                        event.type = type
                    }),
                ).toStrictEqual([])
            },
        )

        it('ignores an unmapped event before reading its data', async () => {
            expect(
                await parseEdited((event) => {
                    event.type = 'session.created'
                    event.data = { object: 'session' }
                }),
            ).toStrictEqual([])
        })

        describe('unprocessable payloads', () => {
            it.each([
                ['not JSON', '{"data":'],
                ['JSON null', 'null'],
                ['a JSON array', '[]'],
                ['a JSON string', '"user.created"'],
            ])('rejects a body that is %s', async (_, body) => {
                const delivery = await resignClerk({ headers: created.headers, body })
                const error = badPayload(() => parse(delivery))
                expect(error).toBeInstanceOf(BadPayloadError)
                expect((error as Error).name).toBe('BadPayloadError')
            })

            it.each([
                ['without type', (event: Doc) => delete event.type],
                ['with a numeric type', (event: Doc) => (event.type = 1)],
                ['without data', (event: Doc) => delete event.data],
                ['with null data', (event: Doc) => (event.data = null)],
                ['with an array as data', (event: Doc) => (event.data = [])],
                ['with a string as data', (event: Doc) => (event.data = 'user')],
            ])('rejects an event %s', async (_, edit) => {
                const delivery = await resignClerk(created, { event: edit })
                expect(badPayload(() => parse(delivery))).toBeInstanceOf(BadPayloadError)
            })

            it.each([
                ['user.deleted without data.id', deleted, (event: Doc) => delete event.data.id],
                ['user.deleted with an empty data.id', deleted, (event: Doc) => (event.data.id = '')],
                ['user.deleted with a null data.id', deleted, (event: Doc) => (event.data.id = null)],
                ['user.created with a numeric data.id', created, (event: Doc) => (event.data.id = 42)],
                ['user.updated without data.id', updated, (event: Doc) => delete event.data.id],
            ])('rejects %s', async (_, fixture, edit) => {
                const delivery = await resignClerk(fixture, { event: edit })
                expect(badPayload(() => parse(delivery))).toBeInstanceOf(BadPayloadError)
            })

            it('gives a message that quotes nothing from the payload', async () => {
                const delivery = await resignClerk({ headers: created.headers, body: `{"secret-marker":${'x'}` })
                const deletedWithout = await resignClerk(deleted, { event: (event) => delete event.data.id })
                for (const run of [() => parse(delivery), () => parse(deletedWithout)]) {
                    const message = (badPayload(run) as Error).message
                    expect(message).not.toContain('secret-marker')
                    expect(message).not.toContain(ADA_UID)
                }
            })
        })

        describe('email', () => {
            const primary = (event: Doc) => event.data.email_addresses[0]

            it('drops the primary email when its verification is not verified', async () => {
                const [event] = await parseEdited((event) => {
                    primary(event).verification.status = 'unverified'
                })
                expect(event!.profile).toStrictEqual({ name: 'Bridge Test', picture: imageUrl(created) })
            })

            it('drops the primary email when its verification is null', async () => {
                const [event] = await parseEdited((event) => {
                    primary(event).verification = null
                })
                expect(event!.profile).not.toHaveProperty('email')
            })

            it('drops the email when no primary is set', async () => {
                const [event] = await parseEdited((event) => {
                    event.data.primary_email_address_id = null
                })
                expect(event!.profile).not.toHaveProperty('email')
            })

            it('uses only the entry the primary id names, not another verified one', async () => {
                const [event] = await parseEdited((event) => {
                    const other = { ...primary(event), id: 'idn_2pXkOtHeR0aBcDeFgHiJkLmNoPq', email_address: 'other@acme.example' }
                    other.verification = { ...other.verification, status: 'unverified' }
                    event.data.email_addresses.unshift(other)
                    event.data.primary_email_address_id = other.id
                })
                expect(event!.profile).not.toHaveProperty('email')
            })

            it('finds the primary entry anywhere in the list', async () => {
                const [event] = await parseEdited((event) => {
                    const other = { ...primary(event), id: 'idn_2pXkOtHeR0aBcDeFgHiJkLmNoPq', email_address: 'other@acme.example' }
                    event.data.email_addresses.unshift(other)
                })
                expect(event!.profile.email).toBe(ADA_EMAIL)
            })
        })

        describe('phone', () => {
            it('keeps the primary phone number when verified', async () => {
                const [event] = await parseEdited((event) => {
                    event.data.phone_numbers = [phoneEntry({ attempts: 1, expire_at: null, object: 'verification_otp', status: 'verified', strategy: 'phone_code' })]
                    event.data.primary_phone_number_id = 'idn_2pXkPh0nE1aBcDeFgHiJkLmNoPq'
                })
                expect(event!.profile.phoneNumber).toBe('+15555550100')
            })

            it.each([
                ['unverified', { attempts: 1, expire_at: null, object: 'verification_otp', status: 'unverified', strategy: 'phone_code' }],
                ['null verification', null],
            ])('drops the primary phone number with %s', async (_, verification) => {
                const [event] = await parseEdited((event) => {
                    event.data.phone_numbers = [phoneEntry(verification)]
                    event.data.primary_phone_number_id = 'idn_2pXkPh0nE1aBcDeFgHiJkLmNoPq'
                })
                expect(event!.profile).not.toHaveProperty('phoneNumber')
            })

            it('drops a verified phone number that is not the primary one', async () => {
                const [event] = await parseEdited((event) => {
                    event.data.phone_numbers = [phoneEntry({ status: 'verified' })]
                })
                expect(event!.profile).not.toHaveProperty('phoneNumber')
            })
        })

        describe('name and picture', () => {
            it.each([
                ['a null last_name', 'Ada', null, 'Ada'],
                ['a null first_name', null, 'Lovelace', 'Lovelace'],
                ['an empty last_name', 'Ada', '', 'Ada'],
                ['both names', 'Ada', 'Lovelace', 'Ada Lovelace'],
            ])('joins the names with %s', async (_, first, last, name) => {
                const [event] = await parseEdited((event) => {
                    event.data.first_name = first
                    event.data.last_name = last
                })
                expect(event!.profile.name).toBe(name)
            })

            it('gives no name when both are null', async () => {
                const [event] = await parseEdited((event) => {
                    event.data.first_name = null
                    event.data.last_name = null
                })
                expect(event!.profile).not.toHaveProperty('name')
            })

            it('drops an image_url that is not https', async () => {
                const [event] = await parseEdited((event) => {
                    event.data.image_url = 'http://img.clerk.example/ada.png'
                })
                expect(event!.profile).not.toHaveProperty('picture')
            })
        })

        it('gives a deleted event no profile, whatever its data holds', async () => {
            const [event] = await parseEdited((event) => {
                event.data.first_name = 'Ada'
                event.data.image_url = 'https://img.clerk.example/ada.png'
            }, deleted)
            expect(event!.profile).toStrictEqual({})
        })
    })
})
