import { describe, expect, it } from 'vitest'
import { parseConfig } from '../src/config'
import type { LifecycleEvent, WebhookSourceConfig } from '../src/types'
import { BadPayloadError } from '../src/webhooks/adapter'
import { casdoor } from '../src/webhooks/casdoor'
import { casdoorConfig } from './helpers/config'
import { CASDOOR_SECRET, casdoorDelivery, deliveryRequest, editCasdoor, type CasdoorEdit, type CasdoorFixture, type Doc } from './helpers/webhooks'
import deleteOwnAccount from './fixtures/casdoor/delete-own-account.json'
import deleteByAdminNullProperties from './fixtures/casdoor/delete-user-by-admin-null-properties.json'
import deleteByAdmin from './fixtures/casdoor/delete-user-by-admin.json'
import deleteByAppCredentials from './fixtures/casdoor/delete-user-by-app-credentials.json'
import deleteByGlobalAdmin from './fixtures/casdoor/delete-user-by-global-admin.json'
import deleteByOtherOrgAdmin from './fixtures/casdoor/delete-user-by-other-org-admin.json'
import deleteBySelf from './fixtures/casdoor/delete-user-by-self.json'
import deniedForOtherOrgAdmin from './fixtures/casdoor/delete-user-denied-for-other-org-admin.json'
import deniedForUser from './fixtures/casdoor/delete-user-denied-for-user.json'
import deleteNoSuchUser from './fixtures/casdoor/delete-user-no-such-user.json'
import rejectedByController from './fixtures/casdoor/delete-user-rejected-by-controller.json'
import loginOauthSignup from './fixtures/casdoor/login-oauth-signup.json'
import newUserOauthSignup from './fixtures/casdoor/new-user-oauth-signup.json'
import newUserSignup from './fixtures/casdoor/new-user-signup.json'
import signup from './fixtures/casdoor/signup.json'
import updateBySelf from './fixtures/casdoor/update-user-by-self.json'

type SourceEdit = (source: Doc) => void

// casdoor-acme accepts organization acme and reads the override from properties.uid
function source(edit: SourceEdit = () => {}): WebhookSourceConfig {
    const doc = casdoorConfig()
    edit(doc.webhookSources['casdoor-acme'])
    return parseConfig(JSON.stringify(doc)).webhookSources['casdoor-acme']!
}

// The same source for an IdP that maps no uid claim, which therefore has no uidField
function sourceWithoutUid(): WebhookSourceConfig {
    const doc = casdoorConfig()
    delete (doc.idps.casdoor.claims as Doc).uid
    delete (doc.webhookSources['casdoor-acme'] as Doc).uidField
    return parseConfig(JSON.stringify(doc)).webhookSources['casdoor-acme']!
}

const SOURCE = source()

const PICTURE = 'https://cdn.casbin.org/img/casbin.svg'
// The deleted user, alice, and the organization admin who deleted her
const ALICE = 'd75162f2-693a-408e-92d1-65d71d8697e0'
const ALICE_UID = '39ca13d1-4dd9-4bdf-ad90-b2ae382c6b6c'
const ACME_ADMIN = 'a4d62447-e463-419e-9ec7-963cdb979adc'

function parse(fixture: CasdoorFixture, from: WebhookSourceConfig = SOURCE): LifecycleEvent[] {
    const delivery = casdoorDelivery(fixture)
    return casdoor.parse(deliveryRequest('casdoor-acme', delivery), delivery.body, from)
}

function parseEdited(fixture: CasdoorFixture, edit: CasdoorEdit, from: WebhookSourceConfig = SOURCE): LifecycleEvent[] {
    return parse(editCasdoor(fixture, edit), from)
}

function parseRaw(body: string): LifecycleEvent[] {
    return casdoor.parse(deliveryRequest('casdoor-acme', { headers: signup.headers, body }), body, SOURCE)
}

function badPayload(run: () => unknown): unknown {
    try {
        run()
    } catch (error) {
        return error
    }
    throw new Error('expected a BadPayloadError')
}

function authenticate(headers: Record<string, string | null>, secret = CASDOOR_SECRET): Promise<boolean> {
    const delivery = casdoorDelivery(newUserSignup)
    return casdoor.authenticate(deliveryRequest('casdoor-acme', delivery, headers), delivery.body, secret, 0)
}

describe('Casdoor webhooks', () => {
    describe('authenticate', () => {
        it('accepts the configured bearer secret', async () => {
            expect(await authenticate({})).toBe(true)
        })

        it('takes the scheme in any case', async () => {
            expect(await authenticate({ authorization: `bearer ${CASDOOR_SECRET}` })).toBe(true)
            expect(await authenticate({ authorization: `BEARER ${CASDOOR_SECRET}` })).toBe(true)
        })

        it.each([
            ['another secret', 'Bearer test-casdoor-webhook-secreT'],
            ['the secret with a suffix', `Bearer ${CASDOOR_SECRET}x`],
            ['a prefix of the secret', `Bearer ${CASDOOR_SECRET.slice(0, -1)}`],
            ['the secret without a scheme', CASDOOR_SECRET],
            ['another scheme', `Basic ${CASDOOR_SECRET}`],
            ['the scheme alone', 'Bearer'],
            ['an empty header', ''],
        ])('rejects %s', async (_, authorization) => {
            expect(await authenticate({ authorization })).toBe(false)
        })

        it('rejects a delivery without Authorization', async () => {
            expect(await authenticate({ authorization: null })).toBe(false)
        })

        it('never accepts anything for an empty secret', async () => {
            const delivery = casdoorDelivery(newUserSignup)
            const request = deliveryRequest('casdoor-acme', delivery, { authorization: 'Bearer x' })
            expect(await casdoor.authenticate(request, delivery.body, '', 0)).toBe(false)
        })
    })

    describe('parse', () => {
        describe('new-user', () => {
            it('maps a sign-up to user-created for the stored user, without an unverified email', () => {
                expect(parse(newUserSignup)).toStrictEqual([
                    {
                        idpEventId: 'new-user:89f3dfae-084b-4f66-b7a9-a18011957965',
                        type: 'user-created',
                        subject: '33d91987-4b7e-4c23-8097-01a93c1873aa',
                        profile: { name: 'Nina Signup', picture: PICTURE },
                    },
                ])
            })

            it('maps an OAuth sign-up to user-created with the provider-verified email', () => {
                expect(parse(newUserOauthSignup)).toStrictEqual([
                    {
                        idpEventId: 'new-user:4677bed3-d384-471f-b767-9f95d82f5e0c',
                        type: 'user-created',
                        subject: '7219e2b2-93de-4e9d-9dd2-dc9b73b5f62b',
                        profile: { email: 'gus@globex.example', name: 'Gus Example', picture: PICTURE },
                    },
                ])
            })

            it('reads the uid override from the stored user', () => {
                const [event] = parseEdited(newUserSignup, {
                    object: (user) => {
                        user.properties = { uid: '0b2e6d4c-9a8f-4b7e-8c6d-5e4f3a2b1c0d' }
                    },
                })
                expect(event!.uid).toBe('0b2e6d4c-9a8f-4b7e-8c6d-5e4f3a2b1c0d')
            })

            it('takes the email only when emailVerified is exactly true', () => {
                for (const emailVerified of ['true', 1, null]) {
                    const [event] = parseEdited(newUserOauthSignup, {
                        object: (user) => {
                            user.emailVerified = emailVerified
                        },
                    })
                    expect(event!.profile).not.toHaveProperty('email')
                }
            })

            it('never takes a phone number, which Casdoor stores without verification', () => {
                const [event] = parseEdited(newUserOauthSignup, {
                    object: (user) => {
                        user.phone = '+15555550100'
                        user.countryCode = 'US'
                    },
                })
                expect(event!.profile).not.toHaveProperty('phoneNumber')
            })

            it('is not subject to the admin condition of deletions', () => {
                expect(parseEdited(newUserSignup, { record: (record) => (record.extendedUser = null) })).toHaveLength(1)
            })
        })

        describe('delete-user by an admin of the organization', () => {
            it('maps to user-deleted for the deleted user, not the admin, with the uid override', () => {
                const events = parse(deleteByAdmin)
                expect(events).toStrictEqual([
                    { idpEventId: 'delete-user:7ef498bb-5664-4ec8-9fcd-62ee5f7f0d0f', type: 'user-deleted', subject: ALICE, uid: ALICE_UID, profile: {} },
                ])
                expect(JSON.stringify(events)).not.toContain(ACME_ADMIN)
            })

            it('gives no override for properties null, a user created without them', () => {
                expect(parse(deleteByAdminNullProperties)).toStrictEqual([
                    {
                        idpEventId: 'delete-user:80571e1e-3a10-4d49-89f2-46fd157ad5bd',
                        type: 'user-deleted',
                        subject: '5df95c53-cddf-4d39-82e7-0b9f39b8e1f4',
                        profile: {},
                    },
                ])
            })

            it('relays a deletion that matched no user, which Casdoor answers ok', () => {
                expect(parse(deleteNoSuchUser)).toStrictEqual([
                    {
                        idpEventId: 'delete-user:e15d4514-c969-492d-adce-387c47ce8f9c',
                        type: 'user-deleted',
                        subject: '4021c994-5bcd-472e-a39e-6c1b1552f44d',
                        profile: {},
                    },
                ])
            })

            it('rejects a body without a properties key when a uidField is configured', () => {
                const error = badPayload(() => parseEdited(deleteByAdmin, { object: (user) => delete user.properties }))
                expect(error).toBeInstanceOf(BadPayloadError)
                expect((error as Error).name).toBe('BadPayloadError')
            })

            it('needs no properties key when the source has no uidField', () => {
                const events = parseEdited(deleteByAdmin, { object: (user) => delete user.properties }, sourceWithoutUid())
                expect(events).toStrictEqual([
                    { idpEventId: 'delete-user:7ef498bb-5664-4ec8-9fcd-62ee5f7f0d0f', type: 'user-deleted', subject: ALICE, profile: {} },
                ])
            })

            it('ignores the override when the source has no uidField', () => {
                expect(parse(deleteByAdmin, sourceWithoutUid())[0]).not.toHaveProperty('uid')
            })

            it('carries no profile, whatever the body holds', () => {
                expect(parse(deleteByAdmin)[0]!.profile).toStrictEqual({})
            })
        })

        describe('records that are not relayed', () => {
            it.each([
                ['signup, which new-user follows', signup],
                ['login of an OAuth sign-up, which new-user follows', loginOauthSignup],
                ['delete-user by an admin of another organization, with a forged id', deleteByOtherOrgAdmin],
                ['delete-user by a global admin', deleteByGlobalAdmin],
                ['delete-user through application credentials, without extendedUser', deleteByAppCredentials],
                ['delete-user by the user themselves, with a forged id and properties', deleteBySelf],
                ['update-user by the user themselves, with forged properties', updateBySelf],
                ['delete-own-account', deleteOwnAccount],
                ['delete-user the controller rejected', rejectedByController],
                ['delete-user the authorization filter denied a user', deniedForUser],
                ['delete-user the authorization filter denied an admin of another organization', deniedForOtherOrgAdmin],
            ])('ignores %s', (_, fixture) => {
                expect(parse(fixture)).toStrictEqual([])
            })

            it.each([
                ['a sign-up', 'another organization', newUserSignup, (record: Doc) => (record.organization = 'globex')],
                ['a sign-up', 'a failed outcome', newUserSignup, (record: Doc) => (record.response = '{status:"error", msg:"x"}')],
                ['an OAuth sign-up', 'another organization', newUserOauthSignup, (record: Doc) => (record.organization = 'globex')],
                ['an OAuth sign-up', 'a failed outcome', newUserOauthSignup, (record: Doc) => (record.response = '{status:"error", msg:"x"}')],
            ])('ignores the new-user of %s with %s', (_flow, _filter, fixture, edit) => {
                expect(parseEdited(fixture, { record: edit })).toStrictEqual([])
            })

            it.each([
                ['another organization', (record: Doc) => (record.organization = 'globex')],
                ['the organization in another case', (record: Doc) => (record.organization = 'Acme')],
                ['a failed request', (record: Doc) => (record.response = '{status:"error", msg:"Unauthorized operation"}')],
                ['a response that only mentions ok', (record: Doc) => (record.response = '{msg:"", status:"ok"}')],
                ['an action Casdoor never sends', (record: Doc) => (record.action = 'user-created')],
                ['add-user', (record: Doc) => (record.action = 'add-user')],
                ['update-user', (record: Doc) => (record.action = 'update-user')],
            ])('ignores an admin deletion edited into %s', (_, edit) => {
                expect(parseEdited(deleteByAdmin, { record: edit })).toStrictEqual([])
            })

            it.each([
                ['null', null],
                ['not an admin', { owner: 'acme', name: 'frank', id: 'c92ba709-4772-441b-b4fa-339b0d3d35d5', isAdmin: false }],
                ['an admin of another organization', { owner: 'globex', name: 'globex-admin', id: ACME_ADMIN, isAdmin: true }],
                ['a global admin', { owner: 'built-in', name: 'admin', id: ACME_ADMIN, isAdmin: true }],
                ['isAdmin as a string', { owner: 'acme', name: 'acme-admin', id: ACME_ADMIN, isAdmin: 'true' }],
                ['isAdmin only inherited', JSON.parse('{"__proto__":{"isAdmin":true},"owner":"acme","name":"acme-admin"}')],
                ['an array', [{ owner: 'acme', isAdmin: true }]],
            ])('ignores a deletion whose extendedUser is %s', (_, extendedUser) => {
                expect(parseEdited(deleteByAdmin, { record: (record) => (record.extendedUser = extendedUser) })).toStrictEqual([])
            })

            it('ignores a deletion without extendedUser', () => {
                expect(parseEdited(deleteByAdmin, { record: (record) => delete record.extendedUser })).toStrictEqual([])
            })

            it('ignores an admin deletion of a user of another organization', () => {
                expect(parseEdited(deleteByAdmin, { object: (user) => (user.owner = 'globex') })).toStrictEqual([])
                expect(parseEdited(deleteByAdmin, { object: (user) => delete user.owner })).toStrictEqual([])
            })

            it('decides on the record before reading its object', () => {
                // delete-own-account carries a form body, not JSON
                expect(deleteOwnAccount.body.object).toBe('password=***')
                expect(parse(deleteOwnAccount)).toStrictEqual([])
                expect(parseEdited(deleteByGlobalAdmin, { record: (record) => (record.object = 'not json') })).toStrictEqual([])
                expect(parseEdited(rejectedByController, { record: (record) => (record.object = 'not json') })).toStrictEqual([])
            })
        })

        describe('unprocessable payloads', () => {
            it.each([
                ['not JSON', '{"name":'],
                ['JSON null', 'null'],
                ['a JSON array', '[]'],
                ['a JSON number', '0'],
            ])('rejects a body that is %s', (_, body) => {
                expect(badPayload(() => parseRaw(body))).toBeInstanceOf(BadPayloadError)
            })

            it.each(['name', 'action', 'organization', 'response'])('rejects a record without a string %s', (member) => {
                expect(badPayload(() => parseEdited(newUserSignup, { record: (record) => delete record[member] }))).toBeInstanceOf(BadPayloadError)
                expect(badPayload(() => parseEdited(newUserSignup, { record: (record) => (record[member] = 0) }))).toBeInstanceOf(BadPayloadError)
            })

            // An empty name would give every such record one event id
            it.each([
                ['a new-user record', newUserSignup],
                ['an admin deletion', deleteByAdmin],
                ['a signup record, before it would be ignored', signup],
            ])('rejects an empty name on %s', (_, fixture) => {
                expect(badPayload(() => parseEdited(fixture, { record: (record) => (record.name = '') }))).toBeInstanceOf(BadPayloadError)
            })

            it('rejects a record of another organization without a string action, as unprocessable before filtered', () => {
                const edit = (record: Doc) => {
                    record.organization = 'globex'
                    record.action = null
                }
                expect(badPayload(() => parseEdited(deleteByAdmin, { record: edit }))).toBeInstanceOf(BadPayloadError)
            })

            it.each([
                ['missing', (record: Doc) => delete record.object],
                ['not a string', (record: Doc) => (record.object = { id: ALICE })],
                ['not JSON', (record: Doc) => (record.object = 'password=***')],
                ['a JSON array', (record: Doc) => (record.object = '[]')],
                ['JSON null', (record: Doc) => (record.object = 'null')],
            ])('rejects a relayed record whose object is %s', (_, edit) => {
                expect(badPayload(() => parseEdited(newUserSignup, { record: edit }))).toBeInstanceOf(BadPayloadError)
                expect(badPayload(() => parseEdited(deleteByAdmin, { record: edit }))).toBeInstanceOf(BadPayloadError)
            })

            it.each([
                ['missing', (user: Doc) => delete user.id],
                ['empty', (user: Doc) => (user.id = '')],
                ['a number', (user: Doc) => (user.id = 7)],
            ])('rejects a user whose id is %s', (_, edit) => {
                expect(badPayload(() => parseEdited(newUserSignup, { object: edit }))).toBeInstanceOf(BadPayloadError)
                expect(badPayload(() => parseEdited(deleteByAdmin, { object: edit }))).toBeInstanceOf(BadPayloadError)
            })

            it.each([
                ['a string', 'not-a-map'],
                ['an array', ['39ca13d1-4dd9-4bdf-ad90-b2ae382c6b6c']],
                ['a number', 0],
            ])('rejects properties that are %s when a uidField is configured', (_, properties) => {
                expect(badPayload(() => parseEdited(deleteByAdmin, { object: (user) => (user.properties = properties) }))).toBeInstanceOf(BadPayloadError)
            })

            it('gives a message that quotes nothing from the payload', () => {
                const runs = [
                    () => parseRaw('{"secret-marker":'),
                    () => parseEdited(deleteByAdmin, { object: (user) => (user.properties = 'secret-marker') }),
                    () => parseEdited(deleteByAdmin, { record: (record) => (record.object = 'secret-marker') }),
                ]
                for (const run of runs) expect((badPayload(run) as Error).message).not.toContain('secret-marker')
            })
        })

        describe('uidField', () => {
            it.each(['constructor', 'toString', 'hasOwnProperty', '__proto__'])('reads %j only as a member of properties', (uidField) => {
                const from = source((doc) => (doc.uidField = uidField))
                expect(parseEdited(deleteByAdmin, { object: (user) => (user.properties = {}) }, from)[0]).not.toHaveProperty('uid')
                const withOverride = editCasdoor(deleteByAdmin, {
                    record: (record) => {
                        const user = JSON.parse(record.object)
                        user.properties = {}
                        record.object = JSON.stringify(user).replace('"properties":{}', `"properties":{${JSON.stringify(uidField)}:"${ALICE_UID}"}`)
                    },
                })
                expect(parse(withOverride, from)[0]!.uid).toBe(ALICE_UID)
            })

            it('passes a malformed override on unchanged, for the user id derivation to refuse', () => {
                const [event] = parseEdited(deleteByAdmin, { object: (user) => (user.properties = { uid: 'admin' }) })
                expect(event!.uid).toBe('admin')
            })
        })

        describe('event id', () => {
            it('is the action and the record name, so a sign-up and its new-user never share one', () => {
                expect(signup.body.name).toBe(newUserSignup.body.name)
                expect(parse(newUserSignup)[0]!.idpEventId).toBe(`new-user:${signup.body.name}`)
                expect(loginOauthSignup.body.name).toBe(newUserOauthSignup.body.name)
                expect(parse(newUserOauthSignup)[0]!.idpEventId).toBe(`new-user:${loginOauthSignup.body.name}`)
            })

            it('never uses the record id, which is always 0', () => {
                expect(deleteByAdmin.body.id).toBe(0)
                expect(parse(deleteByAdmin)[0]!.idpEventId).toBe(`delete-user:${deleteByAdmin.body.name}`)
            })
        })

        it('refuses a source of another type', () => {
            const clerkSource: WebhookSourceConfig = { id: 'clerk-acme', type: 'clerk', idp: 'clerk-acme', products: ['acme'] }
            expect(() => parse(deleteByAdmin, clerkSource)).toThrow(TypeError)
        })
    })
})
