import { describe, expect, it } from 'vitest'
import { loadRuntime, webhookSecretName, type RuntimeSource } from '../src/runtimes/load'
import type { Runtime, RuntimeFailure } from '../src/types'
import { casdoorConfig, casdoorConfigJson, clerkConfig, clerkConfigJson } from './helpers/config'
import { bridgeSigningKeys } from './helpers/keys'
import { CASDOOR_SECRET, CLERK_SECRET } from './helpers/webhooks'

const keys = await bridgeSigningKeys(1)

function source(overrides: Partial<RuntimeSource> = {}): RuntimeSource {
    const secrets: Record<string, string> = { 'casdoor-acme': CASDOOR_SECRET }
    return { config: casdoorConfigJson, signingKeys: keys.json, webhookSecret: (id) => secrets[id], ...overrides }
}

async function loaded(from: RuntimeSource): Promise<Runtime> {
    const runtime = await loadRuntime(from)
    if ('reason' in runtime) throw new Error(`load failed: ${runtime.reason}`)
    return runtime
}

async function failure(from: RuntimeSource): Promise<string> {
    const runtime = await loadRuntime(from)
    expect(runtime).toEqual({ reason: expect.any(String) })
    return (runtime as RuntimeFailure).reason
}

// Runs this short also occur by chance in fixed English text; longer ones would mean the value was quoted
function runsOf(value: string, length = 6): string[] {
    return Array.from({ length: Math.max(value.length - length + 1, 0) }, (_, index) => value.slice(index, index + length))
}

describe('webhookSecretName', () => {
    it('uppercases the source id and writes - as _', () => {
        expect(webhookSecretName('casdoor-acme')).toBe('WEBHOOK_SECRET_CASDOOR_ACME')
        expect(webhookSecretName('clerk-acme-2')).toBe('WEBHOOK_SECRET_CLERK_ACME_2')
        expect(webhookSecretName('acme')).toBe('WEBHOOK_SECRET_ACME')
    })
})

describe('loadRuntime', () => {
    it('parses the configuration, imports the keys and holds each source secret', async () => {
        const runtime = await loaded(source())

        expect(runtime.config.issuer).toBe('https://id.cn.acme.example')
        expect(Object.keys(runtime.config.products)).toEqual(['acme', 'globex'])
        expect(runtime.keys.jwks.keys).toHaveLength(2)
        expect(runtime.keys.kid).toBe(runtime.keys.jwks.keys[0]!.kid)
        expect(runtime.webhookSecret('casdoor-acme')).toBe(CASDOOR_SECRET)
    })

    it('asks for the secret of every configured source, by source id', async () => {
        const doc = clerkConfig()
        const second = { ...doc.webhookSources['clerk-acme'] }
        const asked: string[] = []
        const runtime = await loaded(
            source({
                config: JSON.stringify({ ...doc, webhookSources: { ...doc.webhookSources, 'clerk-acme-2': second } }),
                webhookSecret: (id) => {
                    asked.push(id)
                    return `${CLERK_SECRET}-${id}`
                },
            }),
        )

        expect(asked).toEqual(['clerk-acme', 'clerk-acme-2'])
        expect(runtime.webhookSecret('clerk-acme')).toBe(`${CLERK_SECRET}-clerk-acme`)
        expect(runtime.webhookSecret('clerk-acme-2')).toBe(`${CLERK_SECRET}-clerk-acme-2`)
    })

    it('needs no secret when no webhook source is configured', async () => {
        const doc = casdoorConfig()
        const asked: string[] = []
        await loaded(
            source({
                config: JSON.stringify({ ...doc, webhookSources: {} }),
                webhookSecret: (id) => {
                    asked.push(id)
                    return undefined
                },
            }),
        )

        expect(asked).toEqual([])
    })

    it('reads each secret once, when loading', async () => {
        const secrets: Record<string, string> = { 'clerk-acme': CLERK_SECRET }
        const runtime = await loaded(source({ config: clerkConfigJson, webhookSecret: (id) => secrets[id] }))
        secrets['clerk-acme'] = 'whsec_changed'

        expect(runtime.webhookSecret('clerk-acme')).toBe(CLERK_SECRET)
    })

    it('has no secret for a source the configuration does not name, and says so without quoting one', async () => {
        const runtime = await loaded(source())
        let message = ''
        try {
            runtime.webhookSecret('clerk-acme')
        } catch (error) {
            message = (error as Error).message
        }

        expect(message).not.toBe('')
        expect(message).not.toContain(CASDOOR_SECRET)
    })

    it('is frozen', async () => {
        expect(Object.isFrozen(await loaded(source()))).toBe(true)
    })

    describe('fails', () => {
        it.each([
            ['absent', undefined],
            ['empty', ''],
        ])('without a configuration (%s)', async (_, config) => {
            expect(await failure(source({ config }))).toBe('missing BRIDGE_CONFIG')
        })

        it('on an invalid configuration, naming its path', async () => {
            const doc = clerkConfig()
            doc.products.acme.idps[0]!.idp = 'clerk-acm'

            expect(await failure(source({ config: JSON.stringify(doc) }))).toBe('config: products.acme.idps[0].idp: unknown idp "clerk-acm"')
        })

        it('on a configuration that is not JSON', async () => {
            expect(await failure(source({ config: '{"issuer": ' }))).toBe('config: invalid JSON')
        })

        it.each([
            ['absent', undefined],
            ['empty', ''],
        ])('without signing keys (%s)', async (_, signingKeys) => {
            expect(await failure(source({ signingKeys }))).toBe('missing SIGNING_KEYS')
        })

        it('on a broken key, naming the member', async () => {
            const { d: _, ...publicOnly } = keys.active

            expect(await failure(source({ signingKeys: JSON.stringify({ active: publicOnly }) }))).toBe('SIGNING_KEYS.active: private key required')
        })

        it('on signing keys that are not JSON, quoting no part of the key', async () => {
            const truncated = keys.json.slice(0, -2)
            const reason = await failure(source({ signingKeys: truncated }))

            expect(reason).toBe('SIGNING_KEYS: invalid JSON')
            for (const run of runsOf(keys.active.d!)) expect(reason).not.toContain(run)
        })

        it.each([
            ['absent', undefined],
            ['empty', ''],
        ])('without the secret of a configured source (%s)', async (_, secret) => {
            expect(await failure(source({ webhookSecret: () => secret }))).toBe('missing webhook secret for source casdoor-acme')
        })

        it('names the first missing secret', async () => {
            const doc = clerkConfig()
            const config = JSON.stringify({ ...doc, webhookSources: { ...doc.webhookSources, 'clerk-acme-2': doc.webhookSources['clerk-acme'] } })
            const secrets: Record<string, string> = { 'clerk-acme': CLERK_SECRET }

            expect(await failure(source({ config, webhookSecret: (id) => secrets[id] }))).toBe('missing webhook secret for source clerk-acme-2')
        })

        it('on the configuration first, then the keys, then the secrets', async () => {
            expect(await failure({ webhookSecret: () => undefined })).toBe('missing BRIDGE_CONFIG')
            expect(await failure({ config: casdoorConfigJson, webhookSecret: () => undefined })).toBe('missing SIGNING_KEYS')
        })

        it('on an unexpected error, never passing its message on', async () => {
            const reason = await failure(
                source({
                    webhookSecret: () => {
                        throw new Error(`cannot read ${CASDOOR_SECRET}`)
                    },
                }),
            )

            expect(reason).toBe('unexpected error')
        })

        it('without rejecting', async () => {
            await expect(loadRuntime(source({ config: 'null' }))).resolves.toEqual({ reason: expect.any(String) })
        })
    })
})
