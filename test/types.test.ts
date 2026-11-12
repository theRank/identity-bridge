import { describe, expectTypeOf, it } from 'vitest'
import type { WebhookSourceConfig } from '../src/types'

// Checked by the typecheck, not at run time: each @ts-expect-error fails the build if its line compiles
describe('WebhookSourceConfig', () => {
    it('requires an organization for casdoor sources and refuses one for clerk sources', () => {
        const sources: WebhookSourceConfig[] = [
            { id: 'casdoor-acme', type: 'casdoor', idp: 'casdoor', organization: 'acme', uidField: 'uid', products: ['acme'] },
            { id: 'clerk-acme', type: 'clerk', idp: 'clerk-acme', uidField: 'external_id', products: ['acme'] },
        ]
        // @ts-expect-error a casdoor source names its organization
        const casdoor: WebhookSourceConfig = { id: 'casdoor-acme', type: 'casdoor', idp: 'casdoor', products: ['acme'] }
        // @ts-expect-error a clerk source has no organization
        const clerk: WebhookSourceConfig = { id: 'clerk-acme', type: 'clerk', idp: 'clerk-acme', organization: 'acme', products: ['acme'] }
        void [sources, casdoor, clerk]
    })

    it('gives the organization only after narrowing on type, and then always a string', () => {
        // @ts-expect-error without narrowing there is no organization to read, so a fail-open guard cannot compile
        const unnarrowed = (source: WebhookSourceConfig) => source.organization
        const narrowed = (source: WebhookSourceConfig) => (source.type === 'casdoor' ? source.organization : undefined)
        expectTypeOf<Extract<WebhookSourceConfig, { type: 'casdoor' }>['organization']>().toEqualTypeOf<string>()
        expectTypeOf(narrowed).returns.toEqualTypeOf<string | undefined>()
        void unnarrowed
    })
})
