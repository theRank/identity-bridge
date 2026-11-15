import { execFileSync } from 'node:child_process'
import { readFileSync, statSync } from 'node:fs'
import { join } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest'
import { clerkConfigJson } from '../helpers/config'
import { bridgeSigningKeys } from '../helpers/keys'
import { CLERK_SECRET } from '../helpers/webhooks'

const ROOT = fileURLToPath(new URL('../..', import.meta.url).href)
const BUNDLE = join(ROOT, 'dist/esa/esa.js')
// ESA's limit for a code package
const LIMIT = 4_000_000

beforeAll(() => {
    execFileSync('npm', ['run', '--silent', 'build:esa'], { cwd: ROOT, stdio: 'ignore' })
}, 60_000)

afterEach(() => {
    vi.restoreAllMocks()
})

describe('ESA bundle', () => {
    // ESA takes one file, and has no module to resolve an import against
    it('imports nothing', () => {
        const source = readFileSync(BUNDLE, 'utf8')

        expect(source).not.toMatch(/^\s*import\b/m)
        expect(source).not.toMatch(/^\s*export\b[^;]*?\bfrom\s*["']/m)
        expect(source).not.toMatch(/\bimport\s*\(/)
        expect(source).not.toMatch(/\brequire\s*\(/)
        expect(source).toMatch(/^export\s*\{[^}]*\bas default\b[^}]*\}/m)
    })

    it('stays under the code package limit', () => {
        expect(statSync(BUNDLE).size).toBeLessThan(LIMIT)
    })

    it("opens with the bridge's licence notice and the full licence of jose", () => {
        const source = readFileSync(BUNDLE, 'utf8')
        const joseLicence = readFileSync(join(ROOT, 'node_modules/jose/LICENSE.md'), 'utf8')
        const banner = source.slice(0, source.indexOf('*/', source.indexOf(joseLicence.trim())) + 2)

        expect(source.startsWith('/*!\n * identity-bridge')).toBe(true)
        expect(banner).toContain('Licensed under the Apache License, Version 2.0')
        expect(banner).toContain(joseLicence.trim())
        expect(banner).toMatch(/^Copyright \(c\) \d{4} Filip Skokan$/m)
    })

    it('serves /healthz with the env as the third argument of fetch', async () => {
        vi.spyOn(console, 'log').mockImplementation(() => {})
        const env = { BRIDGE_CONFIG: clerkConfigJson, SIGNING_KEYS: (await bridgeSigningKeys()).json, WEBHOOK_SECRET_CLERK_ACME: CLERK_SECRET }
        const { default: entry } = (await import(pathToFileURL(BUNDLE).href)) as { default: { fetch(request: Request, context: unknown, env: unknown): Promise<Response> } }

        const response = await entry.fetch(new Request('https://id.acme.example/healthz'), { waitUntil: () => {} }, env)

        expect(response.status).toBe(200)
        expect(await response.json()).toEqual({ status: 'ok' })
    })
})
