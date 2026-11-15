import { spawn } from 'node:child_process'
import { createServer, type Server } from 'node:http'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { afterEach, describe, expect, it } from 'vitest'
import { loadRuntime, webhookSecretName } from '../../src/runtimes/load'
import { createNodeServer } from '../../src/runtimes/node'
import { listen } from './http'

const ROOT = fileURLToPath(new URL('../..', import.meta.url).href)
const servers: Server[] = []

afterEach(() => {
    for (const server of servers.splice(0)) {
        server.closeAllConnections()
        server.close()
    }
})

interface Run {
    code: number | null
    stdout: string
    stderr: string
}

// As CI and deployers run them: plain node, which strips the types itself
function run(script: string, ...args: string[]): Promise<Run> {
    return new Promise((resolve, reject) => {
        const child = spawn(process.execPath, [join(ROOT, 'scripts', script), ...args], { cwd: ROOT })
        let stdout = ''
        let stderr = ''
        child.stdout.on('data', (chunk) => (stdout += String(chunk)))
        child.stderr.on('data', (chunk) => (stderr += String(chunk)))
        child.on('error', reject)
        child.on('close', (code) => resolve({ code, stdout, stderr }))
    })
}

async function devEnv(): Promise<Record<string, string>> {
    const { code, stdout } = await run('dev-env.ts')
    expect(code).toBe(0)
    return Object.fromEntries(
        stdout
            .trimEnd()
            .split('\n')
            .map((line) => [line.slice(0, line.indexOf('=')), line.slice(line.indexOf('=') + 1)]),
    )
}

async function bridge(env: Record<string, string | undefined>): Promise<string> {
    const { server, ready } = createNodeServer({ env, log: () => {} })
    servers.push(server)
    await ready
    return listen(server)
}

type Jwks = { keys: Record<string, unknown>[] }

// In front of a bridge, passing every answer through but the JWKS, which it edits
async function tampered(origin: string, edit: (jwks: Jwks) => Jwks): Promise<string> {
    const server = createServer(async (req, res) => {
        let body = ''
        for await (const chunk of req) body += String(chunk)
        const headers = { 'content-type': req.headers['content-type'] ?? 'text/plain' }
        const answer = await fetch(`${origin}${req.url}`, { method: req.method!, headers, ...(req.method === 'POST' && { body }) })
        let text = await answer.text()
        if (req.url === '/.well-known/jwks.json') text = JSON.stringify(edit(JSON.parse(text) as Jwks))
        res.writeHead(answer.status, { 'content-type': 'application/json' })
        res.end(text)
    })
    servers.push(server)
    return listen(server)
}

// In front of a bridge, answering 401 to a request without every one of the headers, as the ESA debug domain does
// without its access cookie
async function guarded(origin: string, required: Record<string, string>): Promise<string> {
    const server = createServer(async (req, res) => {
        let body = ''
        for await (const chunk of req) body += String(chunk)
        if (Object.entries(required).some(([name, value]) => req.headers[name] !== value)) {
            res.writeHead(401).end()
            return
        }
        const headers = { 'content-type': req.headers['content-type'] ?? 'text/plain' }
        const answer = await fetch(`${origin}${req.url}`, { method: req.method!, headers, ...(req.method === 'POST' && { body }) })
        res.writeHead(answer.status, { 'content-type': answer.headers.get('content-type') ?? 'text/plain' })
        res.end(await answer.text())
    })
    servers.push(server)
    return listen(server)
}

function hostsIn(value: unknown): string[] {
    if (typeof value === 'string') return /^https?:\/\//.test(value) ? [new URL(value).hostname] : []
    if (typeof value !== 'object' || value === null) return []
    return Object.values(value).flatMap(hostsIn)
}

describe('dev-env script', () => {
    it('prints a test configuration, a signing key and a secret per webhook source, one NAME=value per line', async () => {
        const env = await devEnv()
        const config = JSON.parse(env.BRIDGE_CONFIG!) as { webhookSources: Record<string, unknown> }
        const secretNames = Object.keys(config.webhookSources).map(webhookSecretName)

        expect(Object.keys(env)).toEqual(['BRIDGE_CONFIG', 'SIGNING_KEYS', ...secretNames])
        expect(secretNames.length).toBeGreaterThan(0)
        for (const value of Object.values(env)) expect(value).not.toMatch(/[\n#]/)
        const runtime = await loadRuntime({ config: env.BRIDGE_CONFIG, signingKeys: env.SIGNING_KEYS, webhookSecret: (id) => env[webhookSecretName(id)] })
        expect(runtime).not.toHaveProperty('reason')
    })

    it('names only hosts under .example', async () => {
        const hosts = hostsIn(JSON.parse((await devEnv()).BRIDGE_CONFIG!))

        expect(hosts.length).toBeGreaterThan(0)
        for (const host of hosts) expect(host).toMatch(/(^|\.)example$/)
    })

    it('generates a new key and secret each run', async () => {
        const [first, second] = await Promise.all([devEnv(), devEnv()])

        expect(first.SIGNING_KEYS).not.toBe(second.SIGNING_KEYS)
        expect(first.WEBHOOK_SECRET_DEV_CLERK).not.toBe(second.WEBHOOK_SECRET_DEV_CLERK)
    })
})

describe('smoke script', () => {
    it('passes against a bridge running with the dev-env values', async () => {
        const origin = await bridge(await devEnv())
        const { code, stdout } = await run('smoke.ts', origin, 'acme')

        expect(stdout).not.toMatch(/FAIL/)
        expect(stdout.match(/^ok /gm)).toHaveLength(7)
        expect(code).toBe(0)
    })

    it('accepts a base URL with a trailing slash', async () => {
        const origin = await bridge(await devEnv())

        expect((await run('smoke.ts', `${origin}/`, 'acme')).code).toBe(0)
    })

    // A JWKS that carries one has published a signing key
    it.each<[string, (jwks: Jwks) => Jwks, string]>([
        ['the EC private key d', ({ keys }) => ({ keys: keys.map((key) => ({ ...key, d: 'c2VjcmV0LXByaXZhdGUta2V5' })) }), 'd'],
        [
            'RSA private members on a second key',
            ({ keys }) => ({ keys: [...keys, { kty: 'RSA', kid: 'other', n: 'AQAB', e: 'AQAB', p: 'cHJpbWUtcA', q: 'cHJpbWUtcQ' }] }),
            'p, q',
        ],
        ['a symmetric key k', ({ keys }) => ({ keys: [...keys, { kty: 'oct', kid: 'hmac', k: 'c3ltbWV0cmlj' }] }), 'k'],
    ])('fails when a JWKS key holds %s, naming the members and quoting none of them', async (_, edit, members) => {
        const origin = await tampered(await bridge(await devEnv()), edit)
        const { code, stdout } = await run('smoke.ts', origin, 'acme')

        expect(code).toBe(1)
        expect(stdout.match(/^FAIL .*$/gm)).toEqual([expect.stringMatching(new RegExp(`^FAIL GET /\\.well-known/jwks\\.json.*private.*${members}`))])
        expect(stdout).not.toMatch(/c2VjcmV0|cHJpbWU|c3ltbWV0cmlj/)
    })

    it('fails against a bridge in failure mode, naming each mismatch', async () => {
        const { BRIDGE_CONFIG: _, ...env } = await devEnv()
        const origin = await bridge(env)
        const { code, stdout } = await run('smoke.ts', origin, 'acme')

        expect(code).toBe(1)
        expect(stdout.match(/^FAIL /gm)).toHaveLength(6)
        expect(stdout).toMatch(/^ok .*404/m)
        expect(stdout).toMatch(/^FAIL .*\/healthz.*503/m)
    })

    it('fails for a product the bridge does not serve', async () => {
        const origin = await bridge(await devEnv())
        const { code, stdout } = await run('smoke.ts', origin, 'globex')

        expect(code).toBe(1)
        expect(stdout).toMatch(/^FAIL .*junk subject token.*invalid_target/m)
    })

    it('fails when nothing answers', async () => {
        const origin = await bridge({})
        servers.splice(0).forEach((server) => server.close())
        const { code, stdout } = await run('smoke.ts', origin, 'acme')

        expect(code).toBe(1)
        expect(stdout.match(/^FAIL /gm)).toHaveLength(7)
    })

    it('prints its usage without arguments', async () => {
        const { code, stderr } = await run('smoke.ts')

        expect(code).toBe(2)
        expect(stderr).toMatch(/usage: node scripts\/smoke\.ts <base-url> <product-id>/)
    })

    describe('with --header', () => {
        const COOKIE = 'esa_er_token=c21va2UtdG9rZW4'

        it('sends the header with every request', async () => {
            const origin = await guarded(await bridge(await devEnv()), { cookie: COOKIE })
            const { code, stdout } = await run('smoke.ts', origin, 'acme', '--header', `cookie: ${COOKIE}`)

            expect(stdout).not.toMatch(/FAIL/)
            expect(stdout.match(/^ok /gm)).toHaveLength(7)
            expect(code).toBe(0)
        })

        it('sends every header given, before or after the arguments, with or without a space after the colon', async () => {
            const origin = await guarded(await bridge(await devEnv()), { cookie: COOKIE, 'x-smoke': 'yes' })
            const { code, stdout } = await run('smoke.ts', '--header', `Cookie:${COOKIE}`, origin, '--header', 'X-Smoke:  yes ', 'acme')

            expect(stdout).not.toMatch(/FAIL/)
            expect(code).toBe(0)
        })

        it('sends the cookies of several --header options as one cookie header', async () => {
            const origin = await guarded(await bridge(await devEnv()), { cookie: `${COOKIE}; other=1` })
            const { code, stdout } = await run('smoke.ts', origin, 'acme', '--header', `cookie: ${COOKIE}`, '--header', 'cookie: other=1')

            expect(stdout).not.toMatch(/FAIL/)
            expect(code).toBe(0)
        })

        it('fails every check without the header the server needs', async () => {
            const origin = await guarded(await bridge(await devEnv()), { cookie: COOKIE })
            const { code, stdout } = await run('smoke.ts', origin, 'acme')

            expect(code).toBe(1)
            expect(stdout.match(/^FAIL .*401/gm)).toHaveLength(7)
        })

        it.each([
            ['without a colon', ['--header', `cookie ${COOKIE}`]],
            ['without a name', ['--header', `: ${COOKIE}`]],
            ['with a name that is not a token', ['--header', `my cookie: ${COOKIE}`]],
            ['with a value holding a line break', ['--header', `cookie: ${COOKIE}\r\nx-other: 1`]],
            ['without its value', ['--header']],
        ])('refuses a header %s, quoting none of it', async (_, args) => {
            const { code, stdout, stderr } = await run('smoke.ts', 'http://127.0.0.1:9', 'acme', ...args)

            expect(code).toBe(2)
            expect(stderr).toMatch(/--header 'name: value'/)
            expect(stdout).toBe('')
            expect(stderr).not.toContain('c21va2U')
        })
    })
})
