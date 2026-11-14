import { type ChildProcess, execFileSync, spawn } from 'node:child_process'
import { once } from 'node:events'
import { copyFileSync, mkdtempSync, readdirSync, readFileSync, rmSync } from 'node:fs'
import { request } from 'node:http'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { createInterface } from 'node:readline'
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest'
import { clerkConfigJson } from '../helpers/config'
import { bridgeSigningKeys } from '../helpers/keys'
import { FORM } from '../helpers/runtime'
import { CLERK_SECRET } from '../helpers/webhooks'

const ROOT = new URL('../..', import.meta.url).pathname
const BUNDLE = join(ROOT, 'dist/node/server.mjs')
const keys = await bridgeSigningKeys()
const ENV = { BRIDGE_CONFIG: clerkConfigJson, SIGNING_KEYS: keys.json, WEBHOOK_SECRET_CLERK_ACME: CLERK_SECRET }

let dir: string
const children: ChildProcess[] = []

beforeAll(() => {
    execFileSync('npm', ['run', '--silent', 'build:node'], { cwd: ROOT, stdio: 'ignore' })
    // Alone in an empty directory, so nothing but the bundle and Node itself can be loaded
    dir = mkdtempSync(join(tmpdir(), 'identity-bridge-bundle-'))
    copyFileSync(BUNDLE, join(dir, 'server.mjs'))
}, 60_000)

afterEach(() => {
    for (const child of children.splice(0)) child.kill('SIGKILL')
})

afterAll(() => rmSync(dir, { recursive: true, force: true }))

interface Started {
    child: ChildProcess
    origin: string
    lines: Record<string, unknown>[]
    stderr: () => string
    // Resolves with the first stdout line that matches
    line(match: (line: Record<string, unknown>) => boolean): Promise<Record<string, unknown>>
}

// Port 0 lets the system pick one; the bundle logs the port it listens on
async function start(env: Record<string, string>): Promise<Started> {
    const child = spawn(process.execPath, ['server.mjs'], { cwd: dir, env: { PORT: '0', HOST: '127.0.0.1', ...env } })
    children.push(child)
    let stderr = ''
    child.stderr!.on('data', (chunk) => (stderr += String(chunk)))
    const lines: Record<string, unknown>[] = []
    const waiting: [(line: Record<string, unknown>) => boolean, (line: Record<string, unknown>) => void][] = []
    createInterface({ input: child.stdout! }).on('line', (text) => {
        const line = JSON.parse(text) as Record<string, unknown>
        lines.push(line)
        for (const [match, resolve] of waiting) if (match(line)) resolve(line)
    })
    const line = (match: (line: Record<string, unknown>) => boolean) =>
        new Promise<Record<string, unknown>>((resolve, reject) => {
            const seen = lines.find(match)
            if (seen) return resolve(seen)
            waiting.push([match, resolve])
            child.once('exit', (code) => reject(new Error(`exited with ${code} before the line: ${stderr}`)))
        })
    const listening = await line((entry) => entry.event === 'listening')
    return { child, origin: `http://127.0.0.1:${listening.port}`, lines, stderr: () => stderr, line }
}

describe('Node bundle', () => {
    it('imports only Node built-in modules, with jose bundled in', () => {
        const source = readFileSync(BUNDLE, 'utf8')
        const imports = [...source.matchAll(/^import\b[^'"]*["']([^"']+)["']/gm)].map(([, specifier]) => specifier!)

        expect(imports.length).toBeGreaterThan(0)
        for (const specifier of imports) expect(specifier).toMatch(/^node:/)
        expect(readdirSync(dir)).toEqual(['server.mjs'])
    })

    it('starts alone in an empty directory with plain node and answers /healthz', async () => {
        const { origin, lines } = await start(ENV)

        expect(lines[0]).toEqual({ event: 'listening', host: '127.0.0.1', port: expect.any(Number) })
        const health = await fetch(`${origin}/healthz`)
        expect(health.status).toBe(200)
        expect(await health.json()).toEqual({ status: 'ok' })
    })

    it('writes JSON lines to stdout and nothing to stderr', async () => {
        const { origin, lines, stderr, line } = await start(ENV)
        await fetch(`${origin}/healthz`)

        expect(await line((entry) => entry.route === 'health')).toMatchObject({ status: 200, outcome: 'ok' })
        expect(lines.length).toBeGreaterThanOrEqual(2)
        expect(stderr()).toBe('')
    })

    it('keeps serving in failure mode when the runtime fails to load', async () => {
        const { BRIDGE_CONFIG: _, ...withoutConfig } = ENV
        const { origin, line } = await start(withoutConfig)

        expect(await line((entry) => entry.event === 'runtime_load_failed')).toEqual({ event: 'runtime_load_failed', reason: 'missing BRIDGE_CONFIG' })
        expect((await fetch(`${origin}/healthz`)).status).toBe(503)
        expect((await fetch(`${origin}/healthz`)).status).toBe(503)
    })

    it.each(['SIGTERM', 'SIGINT'] as const)('exits cleanly on %s', async (signal) => {
        const { child, line } = await start(ENV)
        child.kill(signal)

        expect(await line((entry) => entry.event === 'stopping')).toEqual({ event: 'stopping', signal })
        const [code] = await once(child, 'exit')
        expect(code).toBe(0)
    })

    it('answers a request in flight before exiting on SIGTERM', async () => {
        const { child, origin, line } = await start(ENV)
        const held = await inFlight(origin)

        child.kill('SIGTERM')
        await line((entry) => entry.event === 'stopping')
        held.finish()

        expect(await held.answered).toEqual({ status: 400, connection: 'close' })
        const [code] = await once(child, 'exit')
        expect(code).toBe(0)
    })

    // With the exit code of a process the signal killed, as the handler stays: in a container, PID 1 ignores a
    // signal it does not handle
    it.each([
        ['SIGTERM', 'SIGTERM', 143],
        ['SIGTERM', 'SIGINT', 130],
        ['SIGINT', 'SIGINT', 130],
    ] as const)('exits at once on %s then %s, even with a request in flight, with %i', async (first, second, exitCode) => {
        const { child, origin, line } = await start(ENV)
        const held = await inFlight(origin)
        held.answered.catch(() => {})

        child.kill(first)
        await line((entry) => entry.event === 'stopping')
        child.kill(second)

        const [code, signal] = await once(child, 'exit')
        expect([code, signal]).toEqual([exitCode, null])
    })
})

// Expect: 100-continue holds the request open, its body unsent, until the server has it in hand
async function inFlight(origin: string) {
    const body = 'grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange'
    const { hostname, port } = new URL(origin)
    const req = request({
        host: hostname,
        port,
        method: 'POST',
        path: '/token',
        headers: { ...FORM, 'content-length': body.length, expect: '100-continue' },
    })
    const answered = new Promise<{ status: number; connection: string | undefined }>((resolve, reject) => {
        req.on('error', reject)
        req.on('response', (res) => {
            res.resume()
            res.on('end', () => resolve({ status: res.statusCode!, connection: res.headers.connection }))
        })
    })
    await once(req, 'continue')
    return { answered, finish: () => req.end(body) }
}
