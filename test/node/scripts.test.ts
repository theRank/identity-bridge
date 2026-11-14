import { spawn } from 'node:child_process'
import type { Server } from 'node:http'
import { join } from 'node:path'
import { afterEach, describe, expect, it } from 'vitest'
import { loadRuntime, webhookSecretName } from '../../src/runtimes/load'
import { createNodeServer } from '../../src/runtimes/node'
import { listen } from './http'

const ROOT = new URL('../..', import.meta.url).pathname
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
})
