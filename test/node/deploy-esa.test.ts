import { spawn } from 'node:child_process'
import { createHash, createHmac, randomBytes } from 'node:crypto'
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { crc32, inflateRawSync } from 'node:zlib'
import { afterAll, describe, expect, it, vi } from 'vitest'
import { authorization, canonicalQuery, type Io, main, parseEnvFile, zip } from '../../scripts/deploy-esa'

const SCRIPT = fileURLToPath(new URL('../../scripts/deploy-esa.ts', import.meta.url).href)
const dir = mkdtempSync(join(tmpdir(), 'identity-bridge-deploy-esa-'))

afterAll(() => rmSync(dir, { recursive: true, force: true }))

const ENDPOINT = 'esa.cn-hangzhou.aliyuncs.com'
const ACCESS_KEY_ID = 'LTAI-test-access-key-id'
const ACCESS_KEY_SECRET = 'test-access-key-secret-c2VjcmV0'
const CREDENTIALS = { ALIBABA_CLOUD_ACCESS_KEY_ID: ACCESS_KEY_ID, ALIBABA_CLOUD_ACCESS_KEY_SECRET: ACCESS_KEY_SECRET }
const NAME = 'bridge-test'
const VERSION = '1763100000000000001'
const DOMAIN = 'bridge-test-1234567890.debug.er.aliyun-esa.example'
const OSS = {
    Url: 'https://routine-upload.oss.example/',
    OSSAccessKeyId: 'STS.test-oss-key-id',
    Signature: 'dGVzdC1vc3Mtc2lnbmF0dXJl',
    Key: 'routines/bridge-test/1763100000000000001/code.zip',
    Policy: 'eyJjb25kaXRpb25zIjpbXX0=',
    XOssSecurityToken: 'test-oss-security-token',
}

// Every value holds a marker, so that a value printed in any form shows up
const marker = () => `canary${randomBytes(12).toString('hex')}`
const VALUES = {
    BRIDGE_CONFIG: JSON.stringify({ issuer: `https://${marker()}.example`, products: { acme: { tag: 'a=b' } } }),
    SIGNING_KEYS: JSON.stringify({ active: { kty: 'EC', crv: 'P-256', d: `${marker()}==` } }),
    WEBHOOK_SECRET_CLERK_ACME: `whsec_${marker()}=`,
}
const BUNDLE = Buffer.concat([Buffer.from('export default { fetch() { return new Response("ok") } }\n'), randomBytes(20_000)])

function file(name: string, content: string | Uint8Array): string {
    const path = join(dir, name)
    writeFileSync(path, content)
    return path
}

const ENV_FILE = file('bridge.env', Object.entries(VALUES).map(([name, value]) => `${name}=${value}\n`).join(''))
const BUNDLE_FILE = file('esa.js', BUNDLE)
const ARGS = ['--name', NAME, '--bundle', BUNDLE_FILE, '--env-file', ENV_FILE]

const sha256 = (data: string | Uint8Array) => createHash('sha256').update(data).digest('hex')

describe('signature V3', () => {
    // The example of Alibaba Cloud's own documentation, "Request syntax and signature method V3", section
    // "Verify your signature implementation":
    // https://www.alibabacloud.com/help/en/sdk/product-overview/v3-request-structure-and-signature
    const example = {
        method: 'POST',
        host: 'ecs.cn-shanghai.aliyuncs.com',
        query: { ImageId: 'win2019_1809_x64_dtc_zh-cn_40G_alibase_20230811.vhd', RegionId: 'cn-shanghai' },
        headers: {
            'x-acs-action': 'RunInstances',
            'x-acs-version': '2014-05-26',
            'x-acs-date': '2023-10-26T10:22:32Z',
            'x-acs-signature-nonce': '3156853299f313e23d1673dc12e1703d',
            'x-acs-content-sha256': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
        },
        body: '',
    }
    const credentials = { accessKeyId: 'YourAccessKeyId', accessKeySecret: 'YourAccessKeySecret' }
    const SIGNED = 'host;x-acs-action;x-acs-content-sha256;x-acs-date;x-acs-signature-nonce;x-acs-version'

    it('matches the example of the documentation', () => {
        expect(authorization(example, credentials)).toBe(
            `ACS3-HMAC-SHA256 Credential=YourAccessKeyId,SignedHeaders=${SIGNED},Signature=06563a9e1b43f5dfe96b81484da74bceab24a1d853912eee15083a6f0f3283c0`,
        )
    })

    it('reads header names in any case and values without surrounding spaces', () => {
        const headers = Object.fromEntries(Object.entries(example.headers).map(([name, value]) => [name.toUpperCase(), ` ${value} `]))

        expect(authorization({ ...example, headers }, credentials)).toBe(authorization(example, credentials))
    })

    it('signs content-type but not the headers the documentation leaves out', () => {
        const unsigned = { ...example, headers: { ...example.headers, accept: 'application/json', 'user-agent': 'test' } }
        const typed = { ...example, headers: { ...example.headers, 'content-type': 'application/x-www-form-urlencoded' } }

        expect(authorization(unsigned, credentials)).toBe(authorization(example, credentials))
        expect(authorization(typed, credentials)).toContain(`SignedHeaders=content-type;${SIGNED},`)
    })

    it('signs the hash of the body', () => {
        const body = 'Name=bridge-test'

        expect(authorization({ ...example, body }, credentials)).not.toBe(authorization(example, credentials))
    })

    it('encodes the query as RFC 3986 says, sorted by name', () => {
        expect(canonicalQuery({ b: 'a b', a: "*~!'()", 'c d': '', é: '/?&=+' })).toBe('a=%2A~%21%27%28%29&b=a%20b&c%20d=&%C3%A9=%2F%3F%26%3D%2B')
        expect(canonicalQuery({})).toBe('')
    })
})

// Read by the central directory, as unzip does, each entry checked against its local header and its CRC
function unzip(archive: Buffer): Map<string, Buffer> {
    const end = archive.length - 22
    expect(archive.readUInt32LE(end)).toBe(0x06054b50)
    const entries = new Map<string, Buffer>()
    let at = archive.readUInt32LE(end + 16)
    for (let index = 0; index < archive.readUInt16LE(end + 10); index++) {
        expect(archive.readUInt32LE(at)).toBe(0x02014b50)
        const method = archive.readUInt16LE(at + 10)
        const nameLength = archive.readUInt16LE(at + 28)
        const name = archive.subarray(at + 46, at + 46 + nameLength).toString()
        const offset = archive.readUInt32LE(at + 42)
        expect(archive.readUInt32LE(offset)).toBe(0x04034b50)
        expect(archive.subarray(offset + 30, offset + 30 + archive.readUInt16LE(offset + 26)).toString()).toBe(name)
        const start = offset + 30 + archive.readUInt16LE(offset + 26) + archive.readUInt16LE(offset + 28)
        const stored = archive.subarray(start, start + archive.readUInt32LE(at + 20))
        expect([0, 8]).toContain(method)
        const data = method === 8 ? inflateRawSync(stored) : stored
        expect(data.length).toBe(archive.readUInt32LE(at + 24))
        expect(crc32(data)).toBe(archive.readUInt32LE(at + 16))
        entries.set(name, data)
        at += 46 + nameLength + archive.readUInt16LE(at + 30) + archive.readUInt16LE(at + 32)
    }
    return entries
}

describe('zip', () => {
    it('holds the bundle as routine/index.js, compressed', () => {
        const archive = Buffer.from(zip('routine/index.js', BUNDLE))

        expect([...unzip(archive).keys()]).toEqual(['routine/index.js'])
        expect(unzip(archive).get('routine/index.js')!.equals(BUNDLE)).toBe(true)
        expect(archive.readUInt16LE(8)).toBe(8)
    })

    it('gives the same archive for the same bundle', () => {
        expect(Buffer.from(zip('routine/index.js', BUNDLE)).equals(Buffer.from(zip('routine/index.js', BUNDLE)))).toBe(true)
    })

    it('holds an empty file', () => {
        expect(unzip(Buffer.from(zip('routine/index.js', new Uint8Array()))).get('routine/index.js')!.length).toBe(0)
    })
})

describe('env file', () => {
    it('reads NAME=value lines, keeping every = after the first and any quotes', () => {
        const text = [
            'BRIDGE_CONFIG={"issuer":"https://id.acme.example","tag":"a=b"}',
            'SIGNING_KEYS="{\'quoted\': true}"',
            "WEBHOOK_SECRET_CLERK_ACME='whsec_abc=='",
            'WEBHOOK_SECRET_CASDOOR_2=x==',
        ].join('\n')

        expect(Object.fromEntries(parseEnvFile(text))).toEqual({
            BRIDGE_CONFIG: '{"issuer":"https://id.acme.example","tag":"a=b"}',
            SIGNING_KEYS: '"{\'quoted\': true}"',
            WEBHOOK_SECRET_CLERK_ACME: "'whsec_abc=='",
            WEBHOOK_SECRET_CASDOOR_2: 'x==',
        })
    })

    it('skips blank lines and comments, and reads CRLF line ends', () => {
        const text = '# the bridge\r\n\r\nSIGNING_KEYS={}\r\n   \r\n#WEBHOOK_SECRET_OLD=x\r\nWEBHOOK_SECRET_A=b \r\n'

        expect(Object.fromEntries(parseEnvFile(text))).toEqual({ SIGNING_KEYS: '{}', WEBHOOK_SECRET_A: 'b ' })
    })

    it('reads past a byte order mark and the spaces before a name or a comment', () => {
        const text = '﻿BRIDGE_CONFIG={}\n   # indented\n\t SIGNING_KEYS= {} \n'

        expect(Object.fromEntries(parseEnvFile(text))).toEqual({ BRIDGE_CONFIG: '{}', SIGNING_KEYS: ' {} ' })
    })

    const NOT_BRIDGE = 'line 2: not BRIDGE_CONFIG, SIGNING_KEYS or a WEBHOOK_SECRET_ name'

    // A secret pasted alone on a line can look like NAME=value, so nothing of a refused line is quoted
    it.each([
        ['another name', 'PATH=/usr/bin', 'PATH'],
        ['a name in lower case', 'bridge_config={}', 'bridge_config'],
        ['a webhook secret without a source', 'WEBHOOK_SECRET_=x', 'WEBHOOK_SECRET_='],
        ['a name that only starts like one', 'WEBHOOK_SECRETS=x', 'SECRETS'],
        ['a shell export', 'export SIGNING_KEYS={}', 'export'],
        ['a line without =', 'whsec_c2VjcmV0', 'c2VjcmV0'],
        ['a value before the =', '{"d":"c2VjcmV0"}=x', 'c2VjcmV0'],
        ['a secret alone on a line', 'whsec_c2VjcmV0==', 'c2VjcmV0'],
        ['a secret in capitals alone on a line', 'WHSEC_QzJWSkNNVjA==', 'QzJWSkNNVjA'],
        ['a secret shaped like a name', 'C2VJCMV0_QUJDREVG=R0hJSktM', 'QUJDREVG'],
    ])('refuses %s, quoting nothing of the line', (_, line, part) => {
        expect(() => parseEnvFile(`BRIDGE_CONFIG={}\n${line}\n`)).toThrow(new RegExp(`^${NOT_BRIDGE}$`))
        expect(NOT_BRIDGE).not.toContain(part)
    })

    it.each([
        ['a name set twice', 'BRIDGE_CONFIG={"x":"c2VjcmV0"}', 'line 2: BRIDGE_CONFIG is set twice'],
        ['an empty value', 'SIGNING_KEYS=', 'line 2: SIGNING_KEYS is empty'],
    ])('refuses %s, naming the bridge variable but not its value', (_, line, message) => {
        expect(() => parseEnvFile(`BRIDGE_CONFIG={}\n${line}\n`)).toThrow(new RegExp(`^${message}$`))
    })

    it('refuses a file that sets nothing', () => {
        expect(() => parseEnvFile('# nothing\n\n')).toThrow('no variable')
    })
})

interface Call {
    action: string
    method: string
    url: URL
    headers: Headers
    body: string
    query: Record<string, string>
    form: Record<string, string>
    upload?: FormData
}

type Respond = (call: Call, nth: number) => Response | undefined

const json = (status: number, body: unknown) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } })
const apiError = (status: number, Code: string, Message: string) => json(status, { RequestId: 'test-request-id', HostId: ENDPOINT, Code, Message })

interface FakeEsa {
    fetch: Io['fetch']
    calls: Call[]
    // What the routine's environments hold
    variables: Record<string, Record<string, { Type: string; Value: string }>>
}

// ESA as it answered a staging deployment, keeping the variables it is given. A test changes an answer with
// `respond`, which gives the answer to the nth call of an action, or undefined for the usual one.
function fakeEsa(respond: Respond = () => undefined, held: Record<string, { Type: string; Value: string }> = {}): FakeEsa {
    const calls: Call[] = []
    const counts = new Map<string, number>()
    const variables: FakeEsa['variables'] = { staging: { ...held }, production: { ...held } }
    const usual: Record<string, (call: Call, nth: number) => Response> = {
        GetRoutine: () => json(200, { RequestId: 'r', DefaultRelatedRecord: DOMAIN, Envs: [] }),
        CreateRoutine: () => json(200, { RequestId: 'r', Status: 'OK' }),
        SetRoutineEnvironmentVariables: (call) => {
            const set = JSON.parse(call.form.EnvironmentVariables!) as FakeEsa['variables'][string]
            Object.assign(variables[call.form.Env!]!, set)
            return json(200, { RequestId: 'r', SetKeys: Object.keys(set) })
        },
        ListRoutineEnvironmentVariables: (call) => {
            const all = Object.entries(variables[call.form.Env!]!)
            const [number, size] = [Number(call.form.PageNumber), Number(call.form.PageSize)]
            const page = all.slice((number - 1) * size, number * size)
            const answer = { RequestId: 'r', TotalCount: all.length, PageNumber: number, PageSize: size, Count: page.length }
            return json(200, { ...answer, EnvironmentVariables: Object.fromEntries(page) })
        },
        CreateRoutineWithAssetsCodeVersion: () => json(200, { RequestId: 'r', CodeVersion: VERSION, Status: 'Init', OssPostConfig: OSS }),
        OSS: () => new Response(null, { status: 204 }),
        GetRoutineCodeVersionInfo: (_, nth) => json(200, { RequestId: 'r', CodeVersion: VERSION, Status: nth === 1 ? 'Init' : 'Available' }),
        CreateRoutineCodeDeployment: (call) => json(200, { RequestId: 'r', DeploymentId: 'd-1', CodeVersions: JSON.parse(call.query.CodeVersions!) }),
    }
    const fetch: Io['fetch'] = async (url, init) => {
        const request = new Request(url, init)
        const action = request.headers.get('x-acs-action') ?? 'OSS'
        const nth = (counts.get(action) ?? 0) + 1
        counts.set(action, nth)
        const upload = action === 'OSS' ? await request.formData() : undefined
        const body = action === 'OSS' ? '' : await request.text()
        const parsed = new URL(request.url)
        const call: Call = {
            action,
            method: request.method,
            url: parsed,
            headers: request.headers,
            body,
            query: Object.fromEntries(parsed.searchParams),
            form: Object.fromEntries(new URLSearchParams(body)),
            ...(upload && { upload }),
        }
        calls.push(call)
        const answer = respond(call, nth) ?? usual[action]?.(call, nth)
        if (answer === undefined) throw new Error(`no answer for ${action}`)
        return answer
    }
    return { fetch, calls, variables }
}

// Every call of the action gets this answer instead of the usual one
function answering(action: string, answer: (call: Call) => Response): Respond {
    return (call) => (call.action === action ? answer(call) : undefined)
}

interface Ran {
    code: number
    stdout: string
    stderr: string
    // Whatever went to the process's own streams or the console rather than through Io
    direct: string
    slept: number[]
}

async function deploy(esa: FakeEsa, args = ARGS, env: Record<string, string | undefined> = CREDENTIALS): Promise<Ran> {
    let stdout = ''
    let stderr = ''
    let direct = ''
    const slept: number[] = []
    const write = ((chunk: string | Uint8Array) => {
        direct += String(chunk)
        return true
    }) as typeof process.stdout.write
    const spies = [
        vi.spyOn(process.stdout, 'write').mockImplementation(write),
        vi.spyOn(process.stderr, 'write').mockImplementation(write),
        ...(['log', 'info', 'warn', 'error', 'debug'] as const).map((method) =>
            vi.spyOn(console, method).mockImplementation((...args) => void (direct += args.join(' '))),
        ),
    ]
    try {
        const code = await main(args, {
            fetch: esa.fetch,
            env,
            stdout: (text) => void (stdout += text),
            stderr: (text) => void (stderr += text),
            sleep: async (ms) => void slept.push(ms),
        })
        return { code, stdout, stderr, direct, slept }
    } finally {
        for (const spy of spies) spy.mockRestore()
    }
}

function expectNoValue(ran: Ran, ...extra: string[]): void {
    const printed = ran.stdout + ran.stderr
    expect(ran.direct).toBe('')
    expect(printed).not.toContain('canary')
    for (const value of [...Object.values(VALUES), ACCESS_KEY_SECRET, ...extra]) expect(printed).not.toContain(value)
}

const encode = (text: string) => encodeURIComponent(text).replace(/[!'()*]/g, (char) => `%${char.charCodeAt(0).toString(16).toUpperCase()}`)

// Checked from the request as it was sent, so the query, headers and body signed are the ones that went out
function expectSigned(call: Call, host = ENDPOINT): void {
    const match = /^ACS3-HMAC-SHA256 Credential=([^,]+),SignedHeaders=([^,]+),Signature=([0-9a-f]{64})$/.exec(call.headers.get('authorization') ?? '')
    expect(match, `${call.action} authorization`).not.toBeNull()
    const [, credential, signedHeaders, signature] = match!
    const signed = signedHeaders!.split(';')
    const sent = [...call.headers.keys()].filter((name) => name === 'content-type' || name.startsWith('x-acs-'))
    expect(credential).toBe(ACCESS_KEY_ID)
    expect(signed).toEqual(['host', ...sent].sort())
    expect(call.url.host).toBe(host)
    expect(call.url.pathname).toBe('/')
    expect(call.headers.get('x-acs-version')).toBe('2024-09-10')
    expect(call.headers.get('x-acs-date')).toMatch(/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$/)
    expect(call.headers.get('x-acs-content-sha256')).toBe(sha256(call.body))
    const query = [...call.url.searchParams]
        .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
        .map(([name, value]) => `${encode(name)}=${encode(value)}`)
        .join('&')
    const value = (name: string) => (name === 'host' ? call.url.host : call.headers.get(name))
    const canonical = [call.method, '/', query, signed.map((name) => `${name}:${value(name)}\n`).join(''), signed.join(';'), sha256(call.body)].join('\n')
    expect(signature).toBe(createHmac('sha256', ACCESS_KEY_SECRET).update(`ACS3-HMAC-SHA256\n${sha256(canonical)}`).digest('hex'))
}

describe('deploy-esa', () => {
    it('creates the routine, sets the variables, uploads and deploys a version bound to the environment, in order', async () => {
        const absent = apiError(400, 'RoutineNotExist', 'The routine does not exist.')
        const esa = fakeEsa((call, nth) => (call.action === 'GetRoutine' && nth === 1 ? absent : undefined))
        const ran = await deploy(esa)

        expect(ran.code).toBe(0)
        expect(esa.calls.map((call) => call.action)).toEqual([
            'GetRoutine',
            'CreateRoutine',
            'SetRoutineEnvironmentVariables',
            'ListRoutineEnvironmentVariables',
            'CreateRoutineWithAssetsCodeVersion',
            'OSS',
            'GetRoutineCodeVersionInfo',
            'GetRoutineCodeVersionInfo',
            'CreateRoutineCodeDeployment',
            'GetRoutine',
        ])
        const [get, create, set, list, version, upload, info, , deployment, last] = esa.calls
        expect(get).toMatchObject({ method: 'GET', query: { Name: NAME }, body: '' })
        expect(create).toMatchObject({ method: 'POST', query: { Name: NAME, Description: expect.any(String) }, body: '' })
        expect(set).toMatchObject({ method: 'POST', query: {}, form: { Name: NAME, Env: 'production', EnvironmentVariables: expect.any(String) } })
        expect(set!.headers.get('content-type')).toBe('application/x-www-form-urlencoded')
        expect(JSON.parse(set!.form.EnvironmentVariables!)).toEqual({
            BRIDGE_CONFIG: { Type: 'plain_text', Value: VALUES.BRIDGE_CONFIG },
            SIGNING_KEYS: { Type: 'secret_text', Value: VALUES.SIGNING_KEYS },
            WEBHOOK_SECRET_CLERK_ACME: { Type: 'secret_text', Value: VALUES.WEBHOOK_SECRET_CLERK_ACME },
        })
        expect(list).toMatchObject({
            method: 'POST',
            query: {},
            form: { Name: NAME, Env: 'production', PageNumber: '1', PageSize: expect.stringMatching(/^\d+$/) },
        })
        expect(version).toMatchObject({ method: 'POST', query: {}, form: { Name: NAME, CodeDescription: expect.any(String), DeployEnv: 'production' } })
        expect(info).toMatchObject({ method: 'GET', query: { Name: NAME, CodeVersion: VERSION }, body: '' })
        expect(deployment).toMatchObject({ method: 'POST', query: { Name: NAME, Env: 'production', Strategy: 'percentage' }, body: '' })
        expect(JSON.parse(deployment!.query.CodeVersions!)).toEqual([{ Percentage: 100, CodeVersion: VERSION }])
        expect(last).toMatchObject({ method: 'GET', query: { Name: NAME } })
        for (const call of esa.calls.filter((call) => call.action !== 'OSS')) expectSigned(call)

        expect(upload).toMatchObject({ method: 'POST' })
        expect(upload!.url.href).toBe(OSS.Url)
        expect(upload!.headers.get('authorization')).toBeNull()
        const fields = upload!.upload!
        expect([...fields.keys()]).toEqual(['OSSAccessKeyId', 'Signature', 'x-oss-security-token', 'policy', 'key', 'file'])
        expect(Object.fromEntries([...fields].filter(([name]) => name !== 'file'))).toEqual({
            OSSAccessKeyId: OSS.OSSAccessKeyId,
            Signature: OSS.Signature,
            'x-oss-security-token': OSS.XOssSecurityToken,
            policy: OSS.Policy,
            key: OSS.Key,
        })
        const archive = Buffer.from(await (fields.get('file') as Blob).arrayBuffer())
        expect([...unzip(archive).keys()]).toEqual(['routine/index.js'])
        expect(unzip(archive).get('routine/index.js')!.equals(BUNDLE)).toBe(true)

        expect(ran.stdout).toContain(`https://${DOMAIN}`)
        expect(ran.stderr).toBe('')
        expect(ran.slept).toHaveLength(1)
        expectNoValue(ran)
    })

    it('deploys to a routine that exists without creating it, and prints its default domain', async () => {
        const esa = fakeEsa()
        const ran = await deploy(esa)

        expect(ran.code).toBe(0)
        expect(esa.calls.map((call) => call.action)).not.toContain('CreateRoutine')
        expect(esa.calls.filter((call) => call.action === 'GetRoutine')).toHaveLength(1)
        expect(ran.stdout).toContain(`https://${DOMAIN}`)
    })

    it('deploys to the environment --env names', async () => {
        const esa = fakeEsa()
        const ran = await deploy(esa, [...ARGS, '--env', 'staging'])

        expect(ran.code).toBe(0)
        const environments = esa.calls.flatMap((call) => [call.form.Env, call.form.DeployEnv, call.query.Env].filter((env) => env !== undefined))
        expect(environments).toEqual(['staging', 'staging', 'staging', 'staging'])
        expect(Object.keys(esa.variables.staging!)).toHaveLength(3)
        expect(esa.variables.production).toEqual({})
    })

    it('calls the endpoint --endpoint names', async () => {
        const esa = fakeEsa()
        const ran = await deploy(esa, [...ARGS, '--endpoint', 'esa.ap-southeast-1.api.example'])

        expect(ran.code).toBe(0)
        for (const call of esa.calls.filter((call) => call.action !== 'OSS')) expectSigned(call, 'esa.ap-southeast-1.api.example')
    })

    it('warns of bridge variables the routine holds and the file lacks, and deletes none', async () => {
        const stale = { WEBHOOK_SECRET_OLD_SOURCE: { Type: 'secret_text', Value: marker() }, OTHER_SETTING: { Type: 'plain_text', Value: marker() } }
        const esa = fakeEsa(undefined, stale)
        const ran = await deploy(esa)

        expect(ran.code).toBe(0)
        expect(ran.stderr.trimEnd().split('\n')).toEqual([expect.stringMatching(/^warning: .*WEBHOOK_SECRET_OLD_SOURCE/)])
        expect(ran.stdout + ran.stderr).not.toContain('OTHER_SETTING')
        expect(esa.calls.map((call) => call.action).filter((action) => /delete/i.test(action))).toEqual([])
        expect(Object.keys(esa.variables.production!)).toEqual(expect.arrayContaining(Object.keys(stale)))
        expectNoValue(ran, ...Object.values(stale).map((variable) => variable.Value))
    })

    it('reads every page of the variables the routine holds', async () => {
        const stale = Object.fromEntries(Array.from({ length: 120 }, (_, index) => [`WEBHOOK_SECRET_OLD_${index}`, { Type: 'secret_text', Value: marker() }]))
        const esa = fakeEsa(undefined, stale)
        const ran = await deploy(esa)

        expect(ran.code).toBe(0)
        const pages = esa.calls.filter((call) => call.action === 'ListRoutineEnvironmentVariables').map((call) => call.form.PageNumber)
        expect(pages).toEqual(Array.from({ length: pages.length }, (_, index) => String(index + 1)))
        expect(ran.stderr.match(/^warning: /gm)).toHaveLength(120)
        expectNoValue(ran, ...Object.values(stale).map((variable) => variable.Value))
    })

    it("stops at an API error, printing only the API's code and message", async () => {
        const esa = fakeEsa(answering('CreateRoutineWithAssetsCodeVersion', () => apiError(400, 'InvalidParameter', 'The specified parameter is invalid.')))
        const ran = await deploy(esa)

        expect(ran.code).toBe(1)
        expect(ran.stderr).toMatch(/CreateRoutineWithAssetsCodeVersion.*InvalidParameter.*The specified parameter is invalid\./)
        expect(ran.stderr).not.toContain('test-request-id')
        expect(esa.calls.at(-1)!.action).toBe('CreateRoutineWithAssetsCodeVersion')
        expectNoValue(ran)
    })

    it('stops at any other error reading the routine', async () => {
        const esa = fakeEsa(answering('GetRoutine', () => apiError(403, 'Forbidden.RAM', 'The user is not authorized.')))
        const ran = await deploy(esa)

        expect(ran.code).toBe(1)
        expect(ran.stderr).toMatch(/GetRoutine.*403.*Forbidden\.RAM.*not authorized/)
        expect(esa.calls.map((call) => call.action)).toEqual(['GetRoutine'])
    })

    it('stops when ESA is not activated', async () => {
        const esa = fakeEsa((call) => {
            if (call.action === 'GetRoutine') return apiError(400, 'RoutineNotExist', 'The routine does not exist.')
            if (call.action === 'CreateRoutine') return apiError(400, 'ServiceNotOpen', 'Functions and Pages is not activated.')
            return undefined
        })
        const ran = await deploy(esa)

        expect(ran.code).toBe(1)
        expect(ran.stderr).toMatch(/CreateRoutine.*ServiceNotOpen/)
        expect(esa.calls.map((call) => call.action)).toEqual(['GetRoutine', 'CreateRoutine'])
    })

    // ESA may echo a request's parameters in its message, and this request holds every value
    it('prints no value when setting the variables fails, even from a message that echoes them', async () => {
        const echo = (call: Call) => apiError(417, '400019', `Quota exceeded: ${call.body} ${call.form.EnvironmentVariables}`)
        const esa = fakeEsa(answering('SetRoutineEnvironmentVariables', echo))
        const ran = await deploy(esa)

        expect(ran.code).toBe(1)
        expect(ran.stderr).toMatch(/SetRoutineEnvironmentVariables.*417.*400019.*quota/)
        expect(esa.calls.at(-1)!.action).toBe('SetRoutineEnvironmentVariables')
        expectNoValue(ran)
    })

    it('prints no part of an answer that is not JSON', async () => {
        const esa = fakeEsa(answering('ListRoutineEnvironmentVariables', () => new Response(`{"EnvironmentVariables": ${VALUES.BRIDGE_CONFIG}`)))
        const ran = await deploy(esa)

        expect(ran.code).toBe(1)
        expect(ran.stderr).toMatch(/ListRoutineEnvironmentVariables/)
        expectNoValue(ran)
    })

    it('prints only the name of an unexpected error, whose message could quote anything', async () => {
        const broken = () => new ReadableStream({ start: (controller) => controller.error(new Error(`broken at ${VALUES.SIGNING_KEYS}`)) })
        const esa = fakeEsa(answering('ListRoutineEnvironmentVariables', () => new Response(broken())))
        const ran = await deploy(esa)

        expect(ran.code).toBe(1)
        expect(ran.stderr).toMatch(/^deploy failed: unexpected \w+\n$/)
        expectNoValue(ran)
    })

    it('stops when the API cannot be reached', async () => {
        const ran = await deploy({ ...fakeEsa(), fetch: () => Promise.reject(new TypeError('fetch failed')) })

        expect(ran.code).toBe(1)
        expect(ran.stderr).toMatch(/GetRoutine.*esa\.cn-hangzhou\.aliyuncs\.com/)
    })

    it('stops when OSS refuses the upload, before deploying', async () => {
        const refused = '<?xml version="1.0"?>\n<Error><Code>AccessDenied</Code><Message>Invalid according to Policy: Policy expired.</Message></Error>'
        const esa = fakeEsa(answering('OSS', () => new Response(refused, { status: 403, headers: { 'content-type': 'application/xml' } })))
        const ran = await deploy(esa)

        expect(ran.code).toBe(1)
        expect(ran.stderr).toMatch(/upload.*403.*AccessDenied.*Policy expired/)
        expect(esa.calls.at(-1)!.action).toBe('OSS')
    })

    it('stops when the version fails to build, before deploying', async () => {
        const esa = fakeEsa(answering('GetRoutineCodeVersionInfo', () => json(200, { CodeVersion: VERSION, Status: 'BuildFailed' })))
        const ran = await deploy(esa)

        expect(ran.code).toBe(1)
        expect(ran.stderr).toMatch(new RegExp(`${VERSION}.*BuildFailed`))
        expect(esa.calls.map((call) => call.action)).not.toContain('CreateRoutineCodeDeployment')
    })

    it('gives up on a version that stays Init, waiting between checks', async () => {
        const esa = fakeEsa(answering('GetRoutineCodeVersionInfo', () => json(200, { CodeVersion: VERSION, Status: 'Init' })))
        const ran = await deploy(esa)

        expect(ran.code).toBe(1)
        expect(ran.stderr).toMatch(new RegExp(`${VERSION}.*Init`))
        const checks = esa.calls.filter((call) => call.action === 'GetRoutineCodeVersionInfo').length
        expect(checks).toBeGreaterThan(10)
        expect(ran.slept).toHaveLength(checks - 1)
        expect(ran.slept.reduce((total, ms) => total + ms, 0)).toBeGreaterThanOrEqual(60_000)
        expect(esa.calls.map((call) => call.action)).not.toContain('CreateRoutineCodeDeployment')
    })

    describe('before calling the API', () => {
        it.each([
            ['no option', []],
            ['no --name', ARGS.slice(2)],
            ['no --bundle', [...ARGS.slice(0, 2), ...ARGS.slice(4)]],
            ['no --env-file', ARGS.slice(0, 4)],
            ['a name in capitals', ['--name', 'Bridge', ...ARGS.slice(2)]],
            ['a name with _', ['--name', 'bridge_test', ...ARGS.slice(2)]],
            ['a name starting with a digit', ['--name', '1bridge', ...ARGS.slice(2)]],
            ['a name of one letter', ['--name', 'b', ...ARGS.slice(2)]],
            ['another environment', [...ARGS, '--env', 'prod']],
            ['an endpoint that is a URL', [...ARGS, '--endpoint', 'https://esa.cn-hangzhou.aliyuncs.com']],
            ['an unknown option', [...ARGS, '--force']],
            ['an argument', [...ARGS, 'extra']],
        ])('prints the usage for %s', async (_, args) => {
            const esa = fakeEsa()
            const ran = await deploy(esa, args)

            expect(ran.code).toBe(2)
            expect(ran.stderr).toMatch(/usage: node scripts\/deploy-esa\.ts --name <routine> --bundle <esa\.js> --env-file <file>/)
            expect(ran.stdout).toBe('')
            expect(esa.calls).toEqual([])
        })

        it.each([
            ['no AccessKey', {}],
            ['no AccessKey secret', { ALIBABA_CLOUD_ACCESS_KEY_ID: ACCESS_KEY_ID }],
            ['an empty AccessKey id', { ...CREDENTIALS, ALIBABA_CLOUD_ACCESS_KEY_ID: '' }],
        ])('stops with %s', async (_, env) => {
            const esa = fakeEsa()
            const ran = await deploy(esa, ARGS, env)

            expect(ran.code).toBe(2)
            expect(ran.stderr).toMatch(/ALIBABA_CLOUD_ACCESS_KEY_ID.*ALIBABA_CLOUD_ACCESS_KEY_SECRET/)
            expect(esa.calls).toEqual([])
        })

        it('stops at an env file with a name the bridge does not read, quoting none of its values', async () => {
            const envFile = file('other.env', `BRIDGE_CONFIG=${VALUES.BRIDGE_CONFIG}\nNODE_OPTIONS=--require ${marker()}\n`)
            const esa = fakeEsa()
            const ran = await deploy(esa, ['--name', NAME, '--bundle', BUNDLE_FILE, '--env-file', envFile])

            expect(ran.code).toBe(1)
            expect(ran.stderr).toMatch(/other\.env: line 2: not BRIDGE_CONFIG, SIGNING_KEYS or a WEBHOOK_SECRET_ name\n/)
            expect(ran.stderr).not.toContain('NODE_OPTIONS')
            expect(esa.calls).toEqual([])
            expectNoValue(ran)
        })

        it.each([
            ['bundle', ['--name', NAME, '--bundle', join(dir, 'missing.js'), '--env-file', ENV_FILE]],
            ['env file', ['--name', NAME, '--bundle', BUNDLE_FILE, '--env-file', join(dir, 'missing.env')]],
        ])('stops at a %s it cannot read', async (_, args) => {
            const esa = fakeEsa()
            const ran = await deploy(esa, args)

            expect(ran.code).toBe(1)
            expect(ran.stderr).toMatch(/missing\.(js|env)/)
            expect(esa.calls).toEqual([])
        })
    })

    // As deployers run it: plain node, which strips the types itself
    it('runs with plain node, printing its usage without arguments', async () => {
        const { code, stdout, stderr } = await new Promise<{ code: number | null; stdout: string; stderr: string }>((resolve, reject) => {
            const child = spawn(process.execPath, [SCRIPT], { env: {} })
            let out = ''
            let err = ''
            child.stdout.on('data', (chunk) => (out += String(chunk)))
            child.stderr.on('data', (chunk) => (err += String(chunk)))
            child.on('error', reject)
            child.on('close', (exit) => resolve({ code: exit, stdout: out, stderr: err }))
        })

        expect(code).toBe(2)
        expect(stdout).toBe('')
        expect(stderr).toMatch(/^usage: node scripts\/deploy-esa\.ts /m)
    })
})
