import { spawn } from 'node:child_process'
import { createHash, createHmac, randomBytes } from 'node:crypto'
import { mkdtempSync, rmSync, symlinkSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { crc32, inflateRawSync } from 'node:zlib'
import { afterAll, describe, expect, it, vi } from 'vitest'
import { authorization, canonicalQuery, type Io, main, parseVarsFile, zip } from '../../scripts/deploy-esa'

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
// Documentation addresses, RFC 5737
const STAGING_IPS = ['203.0.113.10', '203.0.113.11']
const ACCESS_TOKEN = 'test-access-token-dG9rZW4'

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

const VARS_FILE = file('bridge.vars', Object.entries(VALUES).map(([name, value]) => `${name}=${value}\n`).join(''))
const BUNDLE_FILE = file('esa.js', BUNDLE)
const ARGS = ['--name', NAME, '--bundle', BUNDLE_FILE, '--vars', VARS_FILE]

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

describe('variables file', () => {
    it('reads NAME=value lines, keeping every = after the first and any quotes', () => {
        const text = [
            'BRIDGE_CONFIG={"issuer":"https://id.acme.example","tag":"a=b"}',
            'SIGNING_KEYS="{\'quoted\': true}"',
            "WEBHOOK_SECRET_CLERK_ACME='whsec_abc=='",
            'WEBHOOK_SECRET_CASDOOR_2=x==',
        ].join('\n')

        expect(Object.fromEntries(parseVarsFile(text))).toEqual({
            BRIDGE_CONFIG: '{"issuer":"https://id.acme.example","tag":"a=b"}',
            SIGNING_KEYS: '"{\'quoted\': true}"',
            WEBHOOK_SECRET_CLERK_ACME: "'whsec_abc=='",
            WEBHOOK_SECRET_CASDOOR_2: 'x==',
        })
    })

    it('skips blank lines and comments, and reads CRLF line ends', () => {
        const text = '# the bridge\r\n\r\nSIGNING_KEYS={}\r\n   \r\n#WEBHOOK_SECRET_OLD=x\r\nWEBHOOK_SECRET_A=b \r\n'

        expect(Object.fromEntries(parseVarsFile(text))).toEqual({ SIGNING_KEYS: '{}', WEBHOOK_SECRET_A: 'b ' })
    })

    it('reads past a byte order mark and the spaces before a name or a comment', () => {
        const text = '\uFEFFBRIDGE_CONFIG={}\n   # indented\n\t SIGNING_KEYS= {} \n'

        expect(Object.fromEntries(parseVarsFile(text))).toEqual({ BRIDGE_CONFIG: '{}', SIGNING_KEYS: ' {} ' })
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
        expect(() => parseVarsFile(`BRIDGE_CONFIG={}\n${line}\n`)).toThrow(new RegExp(`^${NOT_BRIDGE}$`))
        expect(NOT_BRIDGE).not.toContain(part)
    })

    it.each([
        ['a name set twice', 'BRIDGE_CONFIG={"x":"c2VjcmV0"}', 'line 2: BRIDGE_CONFIG is set twice'],
        ['an empty value', 'SIGNING_KEYS=', 'line 2: SIGNING_KEYS is empty'],
    ])('refuses %s, naming the bridge variable but not its value', (_, line, message) => {
        expect(() => parseVarsFile(`BRIDGE_CONFIG={}\n${line}\n`)).toThrow(new RegExp(`^${message}$`))
    })

    it('refuses a file that sets nothing', () => {
        expect(() => parseVarsFile('# nothing\n\n')).toThrow('no variable')
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
    signal: AbortSignal | undefined
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
        GetRoutineStagingEnvIp: () => json(200, { RequestId: 'r', IPV4: STAGING_IPS }),
        GetRoutineAccessToken: () => json(200, { RequestId: 'r', Token: ACCESS_TOKEN }),
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
            signal: init.signal ?? undefined,
        }
        calls.push(call)
        // As fetch does, rejecting with the reason of a signal that has aborted
        init.signal?.throwIfAborted()
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
    // The time limit each signal handed out stands for
    limits: Map<AbortSignal, number>
}

type Overrides = Partial<Pick<Io, 'sleep' | 'timeout'>>

// By default a signal that never aborts, so that no test waits on a real time limit
async function deploy(esa: FakeEsa, args = ARGS, env: Record<string, string | undefined> = CREDENTIALS, overrides: Overrides = {}): Promise<Ran> {
    let stdout = ''
    let stderr = ''
    let direct = ''
    const slept: number[] = []
    const limits = new Map<AbortSignal, number>()
    const timeout = overrides.timeout ?? (() => new AbortController().signal)
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
            sleep: async (ms) => {
                slept.push(ms)
                await overrides.sleep?.(ms)
            },
            timeout: (ms) => {
                const signal = timeout(ms)
                limits.set(signal, ms)
                return signal
            },
        })
        return { code, stdout, stderr, direct, slept, limits }
    } finally {
        for (const spy of spies) spy.mockRestore()
    }
}

function expectNoValue(ran: Ran, ...extra: string[]): void {
    const printed = ran.stdout + ran.stderr
    expect(ran.direct).toBe('')
    expect(printed).not.toContain('canary')
    const never = [...Object.values(VALUES), ACCESS_KEY_ID, ACCESS_KEY_SECRET, OSS.Signature, OSS.Policy, OSS.XOssSecurityToken, ...extra]
    for (const value of never) expect(printed).not.toContain(value)
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
        expect(esa.calls.map((call) => ran.limits.get(call.signal!))).toEqual(esa.calls.map((call) => (call.action === 'OSS' ? 120_000 : 30_000)))
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

    describe('after deploying', () => {
        const actions = (esa: FakeEsa) => esa.calls.map((call) => call.action)

        // The default domain resolves to production, so staging answers only on its own addresses
        it('prints the addresses staging answers on, and how to reach them', async () => {
            const esa = fakeEsa()
            const ran = await deploy(esa, [...ARGS, '--env', 'staging'])

            expect(ran.code).toBe(0)
            expect(actions(esa).slice(-2)).toEqual(['CreateRoutineCodeDeployment', 'GetRoutineStagingEnvIp'])
            expect(esa.calls.at(-1)).toMatchObject({ method: 'GET', query: {}, body: '' })
            expectSigned(esa.calls.at(-1)!)
            expect(ran.stdout).toContain(`staging addresses: ${STAGING_IPS.join(', ')}\n`)
            expect(ran.stdout).toMatch(/default domain resolves to production/)
            expect(ran.stdout).toContain(`--resolve ${DOMAIN}:443:${STAGING_IPS[0]}`)
            expect(ran.stderr).toBe('')
        })

        it('looks up no staging address for production', async () => {
            const esa = fakeEsa()
            const ran = await deploy(esa)

            expect(actions(esa)).not.toContain('GetRoutineStagingEnvIp')
            expect(ran.stdout).not.toContain(STAGING_IPS[0])
        })

        const forbidden = () => apiError(403, 'Forbidden.RAM', 'The user is not authorized.')

        it.each<[string, () => Response, RegExp]>([
            ['fails', forbidden, /^warning: .*staging addresses.*GetRoutineStagingEnvIp: HTTP 403 Forbidden\.RAM/],
            ['gives none', () => json(200, { RequestId: 'r', IPV4: [] }), /^warning: ESA gave no staging address/],
            ['gives no list', () => json(200, { RequestId: 'r' }), /^warning: ESA gave no staging address/],
        ])('only warns when the staging address lookup %s, as the deploy is done', async (_, answer, warning) => {
            const esa = fakeEsa(answering('GetRoutineStagingEnvIp', answer))
            const ran = await deploy(esa, [...ARGS, '--env', 'staging'])

            expect(ran.code).toBe(0)
            expect(ran.stderr.trimEnd().split('\n')).toEqual([expect.stringMatching(warning)])
        })

        it('prints the access token of the default domain with --print-access-token', async () => {
            const esa = fakeEsa()
            const ran = await deploy(esa, [...ARGS, '--print-access-token'])

            expect(ran.code).toBe(0)
            expect(actions(esa).at(-1)).toBe('GetRoutineAccessToken')
            expect(esa.calls.at(-1)).toMatchObject({ method: 'GET', query: { Name: NAME }, body: '' })
            expectSigned(esa.calls.at(-1)!)
            expect(ran.stdout).toContain(`access token: ${ACCESS_TOKEN}\n`)
            expect(ran.stdout).toContain(`--header 'cookie: esa_er_token=${ACCESS_TOKEN}'`)
            expect(ran.stdout).toMatch(/esa_er_token cookie/)
        })

        it('prints the token after the staging addresses', async () => {
            const esa = fakeEsa()
            const ran = await deploy(esa, [...ARGS, '--env', 'staging', '--print-access-token'])

            expect(ran.code).toBe(0)
            expect(actions(esa).slice(-3)).toEqual(['CreateRoutineCodeDeployment', 'GetRoutineStagingEnvIp', 'GetRoutineAccessToken'])
        })

        it('never asks for the token without --print-access-token', async () => {
            const esa = fakeEsa()
            const ran = await deploy(esa, [...ARGS, '--env', 'staging'])

            expect(actions(esa)).not.toContain('GetRoutineAccessToken')
            expect(ran.stdout + ran.stderr).not.toContain(ACCESS_TOKEN)
        })

        it.each<[string, () => Response, string]>([
            ['fails', forbidden, 'GetRoutineAccessToken: HTTP 403 Forbidden.RAM: The user is not authorized.'],
            ['gives none', () => json(200, { RequestId: 'r' }), 'GetRoutineAccessToken: the answer has no Token'],
        ])('stops when the token asked for %s, the deploy done', async (_, answer, message) => {
            const esa = fakeEsa(answering('GetRoutineAccessToken', answer))
            const ran = await deploy(esa, [...ARGS, '--print-access-token'])

            expect(ran.code).toBe(1)
            expect(ran.stdout).toMatch(/deployed to 100 percent/)
            expect(ran.stderr).toBe(`error: ${message}\n`)
        })
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

    describe('listing the variables', () => {
        const stale = Object.fromEntries(Array.from({ length: 60 }, (_, index) => [`WEBHOOK_SECRET_OLD_${index}`, { Type: 'secret_text', Value: marker() }]))
        const lists = (esa: FakeEsa) => esa.calls.filter((call) => call.action === 'ListRoutineEnvironmentVariables')

        // Pages of 20 whatever the size asked for, as a server may cap it
        function capped(esa: () => FakeEsa, total: boolean): Respond {
            return (call) => {
                if (call.action !== 'ListRoutineEnvironmentVariables') return undefined
                const all = Object.entries(esa().variables[call.form.Env!]!)
                const number = Number(call.form.PageNumber)
                const page = Object.fromEntries(all.slice((number - 1) * 20, number * 20))
                return json(200, { ...(total && { TotalCount: all.length }), PageNumber: number, PageSize: 20, EnvironmentVariables: page })
            }
        }

        it('follows TotalCount past pages shorter than the size asked for', async () => {
            const esa: FakeEsa = fakeEsa(capped(() => esa, true), stale)
            const ran = await deploy(esa)

            expect(ran.code).toBe(0)
            expect(ran.stderr.match(/^warning: .*WEBHOOK_SECRET_OLD_\d+/gm)).toHaveLength(60)
            expect(lists(esa).map((call) => call.form.PageNumber)).toEqual(['1', '2', '3', '4'])
        })

        it('reads to an empty page without TotalCount', async () => {
            const esa: FakeEsa = fakeEsa(capped(() => esa, false), stale)
            const ran = await deploy(esa)

            expect(ran.code).toBe(0)
            expect(ran.stderr.match(/^warning: .*WEBHOOK_SECRET_OLD_\d+/gm)).toHaveLength(60)
            expect(lists(esa).map((call) => call.form.PageNumber)).toEqual(['1', '2', '3', '4', '5'])
        })

        it('stops after 100 pages, warning that the check may be incomplete', async () => {
            const endless = answering('ListRoutineEnvironmentVariables', (call) => {
                const page = Array.from({ length: 50 }, (_, index) => [`OTHER_${call.form.PageNumber}_${index}`, { Type: 'plain_text', Value: 'x' }])
                return json(200, { EnvironmentVariables: Object.fromEntries(page) })
            })
            const esa = fakeEsa(endless)
            const ran = await deploy(esa)

            expect(ran.code).toBe(0)
            expect(lists(esa)).toHaveLength(100)
            expect(ran.stderr.trimEnd().split('\n')).toEqual([expect.stringMatching(/^warning: .*after 100 pages.*may have missed/)])
        })

        it.each<[string, unknown]>([
            ['without EnvironmentVariables', undefined],
            ['with EnvironmentVariables that is a list', [{ Key: 'WEBHOOK_SECRET_OLD', Type: 'secret_text' }]],
            ['with EnvironmentVariables that is text', 'WEBHOOK_SECRET_OLD'],
        ])('warns that the check was skipped for an answer %s', async (_, variables) => {
            const esa = fakeEsa(answering('ListRoutineEnvironmentVariables', () => json(200, { TotalCount: 1, EnvironmentVariables: variables })), stale)
            const ran = await deploy(esa)

            expect(ran.code).toBe(0)
            expect(ran.stderr.trimEnd().split('\n')).toEqual([expect.stringMatching(/^warning: .*check for stale variables was skipped/)])
            expect(lists(esa)).toHaveLength(1)
        })
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

    it('stops at an answer it cannot read, quoting nothing of the error', async () => {
        const broken = () => new ReadableStream({ start: (controller) => controller.error(new Error(`broken at ${VALUES.SIGNING_KEYS}`)) })
        const esa = fakeEsa(answering('ListRoutineEnvironmentVariables', () => new Response(broken())))
        const ran = await deploy(esa)

        expect(ran.code).toBe(1)
        expect(ran.stderr).toBe('error: ListRoutineEnvironmentVariables: the answer could not be read\n')
        expectNoValue(ran)
    })

    it('prints only the name of an unexpected error, whose message could quote anything', async () => {
        const sleep = () => Promise.reject(new RangeError(`broken at ${VALUES.SIGNING_KEYS}`))
        const ran = await deploy(fakeEsa(), ARGS, CREDENTIALS, { sleep })

        expect(ran.code).toBe(1)
        expect(ran.stderr).toBe('error: unexpected RangeError\n')
        expectNoValue(ran)
    })

    it('stops when the API cannot be reached', async () => {
        const ran = await deploy({ ...fakeEsa(), fetch: () => Promise.reject(new TypeError('fetch failed')) })

        expect(ran.code).toBe(1)
        expect(ran.stderr).toBe('error: GetRoutine: no answer from esa.cn-hangzhou.aliyuncs.com\n')
    })

    const expired = () => AbortSignal.abort(new DOMException('The operation was aborted due to timeout', 'TimeoutError'))

    it('stops when the API does not answer in time, quoting nothing of the error', async () => {
        const ran = await deploy(fakeEsa(), ARGS, CREDENTIALS, { timeout: expired })

        expect(ran.code).toBe(1)
        expect(ran.stderr).toBe('error: GetRoutine: no answer from esa.cn-hangzhou.aliyuncs.com within 30 s\n')
    })

    it('stops when the upload does not finish in time, before deploying', async () => {
        const esa = fakeEsa()
        const ran = await deploy(esa, ARGS, CREDENTIALS, { timeout: (ms) => (ms === 120_000 ? expired() : new AbortController().signal) })

        expect(ran.code).toBe(1)
        expect(ran.stderr).toBe('error: OSS upload: no answer within 120 s\n')
        expect(esa.calls.at(-1)!.action).toBe('OSS')
    })

    describe('creating the version', () => {
        const created = (fields: Record<string, unknown>) => json(200, { RequestId: 'r', CodeVersion: VERSION, Status: 'Init', OssPostConfig: OSS, ...fields })
        const uploaded = (esa: FakeEsa) => esa.calls.some((call) => call.action === 'OSS')

        // JSON.parse would round 1763100000000000001 to 1763100000000000000, another version
        it.each<[string, () => Response]>([
            ['a number', () => new Response(JSON.stringify({ CodeVersion: 'x', OssPostConfig: OSS }).replace('"x"', VERSION))],
            ['missing', () => created({ CodeVersion: undefined })],
            ['empty', () => created({ CodeVersion: '' })],
            ['an object', () => created({ CodeVersion: { Id: VERSION } })],
        ])('stops at a CodeVersion that is %s, before uploading', async (_, answer) => {
            const esa = fakeEsa(answering('CreateRoutineWithAssetsCodeVersion', answer))
            const ran = await deploy(esa)

            expect(ran.code).toBe(1)
            expect(ran.stderr).toBe('error: CreateRoutineWithAssetsCodeVersion: the answer has no CodeVersion as text\n')
            expect(uploaded(esa)).toBe(false)
        })

        it.each([
            ['an upload form over plain HTTP', { ...OSS, Url: 'http://routine-upload.oss.example/' }],
            ['no upload form', undefined],
            ['an upload form without its policy', { ...OSS, Policy: undefined }],
        ])('stops at %s, before uploading', async (_, form) => {
            const esa = fakeEsa(answering('CreateRoutineWithAssetsCodeVersion', () => created({ OssPostConfig: form })))
            const ran = await deploy(esa)

            expect(ran.code).toBe(1)
            expect(ran.stderr).toMatch(/^error: CreateRoutineWithAssetsCodeVersion: the answer has no upload form over HTTPS\n$/)
            expect(uploaded(esa)).toBe(false)
            expectNoValue(ran, OSS.Signature, OSS.Policy, OSS.XOssSecurityToken)
        })

        it('sends no security token to OSS when the form has none', async () => {
            const esa = fakeEsa(answering('CreateRoutineWithAssetsCodeVersion', () => created({ OssPostConfig: { ...OSS, XOssSecurityToken: undefined } })))
            const ran = await deploy(esa)

            expect(ran.code).toBe(0)
            const upload = esa.calls.find((call) => call.action === 'OSS')!
            expect([...upload.upload!.keys()]).toEqual(['OSSAccessKeyId', 'Signature', 'policy', 'key', 'file'])
        })
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

    describe('checking the version', () => {
        const timedOut = () => {
            throw new DOMException('The operation was aborted due to timeout', 'TimeoutError')
        }
        const failures: [string, () => Response][] = [
            ['an HTTP 503', () => apiError(503, 'ServiceUnavailable', 'The service is unavailable.')],
            ['a 502 that is not JSON', () => new Response('<html>Bad Gateway</html>', { status: 502 })],
            ['throttling', () => apiError(400, 'Throttling.User', 'Request was denied due to user flow control.')],
            [
                'a network error',
                () => {
                    throw new TypeError('fetch failed')
                },
            ],
            ['a timeout', timedOut],
        ]
        const checks = (esa: FakeEsa) => esa.calls.filter((call) => call.action === 'GetRoutineCodeVersionInfo').length

        it.each(failures)('retries a check that fails with %s', async (_, failure) => {
            const esa = fakeEsa((call, nth) => (call.action === 'GetRoutineCodeVersionInfo' && nth <= 3 ? failure() : undefined))
            const ran = await deploy(esa)

            expect(ran.code).toBe(0)
            expect(checks(esa)).toBe(4)
            expect(ran.slept).toHaveLength(3)
            expect(esa.calls.map((call) => call.action)).toContain('CreateRoutineCodeDeployment')
        })

        it.each(failures)('stops after four checks in a row fail with %s', async (_, failure) => {
            const esa = fakeEsa((call) => (call.action === 'GetRoutineCodeVersionInfo' ? failure() : undefined))
            const ran = await deploy(esa)

            expect(ran.code).toBe(1)
            expect(ran.stderr).toMatch(/^error: GetRoutineCodeVersionInfo: /)
            expect(checks(esa)).toBe(4)
            expect(esa.calls.map((call) => call.action)).not.toContain('CreateRoutineCodeDeployment')
        })

        it('counts the failures in a row only', async () => {
            const init = json(200, { CodeVersion: VERSION, Status: 'Init' })
            const failing = new Set([1, 2, 3, 5, 6, 7])
            const esa = fakeEsa((call, nth) => {
                if (call.action !== 'GetRoutineCodeVersionInfo' || nth > 7) return undefined
                return failing.has(nth) ? apiError(503, 'ServiceUnavailable', 'The service is unavailable.') : init
            })
            const ran = await deploy(esa)

            expect(ran.code).toBe(0)
            expect(checks(esa)).toBe(8)
        })

        it('stops at once on any other error', async () => {
            const esa = fakeEsa(answering('GetRoutineCodeVersionInfo', () => apiError(400, 'InvalidParameter.CodeVersion', 'The code version is invalid.')))
            const ran = await deploy(esa)

            expect(ran.code).toBe(1)
            expect(ran.stderr).toMatch(/GetRoutineCodeVersionInfo: HTTP 400 InvalidParameter\.CodeVersion/)
            expect(checks(esa)).toBe(1)
        })
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
            ['no --vars', ARGS.slice(0, 4)],
            ['a name in capitals', ['--name', 'Bridge', ...ARGS.slice(2)]],
            ['a name with _', ['--name', 'bridge_test', ...ARGS.slice(2)]],
            ['a name starting with a digit', ['--name', '1bridge', ...ARGS.slice(2)]],
            ['a name of one letter', ['--name', 'b', ...ARGS.slice(2)]],
            ['another environment', [...ARGS, '--env', 'prod']],
            ['an endpoint that is a URL', [...ARGS, '--endpoint', 'https://esa.cn-hangzhou.aliyuncs.com']],
            ['an unknown option', [...ARGS, '--force']],
            ['a value for --print-access-token', [...ARGS, '--print-access-token=yes']],
            ['--env-file, which Node takes as its own', [...ARGS.slice(0, 4), '--env-file', VARS_FILE]],
            ['an argument', [...ARGS, 'extra']],
        ])('prints the usage for %s', async (_, args) => {
            const esa = fakeEsa()
            const ran = await deploy(esa, args)

            expect(ran.code).toBe(2)
            expect(ran.stderr).toMatch(/usage: node scripts\/deploy-esa\.ts --name <routine> --bundle <esa\.js> --vars <file>/)
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

        it('stops at a variables file with a name the bridge does not read, quoting none of its values', async () => {
            const varsFile = file('other.vars', `BRIDGE_CONFIG=${VALUES.BRIDGE_CONFIG}\nNODE_OPTIONS=--require ${marker()}\n`)
            const esa = fakeEsa()
            const ran = await deploy(esa, ['--name', NAME, '--bundle', BUNDLE_FILE, '--vars', varsFile])

            expect(ran.code).toBe(1)
            expect(ran.stderr).toMatch(/other\.vars: line 2: not BRIDGE_CONFIG, SIGNING_KEYS or a WEBHOOK_SECRET_ name\n/)
            expect(ran.stderr).not.toContain('NODE_OPTIONS')
            expect(esa.calls).toEqual([])
            expectNoValue(ran)
        })

        it.each([
            ['bundle', ['--name', NAME, '--bundle', join(dir, 'missing.js'), '--vars', VARS_FILE]],
            ['variables file', ['--name', NAME, '--bundle', BUNDLE_FILE, '--vars', join(dir, 'missing.vars')]],
        ])('stops at a %s it cannot read', async (_, args) => {
            const esa = fakeEsa()
            const ran = await deploy(esa, args)

            expect(ran.code).toBe(1)
            expect(ran.stderr).toMatch(/missing\.(js|vars)/)
            expect(esa.calls).toEqual([])
        })
    })

    describe('with plain node, as deployers run it', () => {
        function run(script: string, args: string[] = [], env: Record<string, string> = {}): Promise<{ code: number | null; stdout: string; stderr: string }> {
            return new Promise((resolve, reject) => {
                const child = spawn(process.execPath, [script, ...args], { env })
                let stdout = ''
                let stderr = ''
                child.stdout.on('data', (chunk) => (stdout += String(chunk)))
                child.stderr.on('data', (chunk) => (stderr += String(chunk)))
                child.on('error', reject)
                child.on('close', (code) => resolve({ code, stdout, stderr }))
            })
        }

        it('prints its usage without arguments', async () => {
            const { code, stdout, stderr } = await run(SCRIPT)

            expect(code).toBe(2)
            expect(stdout).toBe('')
            expect(stderr).toMatch(/^usage: node scripts\/deploy-esa\.ts /m)
        })

        it('runs through a symbolic link to it', async () => {
            const link = join(dir, 'linked-deploy-esa.ts')
            symlinkSync(SCRIPT, link)
            const { code, stderr } = await run(link)

            expect(code).toBe(2)
            expect(stderr).toMatch(/^usage: node scripts\/deploy-esa\.ts /m)
        })

        // Node reads an --env-file option even after the script's name, and exits before the script for a missing file
        it('reports a variables file it cannot read itself', async () => {
            const missing = join(dir, 'missing.vars')
            const { code, stderr } = await run(SCRIPT, ['--name', NAME, '--bundle', BUNDLE_FILE, '--vars', missing], CREDENTIALS)

            expect(code).toBe(1)
            expect(stderr).toBe(`error: cannot read the variables file ${missing}: ENOENT\n`)
        })
    })
})
