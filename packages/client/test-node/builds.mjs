// Plain Node checks of the built package: its ES module and CommonJS builds, side by side, and the root wechat.js
import assert from 'node:assert/strict'
import { readdirSync, readFileSync } from 'node:fs'
import { createRequire } from 'node:module'
import * as esm from '@therank/identity-bridge-client'
import * as esmWechat from '@therank/identity-bridge-client/wechat'

const require = createRequire(import.meta.url)
const cjs = require('@therank/identity-bridge-client')
const cjsWechat = require('@therank/identity-bridge-client/wechat')
const file = (path) => new URL(`../${path}`, import.meta.url)
const json = (path) => JSON.parse(readFileSync(file(path), 'utf8'))

assert.match(import.meta.resolve('@therank/identity-bridge-client'), /\/dist\/index\.js$/)
assert.match(import.meta.resolve('@therank/identity-bridge-client/wechat'), /\/dist\/wechat\.js$/)
assert.match(require.resolve('@therank/identity-bridge-client'), /\/dist\/cjs\/index\.js$/)
assert.match(require.resolve('@therank/identity-bridge-client/wechat'), /\/dist\/cjs\/wechat\.js$/)
assert.equal(json('package.json').main, './dist/cjs/index.js')
// Node reads dist/cjs as CommonJS whatever the package's type
assert.deepEqual(json('dist/cjs/package.json'), { type: 'commonjs' })
// Exactly what the build emits: it empties dist/ first, so nothing stale is packed
const emitted = ['form', 'index', 'wechat'].flatMap((name) => [`${name}.js`, `${name}.d.ts`])
const expected = ['cjs', 'cjs/package.json', ...emitted, ...emitted.map((path) => `cjs/${path}`)]
assert.deepEqual(readdirSync(file('dist'), { recursive: true }).map(String).sort(), expected.sort())

const options = { url: 'https://id.acme.example', audience: 'acme', getIdpToken: async () => 'idp-token' }
for (const build of [esm, cjs]) {
    const issued = async () => ({ status: 200, body: { access_token: 'bridge-token', expires_in: 900 } })
    assert.equal(await build.createBridgeClient({ ...options, transport: issued }).getToken(), 'bridge-token')
    const refused = async () => ({ status: 400, body: { error: 'invalid_request', error_description: 'The request is malformed.' } })
    await assert.rejects(build.createBridgeClient({ ...options, transport: refused }).getToken(), (error) => {
        assert.ok(error instanceof build.BridgeError)
        assert.equal(error.name, 'BridgeError')
        assert.equal(error.status, 400)
        assert.equal(error.error, 'invalid_request')
        return true
    })
}
for (const wechat of [esmWechat, cjsWechat]) {
    assert.equal(typeof wechat.wxRequestTransport, 'function')
    assert.equal(typeof wechat.casdoorMiniProgramIdpToken, 'function')
}

// The root wechat.js, evaluated as a CommonJS loader such as WeChat devtools' does
const wechatJs = file('wechat.js')
const module = { exports: {} }
new Function('module', 'exports', 'require', readFileSync(wechatJs, 'utf8'))(module, module.exports, createRequire(wechatJs))
assert.equal(module.exports.wxRequestTransport, cjsWechat.wxRequestTransport)
assert.equal(module.exports.casdoorMiniProgramIdpToken, cjsWechat.casdoorMiniProgramIdpToken)

console.log('client builds: ok')
