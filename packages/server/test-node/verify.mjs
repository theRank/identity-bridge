// Plain Node check of the built package: a token minted here with jose, verified against a JWKS served through the
// verifier's fetch option
import assert from 'node:assert/strict'
import { readdirSync } from 'node:fs'
import { exportJWK, generateKeyPair, SignJWT } from 'jose'
import { BridgeTokenError, createVerifier } from '@therank/identity-bridge-server'

// Exactly what the build emits: it empties dist/ first, so nothing stale is packed
assert.deepEqual(readdirSync(new URL('../dist', import.meta.url)).sort(), ['index.d.ts', 'index.js'])

const issuer = 'https://id.acme.example'
const kid = 'test-key'
const { privateKey, publicKey } = await generateKeyPair('ES256')
const jwks = { keys: [{ ...(await exportJWK(publicKey)), kid, alg: 'ES256', use: 'sig' }] }

const fetched = []
const fetch = async (url) => {
    fetched.push(String(url))
    return Response.json(jwks)
}
const verifier = createVerifier({ issuer, audience: 'acme', fetch })

const now = Math.floor(Date.now() / 1000)
const userId = crypto.randomUUID()
const sign = (typ, claims) => new SignJWT(claims).setProtectedHeader({ alg: 'ES256', typ, kid }).setIssuer(issuer).setAudience('acme').setSubject(userId).setIssuedAt(now)
const accessToken = await sign('at+jwt', { client_id: 'acme', idp: 'clerk-acme', email: 'ada@acme.example', region: 'us' })
    .setJti(crypto.randomUUID())
    .setExpirationTime(now + 900)
    .sign(privateKey)

assert.deepEqual(await verifier.verifyAccessToken(accessToken), { userId, email: 'ada@acme.example', region: 'us', expiresAt: now + 900 })
const request = new Request('https://api.acme.example/me', { headers: { authorization: `Bearer ${accessToken}` } })
assert.equal((await verifier.verifyRequest(request)).userId, userId)
assert.deepEqual(fetched, [`${issuer}/.well-known/jwks.json`])

const jti = crypto.randomUUID()
const eventToken = await sign('secevent+jwt', { txn: 'msg_1', events: { 'urn:identity-bridge:event:user-deleted': {} } })
    .setJti(jti)
    .sign(privateKey)
assert.deepEqual(await verifier.verifyEvent(eventToken), { jti, type: 'user-deleted', userId, profile: {}, issuedAt: now })

await assert.rejects(verifier.verifyAccessToken(eventToken), (error) => {
    assert.ok(error instanceof BridgeTokenError)
    assert.equal(error.reason, 'wrong_type')
    assert.equal('cause' in error, false)
    return true
})

console.log('server package: ok')
