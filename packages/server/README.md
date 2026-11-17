# @therank/identity-bridge-server

Server SDK for [identity-bridge](https://github.com/theRank/identity-bridge). It verifies, in your product's
backend, the bridge access tokens your clients send and the user lifecycle events the bridge delivers.
Clients get the tokens with
[`@therank/identity-bridge-client`](https://www.npmjs.com/package/@therank/identity-bridge-client).

Web APIs only, with [jose](https://github.com/panva/jose) as its one dependency. Runs on Node.js 22.12 or newer,
Cloudflare Workers, Deno and Bun. The package is an ES module only; see [Module format](#module-format).

## Install

```sh
npm install @therank/identity-bridge-server
```

## Usage

Create one verifier and reuse it, so the bridge's keys stay cached between requests:

```ts
import { BridgeTokenError, createVerifier } from '@therank/identity-bridge-server'

const verifier = createVerifier({
    issuer: 'https://id.acme.example', // the bridge
    audience: 'acme', // your product's id in the bridge configuration
})
```

### Access tokens

```ts
async function me(request: Request): Promise<Response> {
    let user
    try {
        user = await verifier.verifyRequest(request) // reads Authorization: Bearer <token>
    } catch (error) {
        if (!(error instanceof BridgeTokenError)) throw error
        if (error.reason === 'jwks_unavailable') return new Response(null, { status: 503 })
        return new Response(null, { status: 401, headers: { 'www-authenticate': 'Bearer' } })
    }
    return Response.json({ id: user.userId, email: user.email })
}
```

`verifyAccessToken(token)` does the same for a token you already hold.

`userId` is the user's id in the bridge, the same from every client and in every event: key your own data by
it. The token carries no roles or permissions; authorization stays in your product. The identity provider the
user signed in with is deliberately not exposed, so that no product logic depends on it.

### Events

The bridge POSTs each event to your product's events URL, the event token being the whole request body:

```ts
async function events(request: Request): Promise<Response> {
    let event
    try {
        event = await verifier.verifyEvent(await request.text())
    } catch (error) {
        if (!(error instanceof BridgeTokenError)) throw error
        return new Response(null, { status: error.reason === 'jwks_unavailable' ? 503 : 400 })
    }
    await applyOnce(event) // atomically record jti and apply the event
    return new Response(null, { status: 202 })
}
```

Implement `applyOnce` in your database: deduplicate by `jti` and apply the change in one transaction, then
answer `202`. Separate `seen` and `apply` calls can race. The bridge counts any `2xx` as delivered; other
statuses fail the delivery and let the IdP retry according to its policy. Events may arrive more than once,
out of order, or after the user's first request. See the
[event handling example](https://github.com/theRank/identity-bridge/blob/main/docs/integrate.md#consuming-events)
for deduplication and deletion handling.

## API

### `createVerifier(options)`

| Option | Type | Description |
|---|---|---|
| `issuer` | `string` | Required, not empty. The bridge's issuer URL, without a trailing slash. The keys are fetched from `${issuer}/.well-known/jwks.json`. |
| `audience` | `string` | Required, not empty. Your product's id in the bridge configuration. |
| `clockToleranceSeconds` | `number` | Leeway for `exp` and `nbf`, from `0` to `60`. Default `60`. |
| `fetch` | `typeof fetch` | Used to fetch the keys. Default: the global `fetch`. |

Invalid options throw from `createVerifier`: a `TypeError` when `issuer` or `audience` is not a non-empty
string, or when `clockToleranceSeconds` is not a number, such as the string `'30'` read from an environment
variable; a `RangeError` when `clockToleranceSeconds` is outside `0` to `60`. So a missing setting fails at
startup instead of letting other products' tokens through.

The keys are cached for 10 minutes; a token whose key is not among them makes the verifier fetch the keys
again, at most once every 30 seconds. A fetch that has not completed after 5 seconds fails.

Returns a verifier with:

- `verifyAccessToken(token: string): Promise<BridgeUser>`
- `verifyRequest(request: Request): Promise<BridgeUser>`: verifies the bearer token of the `Authorization`
  header.
- `verifyEvent(body: string): Promise<BridgeEvent>`: verifies the body of an event delivery.

An access token must be signed by a key of the bridge with ES256, have `typ` `at+jwt` (or
`application/at+jwt`), be issued by `issuer` for `audience`, carry `exp`, `iat` and `sub`, and not have
expired. An event must be signed the same way, have `typ` `secevent+jwt` (or `application/secevent+jwt`),
be issued by `issuer` for `audience`, carry `iat`, `jti` and `sub`, and hold exactly one event of a known
type. Events carry no `exp`. Both kinds of token are signed with the same keys, so the `typ` check is what
keeps an event, which never expires, from being accepted as an access token.

### `BridgeUser`

| Property | Type | Description |
|---|---|---|
| `userId` | `string` | The user's id: a lowercase UUID. |
| `email` | `string?` | Present only when the identity provider verified it. |
| `phoneNumber` | `string?` | E.164, present only when the identity provider verified it. |
| `name` | `string?` | Display name. |
| `picture` | `string?` | Avatar URL. |
| `region` | `string?` | The bridge deployment's region label, such as `us`, when it has one. |
| `expiresAt` | `number` | When the token expires, in seconds since the epoch. |

### `BridgeEvent`

| Property | Type | Description |
|---|---|---|
| `jti` | `string` | The event's id, the same on every delivery of the event. |
| `type` | `'user-created' \| 'user-updated' \| 'user-deleted'` | What happened. |
| `userId` | `string` | The user's id, as in `BridgeUser`. |
| `profile` | `{ email?, phoneNumber?, name?, picture? }` | The user's current profile, with the same rules as `BridgeUser`. Empty for `user-deleted`. |
| `issuedAt` | `number` | When the bridge signed the event, in seconds since the epoch. |

### `BridgeTokenError`

Every verification failure rejects with a `BridgeTokenError` whose `reason` says why. It has no `cause`, and
its message holds the reason alone, never the token or its claims, so it is safe to log.

Invalid options throw from `createVerifier`. Unclassified runtime errors, such as a missing
`AbortSignal.timeout`, pass through unchanged; the examples above rethrow them.

| `reason` | Meaning |
|---|---|
| `missing` | No token: an empty token, or no `Authorization: Bearer` header. |
| `malformed` | Not a well-formed token, or a time claim that is not a number. |
| `wrong_algorithm` | Not signed with ES256. |
| `unknown_key` | No single key of the bridge matches the token. |
| `bad_signature` | The signature does not verify. |
| `expired` | The token expired, beyond the clock tolerance. |
| `wrong_type` | The wrong kind of token, such as an event given to `verifyAccessToken`. |
| `wrong_issuer` | Issued by another bridge, or no issuer. |
| `wrong_audience` | Issued for another product, or no audience. |
| `invalid_claims` | A required claim is missing or invalid, the token is not valid yet, or the event is not exactly one known event. |
| `jwks_unavailable` | The bridge's keys could not be fetched or used. Try again later. |

## Module format

The package is an ES module only; `import` it. From CommonJS:

- **Node.js**: `require('@therank/identity-bridge-server')` works on Node.js 22.12 or newer, through Node's
  support for `require()` of ES modules.
- **TypeScript compiled to CommonJS**: set `module` and `moduleResolution` to `nodenext` and write `import`
  statements; TypeScript 5.8 or newer turns them into `require()` calls. With `module` set to `node16`,
  TypeScript refuses to load an ES module from CommonJS. When a bundler builds your code, `moduleResolution`
  `bundler` works too.

## License

[Apache-2.0](LICENSE)
