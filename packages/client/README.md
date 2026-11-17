# @therank/identity-bridge-client

Client SDK for [identity-bridge](https://github.com/theRank/identity-bridge). It exchanges your identity
provider's token for a bridge access token and caches it in memory. `getToken()` refreshes it when needed;
there is no background refresh. Your backend verifies the bridge token, for example with
[`@therank/identity-bridge-server`](https://www.npmjs.com/package/@therank/identity-bridge-server).

No dependencies. Runs in browsers with ES2017 and `fetch`, Node.js 22 or newer, and WeChat mini programs.

## Install

```sh
npm install @therank/identity-bridge-client
```

## Usage

### Browser

```ts
import { createBridgeClient } from '@therank/identity-bridge-client'

const bridge = createBridgeClient({
    url: 'https://id.acme.example', // the bridge
    audience: 'acme', // your product's id in the bridge configuration
    getIdpToken: () => idp.getToken(), // a fresh token from your identity provider's SDK
})

const response = await fetch('https://api.acme.example/me', {
    headers: { authorization: `Bearer ${await bridge.getToken()}` },
})

// On sign-out
bridge.clear()
```

Call `getToken()` before each request to your backend: it answers from memory while the token is fresh. The
bridge lets a browser read its answers only from the origins listed for the product in the bridge
configuration.

### Node.js

Node.js 22 or newer has a global `fetch`, so usage is the same. Both `import` and `require` work:

```js
const { createBridgeClient } = require('@therank/identity-bridge-client')
```

### WeChat mini programs

Mini programs have no `fetch`. The `wechat` entry point sends requests with `wx.request` and signs the user in
through Casdoor's WeChat mini program login:

```js
const { createBridgeClient } = require('@therank/identity-bridge-client')
const { casdoorMiniProgramIdpToken, wxRequestTransport } = require('@therank/identity-bridge-client/wechat')

const bridge = createBridgeClient({
    url: 'https://id.cn.acme.example',
    audience: 'acme',
    getIdpToken: casdoorMiniProgramIdpToken({
        casdoorUrl: 'https://casdoor.example',
        clientId: 'your-casdoor-application-client-id',
    }),
    transport: wxRequestTransport,
})
```

`casdoorMiniProgramIdpToken` calls `wx.login` for a code and exchanges it at Casdoor for a Casdoor access
token. The WeChat app secret stays in Casdoor's WeChat mini program provider; the mini program needs only the
client id of the Casdoor application. Of Casdoor's answer only the access token or the error is read; nothing
else, WeChat's session key included, is read, kept or logged.

A mini program must meet these constraints:

- **Server domains**: add both the bridge's domain and Casdoor's domain to the mini program's server
  domains. WeChat only lets a mini program call HTTPS domains listed there, and those domains need ICP
  filing.
- **JavaScript version**: the SDK is ES2017, async functions included. Use a base library version that runs
  ES2017, or turn on the WeChat devtools option that compiles JS to ES5.
- **npm**: after installing the package, build npm in WeChat devtools. The package's `main` and its
  `wechat.js` point at its CommonJS build.

## How it works

- **Exchange.** `getToken()` calls `getIdpToken()` and POSTs the token to `${url}/token` as an
  [RFC 8693](https://www.rfc-editor.org/rfc/rfc8693) token exchange for `audience`.
- **Cache.** The bridge token is kept in memory only, never in storage. It is reused while more than
  `min(refreshBeforeSeconds, expires_in / 2)` seconds of its lifetime remain; after that the next call
  exchanges a fresh IdP token. The lifetime is counted from when the answer arrives, by the client's own
  wall clock (`now`, `Date.now` by default), so a device clock that is merely set wrong does not matter. A
  clock that jumps backwards while a token is cached can, however, keep the token in use past its real
  expiry, and your backend then rejects it as `expired`. Pass `now` to use another clock.
- **One exchange at a time.** Calls made while an exchange is in flight wait for that exchange.
- **Retries.** When no answer arrives, or the bridge answers `503 temporarily_unavailable`, the request is
  sent again twice, after 250 ms and then 1 s, with the same IdP token. Other errors are thrown at once.
- **Fallback.** If a refresh fails with `network` or `temporarily_unavailable`, callers receive the cached
  token only while it remains valid by the client's clock and has not been cleared. The next call retries
  the refresh. Other failures, including `getIdpToken()` failures, are thrown.
- **Failures are not cached.** After a failed exchange, the next call starts a new one.

## API

### `createBridgeClient(options)`

| Option | Type | Description |
|---|---|---|
| `url` | `string` | Required. The bridge's issuer URL, without a trailing slash. |
| `audience` | `string` | Required. Your product's id in the bridge configuration. |
| `getIdpToken` | `() => Promise<string>` | Required. Returns a fresh identity provider token on every call. If it rejects, `getToken()` rejects with the same error. |
| `transport` | `Transport` | How requests are sent. Default: the global `fetch`. |
| `refreshBeforeSeconds` | `number` | How long before expiry to exchange again, capped at half the token's lifetime. Default `60`. A negative value throws a `RangeError`. |
| `now` | `() => number` | The clock, in milliseconds since the epoch. Default `Date.now`. |

An option given as `undefined` takes its default.

Returns a client with:

- `getToken(): Promise<string>`: the bridge access token, from memory or from a new exchange, or the cached
  token while the bridge cannot be reached, as described above.
- `clear(): void`: forgets the token, for sign-out. An exchange already in flight still resolves for the
  calls waiting on it, but its token is not kept; the next call starts a new exchange.

### `Transport`

```ts
type Transport = (request: { url: string; body: string }) => Promise<{ status: number; body: unknown }>
```

POSTs `body`, an `application/x-www-form-urlencoded` string, to `url`, and resolves with the HTTP status and
the parsed JSON answer whatever the status. It rejects only when no answer arrives.

### `wxRequestTransport` (from `/wechat`)

A `Transport` over `wx.request`. It rejects with an `Error` holding `wx.request`'s `errMsg` when the request
fails.

### `casdoorMiniProgramIdpToken(options)` (from `/wechat`)

Returns a `getIdpToken` function for mini programs that sign in through Casdoor.

| Option | Type | Description |
|---|---|---|
| `casdoorUrl` | `string` | Required. The Casdoor server, without a trailing slash. |
| `clientId` | `string` | Required. The client id of the Casdoor application. |
| `transport` | `Transport` | Default: `wxRequestTransport`. |

Each call gets a new `wx.login` code and POSTs `client_id`, `code` and `tag=wechat_miniprogram` to
`${casdoorUrl}/api/login/oauth/access_token`. If `wx.login` fails or gives no code, it rejects with an
`Error` and calls nothing else.

### `BridgeError`

Thrown for a failed exchange, and for a failed Casdoor login. It has two properties:

- `status`: the HTTP status of the answer, or `0` when no answer arrived;
- `error`: a short code, below.

The bridge's `error_description` is not exposed: branch on `error`.

The ES module and CommonJS builds each define their own `BridgeError` class, so `instanceof BridgeError` is
false for an error thrown by the other build, as when one part of an app imports the package and another
requires it. Check `error.name === 'BridgeError'` instead:

```ts
import type { BridgeError } from '@therank/identity-bridge-client'

function isBridgeError(error: unknown): error is BridgeError {
    return error instanceof Error && error.name === 'BridgeError'
}
```

| `error` | Status | Meaning |
|---|---|---|
| `invalid_request` | 400 | The bridge did not accept the IdP token, for example because it expired or comes from an identity provider the product does not trust, or the request was malformed, as with an empty IdP token. The bridge's logs say why. |
| `invalid_request` | 413 | The request was too large. |
| `invalid_target` | 400 | The bridge has no product with this `audience`. |
| `temporarily_unavailable` | 503 | The IdP's JWKS could not be fetched or used. The SDK retried the exchange twice. |
| `server_error` | 500 | The bridge failed. |
| `network` | 0 | No answer arrived. The exchange with the bridge first retries twice; `casdoorMiniProgramIdpToken` never retries, since a `wx.login` code can be used only once. |
| `bad_response` | any | The answer was not one the bridge or Casdoor gives, such as an HTML error page from a proxy. |
| `casdoor_error` | Casdoor's | From `casdoorMiniProgramIdpToken`: Casdoor answered `{"status": "error"}`. |
| Casdoor's `error` | Casdoor's | From `casdoorMiniProgramIdpToken`: Casdoor answered with an OAuth error such as `invalid_client`. |

## Module formats

ES modules in `dist/` and CommonJS in `dist/cjs/` both target ES2017. See [`BridgeError`](#bridgeerror) when
mixing builds. The root `wechat.d.ts` supports the `wechat` subpath under `moduleResolution: node`, which
does not read package `exports`.

## License

[Apache-2.0](LICENSE)
