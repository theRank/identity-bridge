# Integrating a product

A product integrates the bridge in three places: its clients exchange IdP tokens for bridge access tokens, its
backend verifies those tokens, and, if it wants lifecycle events, its backend receives them. The TypeScript
SDKs cover the first two in a few lines; other languages use a standard JWT library and the rules in
[api.md](api.md).

| Package | For | Reference |
|---|---|---|
| [`@therank/identity-bridge-client`](https://www.npmjs.com/package/@therank/identity-bridge-client) | Browsers, Node.js 22 or later, JavaScript apps, WeChat mini programs | [README](../packages/client/README.md) |
| [`@therank/identity-bridge-server`](https://www.npmjs.com/package/@therank/identity-bridge-server) | Backends on Node.js 22.12 or later, Workers, Deno, Bun | [README](../packages/server/README.md) |

## Clients

A client signs the user in with the IdP, then asks the bridge for an access token before calling its backend.
The bridge refuses an IdP token older than `maxTokenAgeSeconds`, 15 minutes by default, so the client gets a
fresh IdP token for every exchange ([why](api.md#processing)).

`createBridgeClient` caches the bridge token in memory. A `getToken()` call refreshes it when near expiry
([details](../packages/client/README.md#how-it-works)); there is no background refresh. Supply a function
that returns a fresh IdP token:

```ts
import { createBridgeClient } from '@therank/identity-bridge-client'

const bridge = createBridgeClient({
    url: 'https://id.acme.example', // the bridge's issuer
    audience: 'acme', // the product's id in the bridge configuration
    getIdpToken, // a fresh IdP token on every call, below
})

const response = await fetch('https://api.acme.example/me', {
    headers: { authorization: `Bearer ${await bridge.getToken()}` },
})

// On sign-out
bridge.clear()
```

Call `getToken()` before each request to the backend; it answers from memory while the token is fresh. It
throws a `BridgeError` when an exchange fails without a usable fallback. `400 invalid_request` can mean an
unacceptable IdP token or a malformed request: sign in again if the session ended; otherwise check the bridge
logs. See the [error reference](../packages/client/README.md#bridgeerror).

### Clerk

Clerk's session tokens last 60 seconds, and `getToken()` returns a valid one, from its cache or newly minted
([Clerk](https://clerk.com/docs/js-frontend/reference/objects/session#gettoken)):

```ts
async function getIdpToken(): Promise<string> {
    const token = await clerk.session?.getToken()
    if (!token) throw new Error('not signed in')
    return token
}
```

`clerk` is the loaded Clerk instance; with a framework SDK, use its own `getToken`. The session token must carry
the claims [idp-clerk.md](idp-clerk.md#session-token) adds.

### Casdoor on the web and in apps

The client signs in with the OIDC authorization code flow with PKCE, through any OIDC library, against the
application of that client, and keeps the refresh token. Before each exchange it refreshes, which also lets
Casdoor refuse a user who was deleted or forbidden meanwhile
([idp-casdoor.md](idp-casdoor.md#refresh-tokens)):

```ts
let refreshToken = '<the refresh token from the sign-in>'

async function getIdpToken(): Promise<string> {
    const response = await fetch('https://casdoor.example/api/login/oauth/access_token', {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ grant_type: 'refresh_token', refresh_token: refreshToken, client_id: '<web client id>' }),
    })
    const body: { access_token?: string; refresh_token?: string } = await response.json()
    if (!response.ok || !body.access_token) throw new Error('sign in again')
    refreshToken = body.refresh_token ?? refreshToken // Casdoor rotates refresh tokens
    return body.access_token
}
```

A client that got its token through PKCE refreshes without a client secret
([source](https://github.com/casdoor/casdoor/blob/3d81f45bc98be0fe379b3a21973c783060066af5/object/token_oauth_util.go#L800-L804)),
and Casdoor answers with a new refresh token, since it rotates them by default
([Casdoor](https://casdoor.ai/docs/how-to-connect/oauth/)). Casdoor's documentation shows the refresh at
`/api/login/oauth/refresh_token`; the token endpoint above takes the same grant
([source](https://github.com/casdoor/casdoor/blob/3d81f45bc98be0fe379b3a21973c783060066af5/object/token_oauth.go#L148-L153)).
Store the refresh token as the platform's secure storage allows; never in the bridge client, which keeps
nothing outside memory.

### WeChat mini programs

Mini programs have no `fetch`. The `wechat` entry point sends requests with `wx.request` and signs the user in
through Casdoor's mini program code login ([idp-casdoor.md](idp-casdoor.md#wechat-mini-programs)), without any
client secret:

```js
const { createBridgeClient } = require('@therank/identity-bridge-client')
const { casdoorMiniProgramIdpToken, wxRequestTransport } = require('@therank/identity-bridge-client/wechat')

const bridge = createBridgeClient({
    url: 'https://id.cn.acme.example',
    audience: 'acme',
    getIdpToken: casdoorMiniProgramIdpToken({ casdoorUrl: 'https://casdoor.example', clientId: '<mini program client id>' }),
    transport: wxRequestTransport,
})
```

Each exchange gets a new [`wx.login`](https://developers.weixin.qq.com/miniprogram/dev/api/open-api/login/wx.login.html)
code. Add the bridge's and Casdoor's domains to the mini program's server domains; both need ICP filing
([WeChat](https://developers.weixin.qq.com/miniprogram/dev/framework/ability/network.html)). The
[client README](../packages/client/README.md#wechat-mini-programs) lists the other constraints.

### Without the SDK

Any HTTP client can exchange a token ([request](api.md#request)):

```sh
curl -sS https://id.acme.example/token \
    --data-urlencode 'grant_type=urn:ietf:params:oauth:grant-type:token-exchange' \
    --data-urlencode "subject_token=$IDP_TOKEN" \
    --data-urlencode 'subject_token_type=urn:ietf:params:oauth:token-type:jwt' \
    --data-urlencode 'audience=acme'
```

```json
{"access_token":"eyJhbGciOiJFUzI1NiIs...","issued_token_type":"urn:ietf:params:oauth:token-type:access_token","token_type":"Bearer","expires_in":900}
```

A client that does this itself follows the same pattern as the SDK:

1. Keep the access token in memory, never in persistent storage. Note when it arrived.
2. Reuse it while more than `min(60, expires_in / 2)` seconds of its `expires_in` remain, counted from its
   arrival by the client's own clock. The device's clock may be wrong, so do not compare the JWT's `exp` with
   it.
3. When it is due, get a fresh IdP token and exchange again. Let concurrent callers wait for the one exchange
   in flight.
4. Retry `503 temporarily_unavailable`, and a request that got no answer, a couple of times with the same IdP
   token, after a short wait. Other errors need investigation: `400 invalid_request` can mean a malformed
   request or an unacceptable IdP token. Sign in again if the session has ended; check the bridge logs for
   request or configuration problems.
5. On sign-out, drop the token.

## Backends

Every request from a client carries `Authorization: Bearer <access token>`. The backend verifies it against
the bridge's JWKS and takes the user from it.

### With the server SDK

```ts
import { BridgeTokenError, createVerifier } from '@therank/identity-bridge-server'

// One verifier, reused, so the bridge's keys stay cached
const verifier = createVerifier({ issuer: 'https://id.acme.example', audience: 'acme' })

export async function me(request: Request): Promise<Response> {
    let user
    try {
        user = await verifier.verifyRequest(request)
    } catch (error) {
        if (!(error instanceof BridgeTokenError)) throw error
        if (error.reason === 'jwks_unavailable') return new Response(null, { status: 503 })
        return new Response(null, { status: 401, headers: { 'www-authenticate': 'Bearer' } })
    }
    return Response.json({ id: user.userId, email: user.email, name: user.name })
}
```

`createVerifier` fixes every check of [api.md](api.md#access-token), the `typ` check included, and throws at
start-up when `issuer` or `audience` is missing. The [server README](../packages/server/README.md) has the
full API.

### Other languages

Use a JWT library that supports ES256 and a JWKS, and check, for an access token
([rules](api.md#access-token)):

- `alg` is `ES256`, and the signature verifies with the JWKS key whose `kid` the header names;
- `typ` is `at+jwt` or `application/at+jwt`;
- `iss` is the bridge's issuer and `aud` the product's id;
- `exp` is present and in the future, allowing at most 60 seconds of clock skew;
- `sub` is a user id: a lowercase UUID ([user ids](api.md#user-ids)).

Configure or implement the `typ` check explicitly. A verifier that also fails to require `exp` could accept
an event as an access token that never expires ([why](api.md#access-token)).

#### Go

With the standard library only, Go 1.25 or later:

```go
package bridge

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

// userID is the form of every bridge user id: a lowercase UUID
var userID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// Verifier checks the bridge's access tokens and event tokens for one product.
type Verifier struct {
	Issuer   string // the bridge's issuer, such as https://id.acme.example
	Audience string // the product's id
	JWKSURL  string // default: Issuer + "/.well-known/jwks.json"

	mu      sync.Mutex
	keys    map[string]*ecdsa.PublicKey
	fetched time.Time
}

type Claims struct {
	Iss    string                     `json:"iss"`
	Sub    string                     `json:"sub"`
	Aud    string                     `json:"aud"`
	Exp    *int64                     `json:"exp"`
	Iat    *int64                     `json:"iat"`
	Jti    string                     `json:"jti"`
	Email  string                     `json:"email"`
	Name   string                     `json:"name"`
	Events map[string]json.RawMessage `json:"events"`
}

// VerifyAccessToken returns the claims of a valid access token.
func (v *Verifier) VerifyAccessToken(token string) (*Claims, error) {
	claims, err := v.verify(token, "at+jwt")
	if err != nil {
		return nil, err
	}
	if claims.Exp == nil || time.Now().Unix() > *claims.Exp+60 {
		return nil, errors.New("expired")
	}
	return claims, nil
}

// VerifyEvent returns the claims of a valid event token. Events have no exp.
func (v *Verifier) VerifyEvent(body string) (*Claims, error) {
	claims, err := v.verify(strings.TrimSpace(body), "secevent+jwt")
	if err != nil {
		return nil, err
	}
	if claims.Jti == "" || claims.Iat == nil || len(claims.Events) != 1 {
		return nil, errors.New("not a bridge event")
	}
	return claims, nil
}

func (v *Verifier) verify(token, typ string) (*Claims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("malformed")
	}
	var header struct{ Alg, Typ, Kid string }
	if err := decodeSegment(parts[0], &header); err != nil {
		return nil, err
	}
	// Both kinds are signed with the same key: typ keeps an event from passing as an access token
	if header.Alg != "ES256" || strings.TrimPrefix(strings.ToLower(header.Typ), "application/") != typ {
		return nil, errors.New("wrong algorithm or type")
	}
	key, err := v.key(header.Kid)
	if err != nil {
		return nil, err
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(signature) != 64 {
		return nil, errors.New("malformed signature")
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	r, s := new(big.Int).SetBytes(signature[:32]), new(big.Int).SetBytes(signature[32:])
	if !ecdsa.Verify(key, digest[:], r, s) {
		return nil, errors.New("bad signature")
	}
	var claims Claims
	if err := decodeSegment(parts[1], &claims); err != nil {
		return nil, err
	}
	if claims.Iss != v.Issuer || claims.Aud != v.Audience || !userID.MatchString(claims.Sub) {
		return nil, errors.New("wrong issuer, audience or subject")
	}
	return &claims, nil
}

// key returns the JWKS key with this kid, fetching the set again for an unknown kid at most every 30 seconds
func (v *Verifier) key(kid string) (*ecdsa.PublicKey, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if key, ok := v.keys[kid]; ok {
		return key, nil
	}
	if time.Since(v.fetched) < 30*time.Second {
		return nil, errors.New("unknown key")
	}
	url := v.JWKSURL
	if url == "" {
		url = v.Issuer + "/.well-known/jwks.json"
	}
	client := http.Client{Timeout: 5 * time.Second}
	response, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("JWKS answered %d", response.StatusCode)
	}
	var set struct {
		Keys []struct{ Kty, Crv, X, Y, Kid string }
	}
	if err := json.NewDecoder(response.Body).Decode(&set); err != nil {
		return nil, err
	}
	keys := map[string]*ecdsa.PublicKey{}
	for _, jwk := range set.Keys {
		x, errX := base64.RawURLEncoding.DecodeString(jwk.X)
		y, errY := base64.RawURLEncoding.DecodeString(jwk.Y)
		if jwk.Kty != "EC" || jwk.Crv != "P-256" || errX != nil || errY != nil || len(x) != 32 || len(y) != 32 {
			continue
		}
		key, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), append(append([]byte{4}, x...), y...))
		if err == nil {
			keys[jwk.Kid] = key
		}
	}
	v.keys, v.fetched = keys, time.Now()
	if key, ok := keys[kid]; ok {
		return key, nil
	}
	return nil, errors.New("unknown key")
}

func decodeSegment(segment string, into any) error {
	data, err := base64.RawURLEncoding.DecodeString(segment)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, into)
}
```

Use it from a handler:

```go
var verifier = &bridge.Verifier{Issuer: "https://id.acme.example", Audience: "acme"}

func me(w http.ResponseWriter, r *http.Request) {
	// The scheme is case-insensitive; anything but a bearer token is refused before verifying
	scheme, token, found := strings.Cut(r.Header.Get("Authorization"), " ")
	if !found || !strings.EqualFold(scheme, "Bearer") {
		unauthorized(w)
		return
	}
	claims, err := verifier.VerifyAccessToken(strings.TrimSpace(token))
	if err != nil {
		unauthorized(w)
		return
	}
	fmt.Fprintf(w, "hello %s\n", claims.Sub)
}

func unauthorized(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", "Bearer")
	http.Error(w, "", http.StatusUnauthorized)
}
```

#### Python

With [PyJWT](https://pyjwt.readthedocs.io/) 2.9 or later and [`cryptography`](https://cryptography.io/),
since Python's standard library has no ECDSA: `pip install "pyjwt>=2.9" cryptography`. Earlier PyJWT versions
do not accept the `PyJWK` that `get_signing_key_from_jwt` returns in `jwt.decode`; with them, pass its `.key`.

```python
import re

import jwt

ISSUER = "https://id.acme.example"
AUDIENCE = "acme"
# The form of every bridge user id: a lowercase UUID
USER_ID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")

# One client, reused: it caches the bridge's keys
jwks = jwt.PyJWKClient(f"{ISSUER}/.well-known/jwks.json", cache_keys=True, timeout=5)


def _verify(token: str, typ: str, required: list[str]) -> dict:
    # Both kinds are signed with the same key: typ keeps an event from passing as an access token
    header_typ = str(jwt.get_unverified_header(token).get("typ", "")).lower()
    if header_typ.removeprefix("application/") != typ:
        raise jwt.InvalidTokenError("wrong token type")
    key = jwks.get_signing_key_from_jwt(token)
    claims = jwt.decode(
        token,
        key,
        algorithms=["ES256"],
        issuer=ISSUER,
        audience=AUDIENCE,
        leeway=60,
        options={"require": required},
    )
    if not isinstance(claims["sub"], str) or not USER_ID.fullmatch(claims["sub"]):
        raise jwt.InvalidTokenError("not a bridge user id")
    return claims


def verify_access_token(token: str) -> dict:
    return _verify(token, "at+jwt", ["exp", "iat", "sub"])


def verify_event(body: str) -> dict:
    claims = _verify(body.strip(), "secevent+jwt", ["iat", "jti", "sub"])
    if not isinstance(claims.get("events"), dict) or len(claims["events"]) != 1:
        raise jwt.InvalidTokenError("not a bridge event")
    return claims
```

`verify_access_token` raises a subclass of `jwt.InvalidTokenError` for an invalid token, and
`jwt.PyJWKClientError` when the keys cannot be fetched or no key matches.

## Consuming events

A product that sets `events.url` in the bridge configuration receives a POST for each user event of the
webhook sources that list it ([fan-out](api.md#fan-out)). The body is the event token itself, with
`Content-Type: application/secevent+jwt`.

1. **Verify it** like an access token, but with `typ` `secevent+jwt` and without requiring `exp`: events have
   none ([rules](api.md#event-token)). `verifyEvent` of the server SDK does this.
2. **Process each `jti` once.** The same event arrives again whenever the IdP redelivers a webhook, which it
   does after any product's delivery fails. Record the `jti` in the same transaction as the change it causes,
   so a crash between the two cannot apply an event twice or lose it.
3. **Keep deleted users deleted.** Events carry no sequence: an event an IdP redelivers can arrive after a
   later one, as Clerk warns ([Clerk](https://clerk.com/docs/guides/development/webhooks/overview)). A late
   `user-created` or `user-updated` has its own `jti`, so it passes the check above; on a `user-deleted`, keep
   a tombstone for the id, and skip upserts for ids that have one. Take a lock on the user id first: two events
   for one user can arrive at once, and without it an upsert that found no tombstone can commit after the
   deletion that wrote one.
4. **Answer `202`** once the transaction has committed. Any `2xx` counts as delivered; any other answer, a
   redirect included, makes the bridge answer the IdP with `502`, allowing the IdP to retry. The
   bridge waits 5 seconds for an answer. Refuse an event that does not verify with `400` and the error body of
   [RFC 8935 §2.3](https://www.rfc-editor.org/rfc/rfc8935#section-2.3), as the [API](api.md#event-token) asks.

```ts
import { BridgeTokenError, createVerifier, type BridgeEvent } from '@therank/identity-bridge-server'

const verifier = createVerifier({ issuer: 'https://id.acme.example', audience: 'acme' })

// RFC 8935 error codes for the verifier's reasons; invalid_request for the rest
const SET_ERRORS: Record<string, string> = { wrong_issuer: 'invalid_issuer', wrong_audience: 'invalid_audience', unknown_key: 'invalid_key' }

export async function identityEvents(request: Request): Promise<Response> {
    let event: BridgeEvent
    try {
        event = await verifier.verifyEvent(await request.text())
    } catch (error) {
        if (!(error instanceof BridgeTokenError)) throw error
        if (error.reason === 'jwks_unavailable') return new Response(null, { status: 503 })
        const body = { err: SET_ERRORS[error.reason] ?? 'invalid_request', description: `The event was rejected: ${error.reason}.` }
        return Response.json(body, { status: 400, headers: { 'content-language': 'en' } })
    }
    await db.transaction(async (tx) => {
        // Held until commit, so events for one user apply one at a time
        await tx.query('SELECT pg_advisory_xact_lock(hashtextextended($1, 0))', [event.userId])
        // jti is the primary key, so a repeat inserts nothing
        const { rowCount } = await tx.query('INSERT INTO identity_events (jti) VALUES ($1) ON CONFLICT DO NOTHING', [event.jti])
        if (rowCount === 0) return
        if (event.type === 'user-deleted') {
            await tx.query('DELETE FROM users WHERE id = $1', [event.userId])
            // The tombstone keeps a late event from bringing the user back
            await tx.query('INSERT INTO deleted_users (id, deleted_at) VALUES ($1, now()) ON CONFLICT (id) DO UPDATE SET deleted_at = now()', [event.userId])
            return
        }
        const { rowCount: deleted } = await tx.query('SELECT 1 FROM deleted_users WHERE id = $1', [event.userId])
        if (deleted > 0) return
        await tx.query(
            'INSERT INTO users (id, email, name) VALUES ($1, $2, $3) ON CONFLICT (id) DO UPDATE SET email = $2, name = $3',
            [event.userId, event.profile.email ?? null, event.profile.name ?? null],
        )
    })
    return new Response(null, { status: 202 })
}
```

`db` stands for the product's database client, and the SQL is PostgreSQL's. Another database needs its own lock
on the user id, held until the transaction ends. A `user-created` can also arrive after the user's first
request, which is why users are created on first sight, below.

## Data rules

- **Key users by `sub`**, the bridge's user id. It is the same whichever client the user signs in from, and in
  every event. Do not key by email, which can change or be absent, and do not branch on the `idp` claim.
- **Create users on first sight**, from whichever comes first: an access token or a `user-created` event, unless
  the id has a tombstone (below), checking it under the same lock on the user id as events. Some users produce
  no `user-created` at all.
- **Refresh profiles from token claims.** Tokens include available email, phone, name and picture fields;
  email and phone appear only when verified. For Casdoor users this is the only way profile changes arrive.
- **Keep authorization in the product**, keyed by `sub`. The bridge carries no roles or permissions.
- **After `user-deleted`**, keep the tombstone: later events for the id change nothing. The bridge does not
  know about the deletion: it still exchanges an IdP token issued before it until that token expires or is too
  old, and each access token it issues lives `tokenTtlSeconds`. So refuse tokens for a tombstoned id until the
  [revocation bound](api.md#processing) has passed since the deletion, about 32 minutes with the defaults. A
  token for the id after that means the IdP signed the user in again, as when a Casdoor user signs up again
  through the same OAuth account, which gives the same id ([idp-casdoor.md](idp-casdoor.md#sign-in-providers)):
  create the user anew and drop the tombstone.

## Casdoor events products do not receive

Casdoor's webhook relays only what the bridge can trust. Products do not receive profile updates, users created
without a sign-up flow (such as through the mini program code login or an admin), or deletions other than an
organization admin's. Those users lose access within the revocation bound instead. The full list and the
reasons are in [idp-casdoor.md](idp-casdoor.md#what-is-not-relayed).
