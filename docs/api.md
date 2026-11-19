# API

The bridge's wire contract with clients, product backends and identity providers (IdPs). The
[SDKs](integrate.md) implement the client and backend sides; read this to integrate without them or to check
what they do. Configuration keys named here are described in [configuration.md](configuration.md).

Times are integer seconds since the epoch. Bodies are UTF-8 JSON unless stated otherwise. MUST, SHOULD and
MAY are used as in [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119).

## Endpoints

| Method | Path | Purpose | `Allow` on 405 |
|---|---|---|---|
| `POST` | `/token` | [Token exchange](#token-exchange) | `POST, OPTIONS` |
| `OPTIONS` | `/token` | [CORS preflight](#cors) | |
| `GET` | `/.well-known/jwks.json` | [The bridge's public keys](#jwks) | `GET` |
| `GET` | `/healthz` | [Health and crypto self-test](#health) | `GET` |
| `POST` | `/webhooks/{source}` | [IdP lifecycle webhooks](#webhooks) | `POST` |

- Any other path is `404` with an empty body.
- A known path with another method is `405` with an empty body and the `Allow` header above. `HEAD` is not
  supported: on the `GET` routes it is `405`.
- `{source}` is exactly one non-empty path segment, compared literally with the configured source ids, neither
  decoded nor case-folded. `/webhooks/`, `/webhooks/a/b` and `/webhooks/a/` are unknown paths.

## Issuer

Each deployment has one issuer: an `https` URL without a trailing slash, such as `https://id.acme.example`. It
is the `iss` of everything the bridge signs. The bridge serves its routes at the root path, and the SDKs reach
it at its issuer (`<issuer>/token`, `<issuer>/.well-known/jwks.json`), so use the origin the bridge is served
at, without a path.

## Token exchange

`POST /token` exchanges an IdP's JWT for a bridge access token. It is a profile of
[RFC 8693](https://www.rfc-editor.org/rfc/rfc8693) token exchange. There is no client authentication: clients
are public, and the subject token is the credential.

### Request

- `Content-Type` MUST be `application/x-www-form-urlencoded`. The media type is compared without parameters
  and case-insensitively, so `application/x-www-form-urlencoded; charset=utf-8` is accepted.
- The body is at most 16 KiB (16,384 bytes).

| Parameter | Rule |
|---|---|
| `grant_type` | Required. `urn:ietf:params:oauth:grant-type:token-exchange` |
| `subject_token` | Required. The IdP's JWT in compact serialization |
| `subject_token_type` | Required. `urn:ietf:params:oauth:token-type:jwt`, `urn:ietf:params:oauth:token-type:access_token` or `urn:ietf:params:oauth:token-type:id_token`. All three are verified the same way, as JWTs |
| `audience` | Required, exactly once. The product id from the bridge configuration |
| `requested_token_type` | Optional. If present, `urn:ietf:params:oauth:token-type:access_token` |
| `actor_token`, `actor_token_type` | Must be absent: delegation is not supported |
| `scope` | Must be absent: the bridge issues no scopes |
| `resource` | Must be absent: the product is named by `audience` only |

- A parameter with an empty value is treated as absent, as
  [RFC 6749 §3.2](https://www.rfc-editor.org/rfc/rfc6749#section-3.2) requires.
- Values are compared exactly, case included: a `grant_type` that differs only in case is refused with
  `unsupported_grant_type`, and a `subject_token_type` or `requested_token_type` with `invalid_request`.
- Each parameter in the table may appear at most once. Any other parameter is ignored.

```http
POST /token HTTP/1.1
Host: id.acme.example
Content-Type: application/x-www-form-urlencoded

grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange&subject_token=eyJhbGciOiJSUzI1NiIs...&subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Ajwt&audience=acme
```

### Processing

1. The request is checked as above.
2. `audience` must name a configured product.
3. The subject token is decoded without verifying it, and the bridge picks the product's IdP binding whose
   `issuer` equals the token's `iss` exactly. No network call has happened yet: JWKS URLs come only from
   configuration, and a token from an issuer the product does not trust is refused before any fetch.
4. The token is verified with that IdP's JWKS: the signature; `alg` in the IdP's `algorithms`; `iss`; `exp`,
   required and in the future; `nbf`, if present; `iat`, required, not in the future and not older than
   `maxTokenAgeSeconds`. Each time check allows `clockToleranceSeconds`.
5. Every entry of the IdP's `requiredClaims` equals the token's claim exactly.
6. When the binding lists them: one of the token's client ids (the claim named by `claims.clientId`, `aud` by
   default, a string or an array) is in `clientIds`, and the token's `azp` is in `authorizedParties`.
7. `sub` is a non-empty string.
8. The IdP's claims are mapped to a profile ([claim mapping](configuration.md#claim-mapping)) and the user id
   is derived ([user ids](#user-ids)).
9. The access token is signed and returned. Nothing is stored.

The bridge does not check session or account status at the IdP. Once the IdP stops issuing tokens to a user,
the remaining access window is at most `maxTokenAgeSeconds + clockToleranceSeconds + tokenTtlSeconds`, plus
the verifier's leeway on `exp` (at most 60 seconds, as below): 900 + 60 + 900 + 60 seconds, or 32 minutes with
the defaults. An unexpired IdP token can be exchanged repeatedly within its allowed age; clients should
request a fresh token before each exchange.

### Success

`200`, with `Content-Type: application/json`, `Cache-Control: no-store` and `Pragma: no-cache`:

```json
{
  "access_token": "<JWT>",
  "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
  "token_type": "Bearer",
  "expires_in": 900
}
```

`expires_in` equals `tokenTtlSeconds`. There is no `refresh_token`: to refresh, a client exchanges a fresh IdP
token. There is no `scope`.

### Errors

An [RFC 6749 §5.2](https://www.rfc-editor.org/rfc/rfc6749#section-5.2) body,
`{"error": "...", "error_description": "..."}`, with the same `Cache-Control` and `Pragma` headers and
`Vary: Origin`. `error_description` is the fixed phrase of its row and never echoes request or token content.
`server_error` and `temporarily_unavailable` come from
[RFC 6749 §4.1.2.1](https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2.1);
[RFC 8693 §2.2.2](https://www.rfc-editor.org/rfc/rfc8693#section-2.2.2) allows them.

| Status | `error` | When | `error_description` | Log codes |
|---|---|---|---|---|
| 400 | `invalid_request` | Wrong content type; a missing, repeated or invalid parameter; an actor token | `The request is malformed.` | `bad_request` |
| 400 | `invalid_request` | Any subject token failure, processing steps 3 to 7, or an invalid `uid` override | `The subject token is not acceptable.` | `malformed_token`, `untrusted_issuer`, `bad_algorithm`, `bad_signature`, `unknown_key`, `expired`, `too_old`, `not_yet_valid`, `missing_claim`, `claim_mismatch`, `client_mismatch`, `bad_uid` |
| 400 | `invalid_target` | Unknown `audience`; more than one `audience`; `resource` present | `The requested audience is not available.` | `unknown_product`, `bad_request` |
| 400 | `invalid_scope` | `scope` present | `Scopes are not supported.` | `bad_request` |
| 400 | `unsupported_grant_type` | `grant_type` present but not token exchange | `Only token exchange is supported.` | `unsupported_grant` |
| 413 | `invalid_request` | Body over 16 KiB | `The request is too large.` | `too_large` |
| 503 | `temporarily_unavailable` | The IdP's JWKS could not be fetched or used | `The identity provider is unavailable.` | `jwks_unavailable` |
| 500 | `server_error` | [Failure mode](#failure-mode) or an unexpected error | `The service failed.` | `runtime_unavailable`, `internal_error` |

Every subject token failure gives the same `error` and description, so the endpoint does not tell a caller
which check failed. The precise reason is the log code, described in
[configuration.md](configuration.md#log-codes).

When a request breaks several rules, the first that applies decides the answer: the content type, the body
size, a repeated `audience` (`invalid_target`), any other repeated parameter (`invalid_request`), a missing
`grant_type` (`invalid_request`), another grant type (`unsupported_grant_type`), `resource`
(`invalid_target`), `scope` (`invalid_scope`), then the remaining parameter rules (`invalid_request`), then the
product.

A client may retry `503 temporarily_unavailable` with the same IdP token. Do not automatically retry other
errors: inspect the error and bridge logs first. The [client SDK](../packages/client/README.md#how-it-works)
also retries transport failures.

### CORS

Every `POST` and `OPTIONS` response from `/token` carries `Vary: Origin`; a `405` does not.

- **Preflight.** `OPTIONS /token` answers `204`. When the request's `Origin` is in the `allowedOrigins` of any
  product, the answer carries `Access-Control-Allow-Origin: <origin>`, `Access-Control-Allow-Methods: POST`,
  `Access-Control-Allow-Headers: Content-Type` and `Access-Control-Max-Age: 600`; otherwise no CORS headers. A
  preflight carries no body, so the product is not known yet. In [failure mode](#failure-mode) a preflight
  gets the same `500` as a `POST`, without CORS headers, so a browser reports a CORS error rather than the
  `500`: check `/healthz` and the `runtime_load_failed` log line, not `allowedOrigins`.
- **`POST`.** `Access-Control-Allow-Origin: <origin>` is sent only when the request's `Origin` is in the
  `allowedOrigins` of the product named by `audience`. It is sent on success and on every error after the
  product is resolved, so a browser can read the error.

An origin that is not listed gets no CORS headers, but the request is still processed: CORS is a browser
control, not authentication. A form-encoded `POST` without custom headers is a CORS simple request and is not
preflighted; the preflight serves clients that add headers. CORS concerns browsers only: native apps need no
`allowedOrigins` entry, and a WeChat mini program's requests are governed by its server domain list instead
([WeChat][wx-network]).

## Access token

A JWT following [RFC 9068](https://www.rfc-editor.org/rfc/rfc9068), with one deviation: it is signed only with
ES256. [RFC 9068 §2.1](https://www.rfc-editor.org/rfc/rfc9068#section-2.1) requires authorization servers and
resource servers to support RS256; the bridge does not offer RS256, and verifiers MUST support ES256. The
token carries no `scope` claim, since the bridge issues no scopes.

Header:

```json
{"alg": "ES256", "typ": "at+jwt", "kid": "<RFC 7638 thumbprint of the signing key>"}
```

| Claim | Presence | Value |
|---|---|---|
| `iss` | always | The deployment's issuer |
| `sub` | always | The user id, a lowercase canonical UUID ([user ids](#user-ids)) |
| `aud` | always | The product id, a string |
| `client_id` | always | The product id |
| `iat`, `exp` | always | `exp = iat + tokenTtlSeconds` |
| `jti` | always | A random UUID v4 |
| `idp` | always | The IdP's id from configuration. Informational: products MUST NOT branch on it |
| `region` | if configured | The deployment's label, such as `us` or `cn` |
| `email` | if verified | Only an email the IdP marks verified; a string containing `@` |
| `phone_number` | if verified and E.164 | Only a verified number in E.164 form. One the IdP stores as a national number and a region is joined first ([Casdoor](idp-casdoor.md#phone-numbers)) |
| `name` | if present | The display name, trimmed, not empty |
| `picture` | if present and `https` | The avatar URL as given, without userinfo, spaces, control characters or backslashes |

There is no `email_verified` claim: an `email` present is verified by definition, and so is a `phone_number`.
The token carries no roles, permissions or groups; authorization stays in each product.

**Verifying an access token.** A product backend checks:

- the signature, against the bridge's [JWKS](#jwks);
- `alg` is `ES256`;
- `typ` is `at+jwt` ([RFC 9068 §4](https://www.rfc-editor.org/rfc/rfc9068#section-4) also allows
  `application/at+jwt`);
- `iss` equals the deployment's issuer;
- `aud` equals the product's own id;
- `exp` is in the future, with at most 60 seconds of tolerance.

The `typ` check is essential. [Event tokens](#event-token) are signed with the same key, name the product as
`aud` and the user as `sub`, and carry no `exp`; a verifier that skips `typ` and does not require `exp` would
accept an event as an access token that never expires.

## User ids

`sub` is the same for a person on every exchange and in every event, and it is stable across IdP migrations
when the override below is used.

1. **Override.** If the IdP's mapping names a `uid` claim and the token carries it with a value other than
   `null`, the value MUST be a canonical UUID, of any version, other than the nil UUID (all zeros) and the max
   UUID (all `f`), which backends write as empty defaults and which would merge every such user into one. It
   is lowercased and becomes `sub`. A malformed value fails the exchange (`bad_uid`) rather than falling back,
   which would give one person two ids. An absent or `null` claim means no override.
2. **Derived.** Otherwise, `sub` is the UUIDv5 ([RFC 9562](https://www.rfc-editor.org/rfc/rfc9562#section-5.5))
   of the UTF-8 bytes of `JSON.stringify([idpIssuer, idpSubject])` under the namespace
   `95c1f512-a23b-48f7-8328-199bb33cc0b4` (`USER_ID_NAMESPACE`), where `idpIssuer` is the IdP's configured
   `issuer`, which equals the token's `iss`, and `idpSubject` is the token's `sub`.
3. **Webhooks.** The webhook path derives the same id for the same user: the configured issuer of the
   source's IdP, the IdP's user id from the payload, and the override read from the source's `uidField`, with
   the same rules.

Both namespaces on this page are fixed: changing one changes the ids derived under it. A derived user id is
as distinct as the IdP's `sub` under its issuer: per Clerk application, and per Casdoor instance, where it
depends on the organization's sign-in providers ([idp-casdoor.md](idp-casdoor.md#sign-in-providers)).

The field behind `uid` MUST be writable only by administrators or backends, and MUST reach the bridge in every
token and every lifecycle event, deletions included: Clerk's `external_id`
([Clerk setup](idp-clerk.md#user-id-override)) and a Casdoor `Properties` key with its modify rule pinned to
Admin ([Casdoor setup](idp-casdoor.md#user-id-override)).

## JWKS

`GET /.well-known/jwks.json` answers `200` with `Content-Type: application/json` and
`Cache-Control: public, max-age=300`:

```json
{"keys": [{"kty": "EC", "crv": "P-256", "x": "...", "y": "...", "kid": "...", "alg": "ES256", "use": "sig"}]}
```

The active key comes first, then the retired keys. Only public members are published. `kid` is the key's
[RFC 7638](https://www.rfc-editor.org/rfc/rfc7638) thumbprint. A verifier that meets an unknown `kid` should
fetch the set again, as jose and the server SDK do.

## Health

`GET /healthz` answers `200 {"status": "ok"}` when the runtime loaded and the WebCrypto self-test passes, and
`503 {"status": "unavailable"}` otherwise, without saying what failed. Both carry `Cache-Control: no-store`,
so no cache between the bridge and a monitor hides a failure or a recovery.

The self-test runs once per isolate or process and is cached: ES256 signing and verification with an
ephemeral key, RS256 verification of a built-in token, a SHA-1 digest and HMAC-SHA256. It makes no network
requests and does not test IdP availability, webhook authentication or delivery to products.

## Webhooks

`POST /webhooks/{source}` receives an IdP's user lifecycle webhooks and relays them to products as
[event tokens](#event-token). The body is at most 256 KiB (262,144 bytes). Setting up the IdP side is
described in [idp-clerk.md](idp-clerk.md#webhooks) and [idp-casdoor.md](idp-casdoor.md#webhook).

### Responses

The method and the runtime are checked first, then the source, the body size and the authentication. The
payload is then parsed, in this order: the body must be a JSON object with the envelope fields of its source
type, else it is unprocessable; then the event type and the filters decide whether it is relayed; then the
event's own fields must be valid, else it is unprocessable.

| Status | Body | When | Log code |
|---|---|---|---|
| 405 | empty | Wrong method | |
| 404 | empty | Unknown `source` | `unknown_source` |
| 413 | empty | Body over 256 KiB | `too_large` |
| 401 | empty | Authentication failed, missing headers included | `bad_webhook_auth` |
| 200 | `{"delivered": [], "failed": []}` | Authenticated but not relayed: the event type is not mapped, or a filter dropped it | `ignored` |
| 200 | `{"delivered": [], "failed": []}` | Authenticated but unprocessable: the body is not JSON, a required field is missing, or the `uid` override is invalid | `bad_payload`, `bad_uid` |
| 200 | `{"delivered": ["<product>", ...], "failed": []}` | Every delivery succeeded | |
| 502 | `{"delivered": ["<product>", ...], "failed": [{"product": "<id>", "error": "timeout" \| "network" \| "status <n>"}, ...]}` | At least one delivery failed | `delivery_failed` |
| 500 | empty | [Failure mode](#failure-mode) or an unexpected error | `runtime_unavailable`, `internal_error` |

Non-empty bodies are `Content-Type: application/json`. An unprocessable payload is answered `200`: the IdP
would send the same bytes again, so a retry cannot help, and the log code is the alert.

### Clerk sources

A source with `type: "clerk"` receives Clerk's webhooks, which Clerk sends through Svix
([Clerk][clerk-webhooks]).

- **Authentication.** The headers `svix-id`, `svix-timestamp` and `svix-signature`. The signed content is
  `<svix-id>.<svix-timestamp>.<raw body>`, signed with HMAC-SHA256 under the base64-decoded part of the
  `whsec_...` secret after the prefix ([Svix][svix-verify]). The webhook is accepted when any space-separated
  `v1,<signature>` entry matches, compared in constant time, and the timestamp is within 300 seconds of the
  bridge's clock, either way.
- **Event id.** The `svix-id` header, which stays the same when Svix delivers the message again
  ([Svix][svix-verify]).
- **Mapping.** `user.created` → `user-created`, `user.updated` → `user-updated`, `user.deleted` →
  `user-deleted`. Any other type is ignored.
- **Subject.** `data.id`, a non-empty string, else `bad_payload`.
- **Override.** When the source has a `uidField`, which for Clerk is always `external_id`:
  `data.external_id`. Clerk sends it in all three user events ([user][clerk-user-json],
  [deleted user][clerk-deleted-json]); absent or `null` means no override.
- **Profile**, for created and updated users: the entry of `email_addresses` whose id is
  `primary_email_address_id`, if its `verification.status` is `verified`; the phone number the same way, with
  `phone_numbers` and `primary_phone_number_id`; `first_name` and `last_name` joined by a space; `image_url`.
  A deleted user carries only its id and `external_id` ([deleted user][clerk-deleted-json]), so `user-deleted`
  has no profile.

### Casdoor sources

A source with `type: "casdoor"` receives a Casdoor webhook. Casdoor does not sign webhooks; the webhook is
configured to send a secret header ([Casdoor][casdoor-webhooks]).

- **Authentication.** `Authorization: Bearer <secret>`, compared in constant time.
- **Body.** A Casdoor record ([records][casdoor-records]), with the members `id`, `action`, `organization`,
  `user`, `object` (a JSON string), `response` and `extendedUser`, among others. A record whose `id` is not a
  positive integer, or whose `action`, `organization` or `response` is not a string, is `bad_payload`.
- **Event id.** The record's `id`, in decimal, such as `4102`: the id Casdoor stored the record under
  ([source][casdoor-add-record]). A `new-user` record is stored apart from the record of the request that
  created the user ([source][casdoor-new-user]), so the two have different ids. Casdoor before 4.28 sent the
  webhook before it stored the record, so with the `id` `0`: every webhook of such a release is `bad_payload`.
- **Organization filter.** The record's `organization` must equal the source's `organization`, and for
  `delete-user` so must `object.owner`; otherwise the record is ignored. The bridge checks this itself rather
  than relying on the webhook's "single organization only" option, which it cannot see.
- **Outcome filter.** A record whose `response` does not begin with `{status:"ok"` is ignored. Casdoor's
  `statusCode` does not reflect the outcome ([records][casdoor-records]). `ok` means the request did not fail,
  not that it changed anything: deleting a user that does not exist also answers `ok`
  ([source][casdoor-unaffected]).
- **Mapping**, by `action`:

  | `action` | Event | User fields from | Condition, else ignored |
  |---|---|---|---|
  | `new-user` | `user-created` | `object`: the stored user, serialized by Casdoor | |
  | `delete-user` | `user-deleted` | `object`: the request body | `extendedUser.isAdmin` is `true` and `extendedUser.owner` equals the record's `organization` |
  | anything else, `signup`, `add-user` and `update-user` included | | | always ignored |

  For `delete-user` and the other API actions, `object` is the caller's raw request body, not what Casdoor
  stored ([source][casdoor-object]), and `extendedUser` is the caller, loaded by Casdoor from its store
  ([source][casdoor-extended-user]). Casdoor lets users update and delete their own accounts
  ([source][casdoor-self-apis]), so a body from a user who is not an admin can name another user's `id` or
  `properties`. Only an admin of the source's own organization is trusted, since such an admin may write those
  fields anyway. `extendedUser` is `null` unless the webhook's extended user option is on and the caller is a
  stored user. This trust is only as strong as Casdoor's authorization on the record-producing APIs: on an
  instance shared by several products, every administrator on the instance is inside each product's trust
  boundary ([shared instance](idp-casdoor.md#trust-on-a-shared-instance)).
- **Subject.** `object.id`, a non-empty string, else `bad_payload`.
- **Override.** When the source has a `uidField`: `object.properties[uidField]`. `properties` must then be
  present, as an object or `null` (a user without properties, so no override), else `bad_payload`: a body
  without it cannot tell "no override" from "override not sent".
- **Profile**, for `user-created` only: `email` if `emailVerified` is `true`; `displayName`; `avatar`; the
  phone number, joined from `phone` and `countryCode`, if the IdP's claims set `phoneVerified` to `true`
  ([phone numbers](idp-casdoor.md#phone-numbers)).

What this leaves out, and why, is listed in [idp-casdoor.md](idp-casdoor.md#what-is-not-relayed).

### Fan-out

For each product in the source's `products`, the bridge POSTs one [event token](#event-token) to the product's
`events.url`, with `Content-Type: application/secevent+jwt` and `Accept: application/json`. Deliveries run
concurrently, each with a 5-second timeout, and redirects are not followed. A `2xx` answer is a success; any
other answer, a `3xx` included, is a failure (`status <n>`).

If every delivery succeeds, the webhook is answered `200`; otherwise `502`. The IdP may redeliver the whole
webhook according to its retry policy; the bridge has no retry queue. Products already served must discard
repeated `jti` values.

## Event token

A Security Event Token ([RFC 8417](https://www.rfc-editor.org/rfc/rfc8417)), pushed as in
[RFC 8935](https://www.rfc-editor.org/rfc/rfc8935): the body of each delivery is the compact JWT.

Header:

```json
{"alg": "ES256", "typ": "secevent+jwt", "kid": "<RFC 7638 thumbprint of the signing key>"}
```

| Claim | Value |
|---|---|
| `iss` | The deployment's issuer |
| `aud` | The product id |
| `iat` | When the bridge signed the event |
| `jti` | UUIDv5 of `JSON.stringify([sourceId, idpEventId])` under the namespace `73c4ff75-fed7-4a0c-8541-3ff240e8f331` (`EVENT_ID_NAMESPACE`): the same on every delivery of the IdP's event |
| `txn` | `idpEventId`: the `svix-id` for Clerk, the record's `id` for Casdoor |
| `sub` | The user id ([user ids](#user-ids)) |
| `events` | Exactly one member, below |

| Event type URI | Payload |
|---|---|
| `urn:identity-bridge:event:user-created` | The profile: `email`, `phone_number`, `name`, `picture`, each only when known and, for email and phone, verified, with the same rules as the access token |
| `urn:identity-bridge:event:user-updated` | The same profile, with current values |
| `urn:identity-bridge:event:user-deleted` | `{}` |

An example payload, for the Clerk source `clerk-acme`, the `svix-id` `msg_2pVYk0Example`, and the user
`user_2pVYk0Example` of the IdP issuer `https://clerk.acme.example`, without an override:

```json
{
  "iss": "https://id.acme.example",
  "aud": "acme",
  "iat": 1794600000,
  "jti": "b7a8a8a5-3863-5214-84d7-a673f944aaf0",
  "txn": "msg_2pVYk0Example",
  "sub": "8dbc926a-2a0f-52e5-aa8f-01770c1f70d9",
  "events": {"urn:identity-bridge:event:user-created": {"email": "ada@acme.example", "name": "Ada Lovelace"}}
}
```

**Verifying an event.** A product checks the signature against the bridge's JWKS; `alg` is `ES256`; `typ` is
`secevent+jwt`; `iss` equals the deployment's issuer; `aud` equals the product's own id. Events carry no
`exp`.

**Answering.** A product answers `202`
([RFC 8935 §2.2](https://www.rfc-editor.org/rfc/rfc8935#section-2.2)) once the event is durably accepted. A
rejection SHOULD use the [RFC 8935 §2.3](https://www.rfc-editor.org/rfc/rfc8935#section-2.3) error body; the
bridge counts any `2xx` as delivered and anything else as failed ([fan-out](#fan-out)). A product MUST treat a
repeated `jti` as already processed: the same event arrives again whenever the IdP redelivers a webhook.
[integrate.md](integrate.md#consuming-events) shows how.

## Failure mode

The runtime loads once per isolate (Workers, ESA) or process (Node): the configuration, the signing keys and
the webhook secret of every configured source. If any part fails, the bridge keeps serving, in failure mode,
after the `404` and `405` checks:

- `/healthz` answers `503 {"status": "unavailable"}`, with `Cache-Control: no-store`;
- `/token` answers `500 server_error` to `POST` and `OPTIONS` alike, with the headers of a token error,
  `Vary: Origin` included, and no CORS headers;
- every other route answers `500` with an empty body.

Each such request is logged with the code `runtime_unavailable`, and once per isolate or process the bridge
logs a `runtime_load_failed` line that says what failed
([configuration.md](configuration.md#runtime-load-failures)). A deployment that cannot load is therefore
caught by `/healthz` and the smoke test rather than by the first user.

An exception that escapes a route gets the answer failure mode gives that route and is logged as
`internal_error`; on `/token`, once the product is resolved, that `500` also carries the [CORS](#cors) headers.

[clerk-webhooks]: https://clerk.com/docs/guides/development/webhooks/overview
[svix-verify]: https://docs.svix.com/receiving/verifying-payloads/how-manual
[clerk-user-json]: https://github.com/clerk/javascript/blob/c9bdae3b0aef91699a73824fecc6726959196ab4/packages/backend/src/api/resources/JSON.ts#L695
[clerk-deleted-json]: https://github.com/clerk/javascript/blob/c9bdae3b0aef91699a73824fecc6726959196ab4/packages/backend/src/api/resources/JSON.ts#L747-L764
[casdoor-webhooks]: https://casdoor.ai/docs/webhooks/overview/
[casdoor-records]: https://casdoor.ai/docs/organization/records/
[casdoor-add-record]: https://github.com/casdoor/casdoor/blob/3d81f45bc98be0fe379b3a21973c783060066af5/object/record.go#L248-L281
[casdoor-new-user]: https://github.com/casdoor/casdoor/blob/3d81f45bc98be0fe379b3a21973c783060066af5/routers/record.go#L166-L191
[casdoor-unaffected]: https://github.com/casdoor/casdoor/blob/3d81f45bc98be0fe379b3a21973c783060066af5/controllers/base.go#L423-L431
[casdoor-object]: https://github.com/casdoor/casdoor/blob/3d81f45bc98be0fe379b3a21973c783060066af5/object/record.go#L165-L172
[casdoor-extended-user]: https://github.com/casdoor/casdoor/blob/3d81f45bc98be0fe379b3a21973c783060066af5/object/record.go#L444-L457
[casdoor-self-apis]: https://github.com/casdoor/casdoor/blob/3d81f45bc98be0fe379b3a21973c783060066af5/authz/authz.go#L279-L306
[wx-network]: https://developers.weixin.qq.com/miniprogram/dev/framework/ability/network.html
