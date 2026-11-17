# Configuration

A deployment is one issuer, one key set and one configuration. It receives three kinds of values:

| Name | Secret | Content |
|---|---|---|
| `BRIDGE_CONFIG` | no | The [configuration document](#the-configuration-document), JSON |
| `SIGNING_KEYS` | yes | The [signing keys](#signing-keys), JSON |
| `WEBHOOK_SECRET_<SOURCE>` | yes | One [webhook secret](#webhook-secrets) per webhook source |

Each runtime takes them as environment variables or bindings: see
[Workers](deploy-workers.md#configuration-and-secrets), [Function Compute](deploy-fc.md#configuration-and-secrets),
[ESA](deploy-esa.md#variables) and [Node](deploy-node.md#configuration-and-secrets). The repository holds no
deployment values; keep yours with your deployment.

The bridge loads these values once per isolate or process. Invalid configuration or signing keys, or a
missing, empty or whitespace-padded webhook secret, cause [failure mode](api.md#failure-mode): `/healthz`
answers `503`, and a [`runtime_load_failed`](#runtime-load-failures) line identifies the problem. Webhook
secret contents are checked during authentication, not at startup.

## The configuration document

One JSON object. Unknown keys are errors at every level, so a misspelled key fails the deployment instead of
being ignored.

### A Clerk deployment

One Clerk application per product, so each product has an IdP of its own:

```json
{
  "issuer": "https://id.acme.example",
  "region": "us",
  "tokenTtlSeconds": 900,
  "idps": {
    "clerk-acme": {
      "issuer": "https://clerk.acme.example",
      "jwksUri": "https://clerk.acme.example/.well-known/jwks.json",
      "algorithms": ["RS256"],
      "maxTokenAgeSeconds": 900,
      "clockToleranceSeconds": 60,
      "claims": { "uid": "uid", "email": "email", "emailVerified": true, "name": "name", "picture": "picture" }
    }
  },
  "products": {
    "acme": {
      "idps": [{ "idp": "clerk-acme" }],
      "allowedOrigins": ["https://acme.example"],
      "events": { "url": "https://api.acme.example/identity/events" }
    }
  },
  "webhookSources": {
    "clerk-acme": { "type": "clerk", "idp": "clerk-acme", "uidField": "external_id", "products": ["acme"] }
  }
}
```

[idp-clerk.md](idp-clerk.md) explains the mapping: why `emailVerified` is `true`, and where `uid` comes from.

### A Casdoor deployment

One shared Casdoor instance serving two products, its applications using the `JWT-Custom` token format:

```json
{
  "issuer": "https://id.cn.acme.example",
  "region": "cn",
  "idps": {
    "casdoor": {
      "issuer": "https://casdoor.example",
      "jwksUri": "https://casdoor.example/.well-known/jwks",
      "algorithms": ["RS256"],
      "requiredClaims": { "tokenType": "access-token" },
      "claims": { "uid": "uid", "emailVerified": "emailVerified", "name": "displayName", "picture": "avatar" }
    }
  },
  "products": {
    "acme": {
      "idps": [{ "idp": "casdoor", "clientIds": ["<acme web client id>", "<acme app client id>", "<acme mini program client id>"] }],
      "allowedOrigins": ["https://cn.acme.example"],
      "events": { "url": "https://api.cn.acme.example/identity/events" }
    },
    "globex": {
      "idps": [{ "idp": "casdoor", "clientIds": ["<globex web client id>"] }]
    }
  },
  "webhookSources": {
    "casdoor-acme": { "type": "casdoor", "idp": "casdoor", "organization": "acme", "uidField": "uid", "products": ["acme"] }
  }
}
```

Both products bind the same IdP, so each binding lists its own client ids. [idp-casdoor.md](idp-casdoor.md)
explains `requiredClaims`, the client ids and the webhook source.

### Rules

The ids of IdPs, products and webhook sources are the record keys, and match `^[a-z0-9][a-z0-9-]{0,62}$`.
A record does not repeat its id as a member: `id` is an unknown key. Durations are integer seconds.

| Key | Required | Rule | Default |
|---|---|---|---|
| `issuer` | yes | The bridge's [issuer](api.md#issuer): an `https` URL whose text does not end with `/`, `?` or `#`, with no query, fragment, username or password | |
| `region` | no | A label copied into access tokens: `^[a-z][a-z0-9-]{0,31}$` | absent |
| `tokenTtlSeconds` | no | Access token lifetime, 60 to 3600 | `900` |
| `idps` | yes | A non-empty object of IdP records | |
| `idps.*.issuer` | yes | The IdP's `iss`, compared exactly, with the same rules as `issuer`. Distinct across IdP records, so one issuer has one claim mapping and each person one user id | |
| `idps.*.jwksUri` | yes | An `https` URL with no username or password | |
| `idps.*.algorithms` | no | A non-empty subset of `RS256`, `RS384`, `RS512`, `PS256`, `ES256`, `ES384`, `EdDSA` | `["RS256", "ES256"]` |
| `idps.*.maxTokenAgeSeconds` | no | How old an IdP token may be, by its `iat`, 30 to 3600 | `900` |
| `idps.*.clockToleranceSeconds` | no | Tolerance for `exp`, `nbf` and `iat`, 0 to 300 | `60` |
| `idps.*.requiredClaims` | no | A non-empty object of claim name to string, number or boolean. Each must equal the token's claim exactly. To require none, omit the key: `{}` is refused | absent |
| `idps.*.claims` | no | The [claim mapping](#claim-mapping) | see below |
| `products` | yes | A non-empty object of product records | |
| `products.*.idps` | yes | A non-empty array of bindings, `{ "idp": "<idp id>" }` plus the optional lists below. Each `idp` exists and is bound at most once per product | |
| `products.*.idps[].clientIds`, `products.*.idps[].authorizedParties` | no | Non-empty arrays of non-empty strings, checked against the token's client id claim and its `azp`. When two or more products bind the same IdP, each of those bindings MUST list at least one of the two, and no value may appear in the bindings of two products, counting both lists together (a Casdoor token carries its client id as both `aud` and `azp`, [source](https://github.com/casdoor/casdoor/blob/66b51eef9422bdd8f2f215f37ea29858548fb918/object/token_jwt.go#L685-L704)): a shared value would let one product's token be exchanged for another's | |
| `products.*.allowedOrigins` | no | Origins whose browsers may read `/token` answers ([CORS](api.md#cors)). Each is an `http` or `https` origin equal to `new URL(o).origin`, or `<scheme>://<host>` for another scheme such as `capacitor://localhost`, with no spaces or control characters | `[]` |
| `products.*.events.url` | no | An `https` URL with no username or password, where the product receives [events](api.md#event-token). Without `events`, the product receives none | |
| `webhookSources` | no | An object of webhook source records | `{}` |
| `webhookSources.*.type` | yes | `clerk` or `casdoor` | |
| `webhookSources.*.idp` | yes | An IdP id; its `issuer` is used to [derive user ids](api.md#user-ids) | |
| `webhookSources.*.organization` | for `casdoor`; not allowed for `clerk` | The Casdoor organization whose records the source accepts | |
| `webhookSources.*.uidField` | exactly when the IdP's `claims.uid` is set | The field behind the IdP's `uid` claim: for `clerk`, `external_id`; for `casdoor`, a non-empty `Properties` key | |
| `webhookSources.*.products` | yes | A non-empty array of product ids, without repeats. Each exists, has `events`, and binds the source's `idp` | |

### Claim mapping

`idps.*.claims` names the IdP's claims the bridge reads. Every key is optional.

| Key | Default | Meaning |
|---|---|---|
| `clientId` | `aud` | The claim checked against `clientIds` |
| `uid` | none | The claim holding the [user id override](api.md#user-ids) |
| `email` | `email` | The email claim |
| `emailVerified` | `email_verified` | A claim name, or the literal `true` to trust the IdP's own verification policy |
| `phone` | `phone_number` | The phone number claim |
| `phoneRegion` | none | The claim naming the region of a national number in `phone`, such as `CN` |
| `phoneVerified` | `phone_number_verified` | A claim name, or the literal `true` |
| `name` | `name` | The display name |
| `picture` | `picture` | The avatar URL |

- A verified flag counts only when the claim's value is the boolean `true`.
- An email is kept only when verified and containing `@`. A phone number is kept only when verified and
  matching `^\+[1-9]\d{6,14}$` (E.164). A name is trimmed and dropped when empty. A picture is kept only as an
  `https` URL without userinfo, spaces, control characters or backslashes.
- With `phoneRegion`, the `phone` claim is a national number, digits that do not begin with a zero, and its region is
  an ISO 3166-1 code in capitals. The bridge joins them into E.164 by the region's calling code, and drops a
  pair that makes no number ([Casdoor](idp-casdoor.md#phone-numbers)).
- Claim names depend on the IdP. Casdoor's depend on the application's token format: with `JWT-Custom`, a
  selected field such as `EmailVerified` becomes the claim `emailVerified`, and `Properties.uid` becomes a
  top-level `uid` claim ([idp-casdoor.md](idp-casdoor.md#token-format)).

### Choosing the durations

`maxTokenAgeSeconds` and `tokenTtlSeconds` bound how long a user the IdP cut off keeps access, about 32 minutes
with the defaults ([revocation bound](api.md#processing)). Lower them for a faster cut-off; each client
exchanges about once per `tokenTtlSeconds`, so a shorter lifetime means more exchanges.

## Signing keys

`SIGNING_KEYS` holds the deployment's ES256 (P-256) keys:

```json
{"active": {"kty": "EC", "crv": "P-256", "x": "...", "y": "...", "d": "..."}, "retired": [{"kty": "EC", "crv": "P-256", "x": "...", "y": "..."}]}
```

- `active` is the private JWK that signs access tokens and events. `retired` is optional, default `[]`: public
  JWKs, without `d`, that are still published so tokens signed before a rotation keep verifying.
- `kid`, `alg` and `use` may be left out. If present, `kid` must be the key's
  [RFC 7638](https://www.rfc-editor.org/rfc/rfc7638) thumbprint, `alg` must be `ES256` and `use` must be `sig`.
- Any other top-level member is an error, so a misspelled `retired` cannot drop keys silently.

Generate a key with Node 24 or later. `umask 077` makes the file readable by you alone:

```sh
umask 077
node --input-type=module -e '
const { privateKey } = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"])
const { kty, crv, x, y, d } = await crypto.subtle.exportKey("jwk", privateKey)
console.log(JSON.stringify({ active: { kty, crv, x, y, d } }))
' > signing-keys.json
```

Keep the file out of version control and out of images, and delete it once the deployment holds the keys. A
rotation needs only the public keys, which the bridge publishes.

### Rotating the signing key

1. Generate a new key. This writes two files: `signing-keys.next.json`, the new key with every key the
   deployment publishes now in `retired`, read from its JWKS, and `signing-keys.final.json`, the new key
   alone:

   ```sh
   umask 077
   node --input-type=module -e '
   import { writeFileSync } from "node:fs"
   const { keys } = await (await fetch(`${process.argv[1]}/.well-known/jwks.json`)).json()
   const { privateKey } = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"])
   const { kty, crv, x, y, d } = await crypto.subtle.exportKey("jwk", privateKey)
   const retired = keys.map((key) => ({ kty: key.kty, crv: key.crv, x: key.x, y: key.y }))
   writeFileSync("signing-keys.next.json", JSON.stringify({ active: { kty, crv, x, y, d }, retired }))
   writeFileSync("signing-keys.final.json", JSON.stringify({ active: { kty, crv, x, y, d } }))
   ' https://id.acme.example
   ```

2. Deploy `signing-keys.next.json` as `SIGNING_KEYS` and run the smoke test. New tokens carry the new `kid`;
   verifiers that cached the old JWKS fetch it again when they meet the unknown `kid`, as jose and the server
   SDK do.
3. After all replicas have switched keys, wait at least `tokenTtlSeconds` plus the verifiers' clock tolerance
   (60 seconds at most), so access tokens signed with the old keys have expired. If a product queues signed
   event tokens for later verification, retain the old public keys until those events are processed: events
   have no expiry. Then deploy `signing-keys.final.json`, and delete both files.

If an HTTP cache sits between verifiers and the bridge, it may serve the previous JWKS for up to 300 seconds
(`max-age`), and verifiers would not find the new key in it until then. Purge the cache's copy of
`/.well-known/jwks.json` after step 2, or let verifiers fetch it from the bridge directly.

## Webhook secrets

Each webhook source needs a secret, named `WEBHOOK_SECRET_` and the source id in capitals with `-` as `_`:
the source `clerk-acme` reads `WEBHOOK_SECRET_CLERK_ACME`.

- **Clerk**: the endpoint's signing secret, `whsec_...`, as Clerk shows it ([idp-clerk.md](idp-clerk.md#webhooks)).
- **Casdoor**: a bearer secret you generate, set as the webhook's `Authorization: Bearer <secret>` header
  ([idp-casdoor.md](idp-casdoor.md#webhook)). For example `openssl rand -hex 32`.

A missing or empty secret, or one with leading or trailing whitespace, fails the runtime load, with a reason
naming the source. A secret read from a file that ends with a newline is the usual cause: strip it.

Loading does not verify that the secret matches the IdP. A mismatched secret fails webhook authentication;
malformed Clerk base64 can cause `500 internal_error`. Neither is detected by `/healthz`.

To rotate a webhook secret:

- **Clerk**: rotate the endpoint's secret in Clerk first. For about 24 hours afterwards, Svix signs each
  delivery with both the old and the new secret ([Svix][svix-rotation], [Svix API][svix-rotate-api]), and the
  bridge accepts a delivery when any `v1` signature matches its secret. Deploy the new
  `WEBHOOK_SECRET_<SOURCE>` within that window, and no delivery fails.
- **Casdoor**: there is no overlap. Change the bridge's secret and the webhook's header together; deliveries in
  between fail with `401` and are retried. Casdoor reads the webhook's headers at each attempt
  ([source](https://github.com/casdoor/casdoor/blob/66b51eef9422bdd8f2f215f37ea29858548fb918/object/webhook_worker.go#L114-L129)),
  so its queued retries pick up the new header.

## Sizes

Function Compute and ESA limit the total size of a function's variables: keep within 4 KB on
[Function Compute](deploy-fc.md#configuration-and-secrets) and 16 KiB on ESA's free plan
([ESA](deploy-esa.md#variables)). Count all variable names and values, including webhook secrets, and leave
room for retired public keys during rotation.

Minify `BRIDGE_CONFIG`, for example with `node -e 'process.stdout.write(JSON.stringify(require("./bridge-config.json")))'`.

## Logs

The bridge writes one JSON line per request:

```json
{"route":"token","status":400,"ms":31,"outcome":"rejected","product":"acme","idp":"clerk-acme","code":"too_old"}
{"route":"webhook","status":200,"ms":184,"outcome":"ok","source":"clerk-acme","idp":"clerk-acme","delivered":1,"failed":0}
```

| Field | Value |
|---|---|
| `route` | `token`, `jwks`, `health`, `webhook`, or `other` for unknown paths |
| `status` | The status answered |
| `ms` | Time taken, in milliseconds |
| `outcome` | `ok` for `2xx`, `rejected` for `4xx`, `error` for `5xx` |
| `code` | The log code below, when there is one |
| `product` | The product id, once `audience` resolved |
| `idp` | The IdP id, once known |
| `source` | The webhook source id, from the path |
| `delivered`, `failed` | For webhooks, how many deliveries succeeded and failed |

Logs never hold tokens, emails, phone numbers or payload content.

### Log codes

| Code | Route | Meaning |
|---|---|---|
| `bad_request` | token | The request's shape: content type, a missing, repeated or invalid parameter, `scope`, `resource`, an actor token |
| `too_large` | token, webhook | The body is over the limit |
| `unsupported_grant` | token | `grant_type` is not token exchange |
| `unknown_product` | token | `audience` names no product |
| `malformed_token` | token | The subject token is not a well-formed JWT, its `iss` is not a string, a time claim is not a number, or it uses an unsupported `crit` extension |
| `untrusted_issuer` | token | No binding of the product has the token's `iss` |
| `bad_algorithm` | token | `alg` is outside the IdP's `algorithms` |
| `bad_signature` | token | The signature does not verify |
| `unknown_key` | token | No single key of the IdP's JWKS matches the token |
| `expired` | token | `exp` has passed |
| `too_old` | token | `iat` is older than `maxTokenAgeSeconds` |
| `not_yet_valid` | token | `nbf` or `iat` is in the future |
| `missing_claim` | token | `exp` or `iat` is missing, or `sub` is missing or not a non-empty string |
| `claim_mismatch` | token | A `requiredClaims` value differs |
| `client_mismatch` | token | The client binding failed: `clientIds` or `authorizedParties` |
| `bad_uid` | token, webhook | A malformed `uid` override |
| `jwks_unavailable` | token | The IdP's JWKS could not be fetched, timed out after 5 seconds, or was invalid, including a key the bridge cannot use, such as RSA under 2048 bits |
| `unknown_source` | webhook | The path names no webhook source |
| `bad_webhook_auth` | webhook | The signature, timestamp or bearer secret check failed |
| `bad_payload` | webhook | Authenticated but unprocessable |
| `ignored` | webhook | Authenticated, but the event is not relayed |
| `delivery_failed` | webhook | At least one delivery failed |
| `runtime_unavailable` | any | The runtime failed to load ([failure mode](api.md#failure-mode)) |
| `internal_error` | any | An unexpected exception |
| `client_closed` | any | The connection ended before the request was read completely: the client went away, or the server's request timeout fired. Logged with `status` 499 and `outcome` `rejected`; the client receives no answer. Only the Node entry can see the connection, so only it logs this code |

Useful alerts: any `runtime_unavailable` or `internal_error`; `delivery_failed`, `bad_payload` or `bad_uid` on
webhooks; a rise of `jwks_unavailable`; and, after an IdP change, `untrusted_issuer`, `claim_mismatch` or
`client_mismatch`.

### Runtime load failures

Once per isolate or process, a runtime that failed to load also writes:

```json
{"event":"runtime_load_failed","reason":"config: products.acme.idps[0].idp: unknown idp \"clerk-acm\""}
```

The reason names what failed and never contains secret material. Its forms:

| Reason | Cause |
|---|---|
| `missing BRIDGE_CONFIG`, `missing SIGNING_KEYS` | The variable is not set or is empty |
| `config: <path>: <problem>` | The configuration is invalid at that JSON path, such as `config: products.acme.allowedOrigin: unknown key` |
| `SIGNING_KEYS...: <problem>` | The keys are invalid, such as `SIGNING_KEYS.active: private key required` or `SIGNING_KEYS.retired[0]: private key not allowed` |
| `missing webhook secret for source <id>` | `WEBHOOK_SECRET_<SOURCE>` is not set or is empty |
| `webhook secret for source <id> has surrounding whitespace` | The secret starts or ends with whitespace, such as a newline |
| `unexpected error` | Anything else |

The Node entry also logs `{"event":"listening","host":"0.0.0.0","port":8080}` once it accepts connections, and
`{"event":"stopping","signal":"SIGTERM"}` when it begins to stop ([deploy-node.md](deploy-node.md#stopping)).

[svix-rotation]: https://www.svix.com/blog/svix-update-december-2021-part-1/
[svix-rotate-api]: https://pkg.go.dev/github.com/svix/svix-webhooks/go#Endpoint.RotateSecret
