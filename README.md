# identity-bridge

A stateless identity broker. A client signs the user in with an identity provider (IdP), Clerk or Casdoor
today, and exchanges the IdP's token for the bridge's own short-lived access token through
[RFC 8693](https://www.rfc-editor.org/rfc/rfc8693) token exchange. Product backends trust one issuer, their
bridge deployment, and verify its tokens against its JWKS; they never handle an IdP's tokens. The bridge also
relays the IdPs' user lifecycle webhooks to products as signed security event tokens, so products never handle
an IdP's webhook format either.

Adding or replacing an IdP is a configuration change, not a change to any product. The repository holds the
code, the release artifacts and TypeScript SDKs for clients and backends; each deployer keeps its own
configuration and deployment.

**Status:** 1.0.0 is in preparation and not yet tagged; v0.0.1 and v0.0.2 are test releases. See the
[changelog](CHANGELOG.md).

```text
                    1 sign in
  client ─────────────────────────────→ IdP (Clerk, Casdoor)
    │
    │ 2 POST /token with the IdP token          verified with the IdP's JWKS
    ├─────────────────────────────→ identity-bridge
    │ ←── bridge access token
    │
    │ 3 API call with the bridge token          verified with the bridge's JWKS
    └─────────────────────────────→ product backend

  IdP ── 4 user webhook ──→ identity-bridge ── 5 signed event ──→ product backend
```

## Guarantees

- **Stateless.** No database, key-value store or queue. A request needs only the configuration, the signing
  key and the request itself. Replicas share nothing, and it runs wherever a Web-standard fetch handler runs.
- **Bounded revocation.** The bridge cannot see that an IdP banned a user or ended a session. It refuses IdP
  tokens older than `maxTokenAgeSeconds`, so every exchange needs a fresh IdP token, which the IdP issues only
  to a user it still accepts. A user cut off at the IdP keeps access for at most about 32 minutes with the
  defaults ([why](docs/api.md#processing)).
- **Stable user ids.** A user's id is the UUIDv5 of the IdP's issuer and subject under a fixed namespace, or an
  id set by an administrator in the IdP. The token and the webhook paths give the same id for the same person,
  and the override keeps ids across a migration to another IdP.
- **One format.** Access tokens follow RFC 9068, signed with ES256 only, and carry the user id and, when the IdP
  verified them, the email and phone number, whatever the IdP.
- **Uniform errors, no personal data in logs.** Every rejected IdP token gets the same error; the precise reason
  goes to a log code. Logs never hold tokens, emails, phone numbers or payloads.

The bridge does not provide sign-in screens, sessions, refresh tokens, a user directory, roles or permissions,
or linking one person's accounts across IdPs, and it is not an OpenID Provider. IdPs sign users in; products
keep their own authorization, keyed by the bridge's user id.

## Documentation

- [API](docs/api.md): the endpoints, the access token, user ids, webhooks and event tokens.
- [Configuration](docs/configuration.md): the configuration document, secrets, key rotation and logs.
- IdP setup: [Clerk](docs/idp-clerk.md), [Casdoor](docs/idp-casdoor.md), WeChat mini programs included.
- Deployment: [Cloudflare Workers](docs/deploy-workers.md),
  [Alibaba Cloud Function Compute](docs/deploy-fc.md), [Alibaba Cloud ESA](docs/deploy-esa.md),
  [Node and containers](docs/deploy-node.md).
- [Integrating a product](docs/integrate.md): clients, backends, Go and Python, events and data rules.
- [Changelog](CHANGELOG.md).

## Packages

| Package | For |
|---|---|
| [`@therank/identity-bridge-client`](packages/client/README.md) ([npm](https://www.npmjs.com/package/@therank/identity-bridge-client)) | Browsers, Node.js and WeChat mini programs: exchanges IdP tokens, keeps the bridge token in memory and refreshes it |
| [`@therank/identity-bridge-server`](packages/server/README.md) ([npm](https://www.npmjs.com/package/@therank/identity-bridge-server)) | Product backends: verifies access tokens and events with every check fixed |

Both share the bridge's release version. Backends in other languages use a JWT library: see
[integrate.md](docs/integrate.md#other-languages).

## Choosing a runtime

One deployment is one issuer, one key set and one configuration. A product serving users both outside and
inside mainland China runs two: one trusting Clerk, one trusting Casdoor.

| Runtime | Where | Notes |
|---|---|---|
| [Cloudflare Workers](docs/deploy-workers.md) | Outside mainland China | The Free plan allows 100,000 requests a day and 10 ms of CPU time per request ([limits](https://developers.cloudflare.com/workers/platform/limits/#account-plan-limits)) |
| [Alibaba Cloud ESA](docs/deploy-esa.md) | Mainland China, on an ICP-filed domain | No cold start observed. A request may make 10 fetches on the free plan, 100 on Advanced, so a webhook source relays to at most that many products; 16 KiB of variables on the free plan ([billing](https://help.aliyun.com/en/edge-security-acceleration/esa/user-guide/functions-and-pages-billing)) |
| [Alibaba Cloud Function Compute](docs/deploy-fc.md) | Mainland China, on an ICP-filed domain | The Node bundle as a code package. No fan-out limit. Observed: cold starts after idle minutes, unless an instance is kept. Variables documented as 4 KB in total ([environment variables](https://www.alibabacloud.com/help/en/functioncompute/environment-variables)) |
| [Node](docs/deploy-node.md) | Any host | The Node bundle or the container image, on a host you run |

In mainland China, choose ESA when cold starts matter and every webhook source's products fit within ESA's
fetch limit; Function Compute otherwise; and the container when you already run the host of a self-hosted
Casdoor, beside it.

## Releases

Releases are tagged `vX.Y.Z`. Deployments pin a tag. Each release has:

- on its [GitHub release](https://github.com/theRank/identity-bridge/releases), `server.mjs`, the single-file
  Node bundle, and `esa.js`, the single-file ESA bundle, each with a `.sha256` file;
- the image `ghcr.io/therank/identity-bridge:X.Y.Z`, for `linux/amd64` and `linux/arm64`; the highest release
  that is not a prerelease also gets `X.Y` and `latest`;
- both npm packages at version `X.Y.Z`.

Workers deployments build from the tag's source.

## Smoke test

`scripts/smoke.ts` checks a running deployment from outside; run it after every deploy. It needs Node 24 or
later, nothing installed, no secret and no IdP token:

```sh
node scripts/smoke.ts https://id.acme.example acme
```

It checks that `/healthz` answers `200 {"status": "ok"}`, which needs the configuration, the keys and every
webhook secret to have loaded and the crypto self-test to pass; that the JWKS has an ES256 key with a `kid` and
no private key; that `/token` gives the expected error for a junk subject token, an unknown audience, another
grant type and a scope; and that an unknown path is `404`. It exits with `1` on any mismatch. Each
`--header 'name: value'` is sent with every request, such as the cookie an
[ESA default domain](docs/deploy-esa.md#default-domain-and-staging) needs; header values are never printed.

## Development

Requires Node 24 or later. The service is TypeScript on Web-standard APIs, with [jose](https://github.com/panva/jose)
as its only runtime dependency. Runtime entries are in `src/runtimes`.

```sh
npm ci
npm test            # Vitest, in the Workers runtime and in plain Node
npm run typecheck   # wrangler types, then tsc over the service, tests, scripts and packages
npm run build       # the Workers bundle (dry run), server.mjs, esa.js and the packages
npm run test:node --workspaces --if-present   # the packages' plain-Node checks, after the build
npm run dev         # a local Worker, reading .dev.vars
```

`node scripts/dev-env.ts` prints throwaway values on `*.example` hosts for local runs; see
[deploy-node.md](docs/deploy-node.md#trying-it-locally).

## Security

See [SECURITY.md](SECURITY.md).

## License

[Apache-2.0](LICENSE).
