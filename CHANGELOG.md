# Changelog

The service and both npm packages share one version, following [Semantic Versioning](https://semver.org). A
breaking change to the [wire contract](docs/api.md) is a new major version of all three.

## 1.0.0 (unreleased)

### Service

- `POST /token`: [RFC 8693](https://www.rfc-editor.org/rfc/rfc8693) token exchange of a Clerk or Casdoor JWT
  for a bridge access token, with an IdP binding per product, an algorithm allowlist, a maximum IdP token age,
  required claim values, client binding, claim mapping and CORS. One error for every rejected subject token,
  with the precise reason as a log code.
- Phone numbers an IdP stores as a national number and a region, as Casdoor does, joined into E.164 through the
  `phoneRegion` claim mapping, in access tokens and `user-created` events.
- Access tokens following [RFC 9068](https://www.rfc-editor.org/rfc/rfc9068), signed with ES256 only.
- User ids derived as UUIDv5 of the IdP issuer and subject, or taken from an administrator-set override.
- `GET /.well-known/jwks.json`, with retired keys for rotation.
- `GET /healthz`, with a WebCrypto self-test.
- `POST /webhooks/{source}`: Clerk (Svix-signed) and Casdoor (bearer secret) user lifecycle webhooks relayed
  to products as [RFC 8417](https://www.rfc-editor.org/rfc/rfc8417) security event tokens, pushed as in
  [RFC 8935](https://www.rfc-editor.org/rfc/rfc8935), with deterministic event ids. Casdoor webhooks relay
  only new users and organization admins' deletions, and need Casdoor 4.28 or later.
- One JSON configuration document, checked at load, and a failure mode that keeps answering `/healthz` with
  `503` when the configuration, the keys or a webhook secret cannot be loaded.
- One JSON log line per request, without tokens or personal data.
- `updated_at` in access tokens and in `user-created` / `user-updated` event profiles, when the IdP maps the new
  `updatedAt` claim: when the IdP's state of the profile was current, so products keep the newest profile
  whatever the order tokens and events arrive in. Clerk takes it from the session token claim
  `{{user.updated_at}}` and the webhook's `data.updated_at`, Casdoor from its token's `iat` and the record's
  `createdTime`. The log line reports a token or event that should carry one but does not.

### Runtimes and artifacts

- Entries for Cloudflare Workers, Node 24 and Alibaba Cloud ESA Functions and Pages.
- `server.mjs`, a single-file Node bundle, and `esa.js`, a single-file ESA bundle, attached to each GitHub
  release with their SHA-256.
- A `Dockerfile` and a multi-architecture image on GitHub Container Registry.
- Workers Logs turned on by the repository's `wrangler.jsonc`, for the bridge's own log lines only.
- `scripts/smoke.ts`, a post-deploy smoke test; `scripts/deploy-esa.ts`, an ESA deploy through its OpenAPI;
  `scripts/dev-env.ts`, throwaway values for local runs.
- `scripts/e2e-casdoor.ts`, the bridge against a real Casdoor: the pinned version on changes to the service,
  and weekly both it and Casdoor's newest release.
- `scripts/e2e-clerk.ts`, the bridge against a real Clerk instance, run on changes to the service and weekly,
  except for fork and Dependabot pull requests.

### Packages

- `@therank/identity-bridge-client`: exchange, in-memory cache, refresh and retries, with a WeChat mini program
  entry point for Casdoor's mini program login.
- `@therank/identity-bridge-server`: verification of access tokens and events, every check fixed, with each
  profile's `updatedAt`.

### Documentation

- API reference, configuration, setup guides for Clerk and Casdoor, deployment guides for Workers, Function
  Compute, ESA and Node, and a product integration guide with Go and Python examples.
