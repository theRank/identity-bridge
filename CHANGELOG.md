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
  only new users and organization admins' deletions.
- One JSON configuration document, checked at load, and a failure mode that keeps answering `/healthz` with
  `503` when the configuration, the keys or a webhook secret cannot be loaded.
- One JSON log line per request, without tokens or personal data.

### Runtimes and artifacts

- Entries for Cloudflare Workers, Node 24 and Alibaba Cloud ESA Functions and Pages.
- `server.mjs`, a single-file Node bundle, and `esa.js`, a single-file ESA bundle, attached to each GitHub
  release with their SHA-256.
- A `Dockerfile` and a multi-architecture image on GitHub Container Registry.
- Workers Logs turned on by the repository's `wrangler.jsonc`, for the bridge's own log lines only.
- `scripts/smoke.ts`, a post-deploy smoke test; `scripts/deploy-esa.ts`, an ESA deploy through its OpenAPI;
  `scripts/dev-env.ts`, throwaway values for local runs.

### Packages

- `@therank/identity-bridge-client`: exchange, in-memory cache, refresh and retries, with a WeChat mini program
  entry point for Casdoor's mini program login.
- `@therank/identity-bridge-server`: verification of access tokens and events, every check fixed.

### Documentation

- API reference, configuration, setup guides for Clerk and Casdoor, deployment guides for Workers, Function
  Compute, ESA and Node, and a product integration guide with Go and Python examples.
