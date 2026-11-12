# identity-bridge

**Pre-alpha, under construction.** Nothing here is ready to deploy or depend on yet.

A stateless bridge that gives products one way to know who the user is, whichever identity provider
signed them in. A client exchanges a Clerk or Casdoor token for the bridge's own short-lived access token
through RFC 8693 token exchange; products verify that token against the bridge's JWKS and never handle
provider-specific tokens. The bridge also relays the providers' user lifecycle webhooks to products as
signed security event tokens, and ships TypeScript SDKs for clients and product backends.

## Security

See [SECURITY.md](SECURITY.md).

## License

[Apache-2.0](LICENSE)
