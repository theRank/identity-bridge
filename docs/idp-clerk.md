# Clerk

How to set up [Clerk][clerk-docs] for the bridge. The matching bridge configuration is the
[Clerk example](configuration.md#a-clerk-deployment).

## Applications

Use one Clerk application per product. Each application's instance has its own Frontend API URL, which is the
`iss` of its session tokens ([session tokens][clerk-session-tokens]), so the issuer already tells products
apart and the binding needs no `clientIds`:

```json
"idps": {
  "clerk-acme": {
    "issuer": "https://clerk.acme.example",
    "jwksUri": "https://clerk.acme.example/.well-known/jwks.json",
    "algorithms": ["RS256"],
    "claims": { "uid": "uid", "email": "email", "emailVerified": true, "name": "name", "picture": "picture" }
  }
}
```

- `issuer` is the instance's Frontend API URL, exactly as it appears in `iss`, and `jwksUri` is that URL
  followed by `/.well-known/jwks.json` ([JWKS][clerk-jwks]). Clerk signs session tokens with RS256, as its
  verification example shows ([JWKS][clerk-jwks]).
- Development and production instances have different Frontend API URLs
  ([session tokens][clerk-session-tokens]), so each needs an IdP record of its own, usually in a bridge
  deployment of its own.
- Leave out `authorizedParties`. Clerk sets a session token's `azp` from the `Origin` header of the request,
  and leaves it out when `Origin` is empty or missing ([session tokens][clerk-session-tokens]). Browsers send
  `Origin` ([MDN][mdn-origin]); native apps usually do not, so their tokens have no `azp`, and
  `authorizedParties` would reject them, as it does in Clerk's own backend SDK ([changelog][clerk-azp-change]).
  The product's browser origins go in `allowedOrigins` instead, which only controls [CORS](api.md#cors).

## Session token

Clerk's default session token carries no email ([default claims][clerk-default-claims]). Add the claims the
bridge maps in the Clerk Dashboard, on the **Sessions** page, under **Customize session token**
([customizing][clerk-customize]), with Clerk's shortcodes ([shortcodes][clerk-shortcodes]):

```json
{
  "email": "{{user.primary_email_address}}",
  "name": "{{user.full_name}}",
  "picture": "{{user.image_url}}",
  "uid": "{{user.external_id}}"
}
```

- Leave out `uid` when you do not use the [user id override](#user-id-override). A shortcode whose value is
  not set renders as `null` ([shortcodes][clerk-shortcodes]), which the bridge reads as no value: no override,
  no name.
- The session token is kept in a cookie, so Clerk advises keeping custom claims under about 1.2 KB
  ([customizing][clerk-customize]); these four are well within it. Do not add others for the bridge: it reads
  only the mapped claims.
- Clerk's session tokens expire after 60 seconds, and `getToken()` returns a valid one, from its cache or newly
  minted ([`getToken()`][clerk-gettoken]), so a token can be up to a minute old. That is far younger than the
  default `maxTokenAgeSeconds` of 900; for Clerk, keep it at 60 or more, although the configuration allows 30.

## Email verification

The mapping sets `"emailVerified": true`: it trusts that a session token's email is verified, because Clerk
has no shortcode for the primary address's verification. `{{user.email_verified}}` says whether the user has
any verified address ([shortcodes][clerk-shortcodes]), which is not the same.

Make the trust hold by keeping **Verify at sign-up** on for email addresses, on the **User & authentication**
page of the Clerk Dashboard. It is on by default ([verification][clerk-email-verify]). Without it, a user could
sign up with someone else's address, and products would receive it as verified.

## User id override

Clerk users have a derived bridge user id ([user ids](api.md#user-ids)) unless an override is set. To keep the
ids users had before a migration to Clerk, write each user's previous bridge user id into the user's
`external_id`:

- Set it from a backend, when creating or updating the user ([create][clerk-create-user],
  [update][clerk-update-user]). Clerk's Frontend API does not accept it ([Frontend API][clerk-fapi-me]), so
  users cannot change it themselves.
- It must be a canonical UUID, other than all zeros or all `f`. Clerk requires only that it be unique
  ([update][clerk-update-user]), but the bridge fails every exchange of a user whose `external_id` is anything
  else (`bad_uid`), and relays none of their events.
- Map it as the session token's `uid` claim, as above, set `"uid": "uid"` in the IdP's claims and
  `"uidField": "external_id"` on the webhook source.

The override lives in `external_id` rather than in metadata because it must reach the bridge in every user
event, deletions included. Clerk's `user.created` and `user.updated` events carry the whole user
([webhooks][clerk-webhooks]), with `external_id` ([source][clerk-user-json]), but `user.deleted` carries only
the user's id and, if one is set, `external_id` ([source][clerk-deleted-json]). An override kept in
`public_metadata` would be missing from the deletion, which would then carry the wrong user id.

## Webhooks

On the **Webhooks** page of the Clerk Dashboard, select **Add Endpoint** ([setting up][clerk-webhook-setup]):

- URL `https://<bridge>/webhooks/<source>`, such as `https://id.acme.example/webhooks/clerk-acme`;
- events `user.created`, `user.updated` and `user.deleted`. The bridge ignores other events, so subscribing
  to them only adds requests.

Copy the endpoint's signing secret, `whsec_...` ([webhooks][clerk-webhooks]), into the source's
[webhook secret](configuration.md#webhook-secrets), `WEBHOOK_SECRET_CLERK_ACME` for the source `clerk-acme`;
that section also gives the rotation that loses no delivery.

Clerk delivers webhooks through Svix ([webhooks][clerk-webhooks]), which signs each one
([verifying][svix-verify]) and retries a delivery not answered with a `2xx`, on a schedule that runs for more
than a day ([retries][svix-retries]). The bridge answers `502` when a delivery to any product fails, so Svix
sends the webhook again, with the same `svix-id` ([verifying][svix-verify]), and products drop the repeat by
its `jti` ([fan-out](api.md#fan-out)). Clerk does not promise an order ([webhooks][clerk-webhooks]).

## Clients

Clients pass a fresh session token to the bridge: [integrate.md](integrate.md#clerk).

[clerk-docs]: https://clerk.com/docs
[clerk-session-tokens]: https://clerk.com/docs/guides/sessions/session-tokens
[clerk-default-claims]: https://clerk.com/docs/guides/sessions/session-tokens#default-claims
[clerk-jwks]: https://clerk.com/docs/guides/sessions/manual-jwt-verification#get-your-instances-public-key
[clerk-customize]: https://clerk.com/docs/guides/sessions/customize-session-tokens
[clerk-shortcodes]: https://clerk.com/docs/guides/sessions/jwt-templates#available-shortcodes
[clerk-gettoken]: https://clerk.com/docs/js-frontend/reference/objects/session#gettoken
[clerk-azp-change]: https://github.com/clerk/javascript/blob/c9bdae3b0aef91699a73824fecc6726959196ab4/packages/backend/CHANGELOG.md#L489-L493
[clerk-email-verify]: https://clerk.com/docs/guides/configure/auth-strategies/social-connections/account-linking#email-address-is-unverified-in-clerk
[clerk-create-user]: https://clerk.com/docs/reference/backend/user/create-user#createuserparams
[clerk-update-user]: https://clerk.com/docs/reference/backend/user/update-user#parameters
[clerk-fapi-me]: https://clerk.com/docs/reference/frontend-api/2026-08-20/tag/user/PATCH/v1/me
[clerk-webhooks]: https://clerk.com/docs/guides/development/webhooks/overview
[clerk-webhook-setup]: https://clerk.com/docs/guides/development/webhooks/syncing#set-up-a-webhook-endpoint
[svix-verify]: https://docs.svix.com/receiving/verifying-payloads/how-manual
[svix-retries]: https://docs.svix.com/retries
[mdn-origin]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Origin
[clerk-user-json]: https://github.com/clerk/javascript/blob/c9bdae3b0aef91699a73824fecc6726959196ab4/packages/backend/src/api/resources/JSON.ts#L695
[clerk-deleted-json]: https://github.com/clerk/javascript/blob/c9bdae3b0aef91699a73824fecc6726959196ab4/packages/backend/src/api/resources/JSON.ts#L747-L764
