# Casdoor

How to set up a self-hosted [Casdoor][casdoor-docs] instance for the bridge, including WeChat mini program
sign-in. One Casdoor instance can serve several products. The matching bridge configuration is the
[Casdoor example](configuration.md#a-casdoor-deployment).

Casdoor's documentation does not describe all of what the bridge relies on, and in places differs from what
Casdoor does. Where it does, this guide links to Casdoor's source at release
[4.29.0][casdoor-commit], the version this release was checked against. The repository's
[`scripts/e2e-casdoor.ts`](../scripts/e2e-casdoor.ts) runs the bridge against a Casdoor set up this way, and
its CI repeats that weekly with Casdoor's newest release.

## Instance

- **Set `origin`.** Set `origin` in Casdoor's `conf/app.conf` to its public URL, such as
  `https://casdoor.example` ([configuration][casdoor-config]). Casdoor builds the issuer from `origin`, or from
  the host of each request when `origin` is empty ([Casdoor][casdoor-issuer-doc], [source][casdoor-origin]),
  so without it a token requested through another host name fails as `untrusted_issuer`.
- **IdP record.** Use that URL as the IdP's `issuer`, `<origin>/.well-known/jwks` as its `jwksUri`
  ([OIDC discovery][casdoor-oidc]), and the applications' token signing method, `RS256` unless an application
  sets another ([source][casdoor-signing-method]), as its `algorithms`. The bridge does not accept `ES512` or
  SM2, which Casdoor also offers.
- **Issuer per organization.** Every organization of an instance shares its issuer, unless an organization is
  set to use an issuer of its own ("Use organization issuer"), which is then `<origin>/orgs/<organization>`
  ([source][casdoor-org-issuer]; one Casdoor page says tokens always carry the shared issuer, which the source
  does not bear out). This guide assumes the shared issuer. An organization with its own issuer needs an IdP
  record of its own, with that issuer.

## Organizations and applications

- One organization per product: it is the product's user pool.
- One application per client: web, App, WeChat mini program ([applications][casdoor-application]).
- Each application's client id in the product's binding, under `clientIds`:

  ```json
  "idps": [{ "idp": "casdoor", "clientIds": ["<web client id>", "<app client id>", "<mini program client id>"] }]
  ```

On a shared instance every organization has the same issuer, so neither the issuer nor `requiredClaims` can
tell one organization's tokens from another's. The client id can: Casdoor puts it in a token's `aud` and
`azp` ([source][casdoor-claims]). The bridge therefore requires `clientIds` or `authorizedParties` on every
binding of an IdP that several products bind, and refuses a client id listed for two products
([rules](configuration.md#rules)). Without that, a user of one product could exchange their token for
another product's.

Two cases change `aud` ([source][casdoor-aud]):

- an application shared across organizations gives `aud` `<client id>-org-<organization>`, which is the value
  to list;
- a client that sends an RFC 8707 `resource` gets `aud` set to that resource, so clients must not send one.

## Sign-in providers

In each organization, enable only sign-in providers whose account ids cannot coincide.

A user who signs up through an OAuth provider gets the upstream account's id as their Casdoor `id`
([source][casdoor-oauth-id]), and that `id` is the token's `sub` ([source][casdoor-sub]). Casdoor does not
keep `id` unique ([source][casdoor-id-index]). So:

- within one organization, two providers whose account ids can be equal would give two people one `sub`, and
  so one bridge user;
- the same upstream account signed up in two organizations of one instance gets the same `id` in both, and
  so the same bridge user id. Products in different organizations could correlate such users.

Users who sign up with a password, a code or the mini program get a random id, unless the application's
sign-up item `ID` uses the `Incremental` rule, which numbers users 1, 2, 3 ([source][casdoor-incremental]):
such numbers can equal an upstream provider's numeric account ids, so keep the random rule when an OAuth
provider is enabled.

## Token format

Applications use the `JWT-Custom` token format ([token formats][casdoor-token-format]) with these token
fields:

| Token field | Claim | Bridge mapping |
|---|---|---|
| `Email` | `email` | `email` (the default) |
| `EmailVerified` | `emailVerified` | `"emailVerified": "emailVerified"` |
| `DisplayName` | `displayName` | `"name": "displayName"` |
| `Avatar` | `avatar` | `"picture": "avatar"` |
| `Properties.uid`, when the [override](#user-id-override) is used | `uid` | `"uid": "uid"` |

With `JWT-Custom`, a selected field becomes a claim in camel case, and `Properties.<key>` becomes a top-level
claim named `<key>` ([source][casdoor-custom-claims]). Fields that are not selected are not in the token.
Phone numbers take two more fields and a decision: see [Phone numbers](#phone-numbers).

The IdP record sets `requiredClaims` to `{"tokenType": "access-token"}`. Casdoor's access, refresh and ID
tokens are all JWTs signed with the same key, with the same `iss`; only `tokenType` tells them apart
([source][casdoor-token-types]). Without the check, a client could exchange a refresh token, which lives much
longer, or an ID token.

## Refresh tokens

The bridge refuses an IdP token older than `maxTokenAgeSeconds`, 15 minutes by default, whatever its `exp`
([why](api.md#processing)). Clients therefore refresh their Casdoor token before each exchange:

- add Refresh Token (`refresh_token`) to each web and App application's grant types
  ([application settings][casdoor-app-settings]): Casdoor allows only `authorization_code` unless a grant is
  listed ([source][casdoor-grant-types]);
- set the application's "Refresh token expire" ([refreshing tokens][casdoor-refresh-doc]); left at 0, the
  refresh token expires with the access token ([source][casdoor-refresh-expiry]).

Casdoor's `refresh_token` grant loads the user again and refuses a deleted or forbidden one
([source][casdoor-refresh-user]), which is what makes the age limit a revocation bound. Mini programs do not
refresh: they call [`wx.login`][wx-login] again for a new code.

## User id override

To keep user ids across a migration to Casdoor, write each user's previous bridge user id into a `Properties`
key, such as `uid`, select `Properties.uid` as a token field, and configure `"uid": "uid"` in the IdP's claims
and `"uidField": "uid"` on the webhook source ([user ids](api.md#user-ids)).

- The value must be a canonical UUID, other than all zeros or all `f`. Any other value fails every exchange of
  that user (`bad_uid`).
- Pin the organization's `Properties` account item to the modify rule `Admin`
  ([account items][casdoor-account-items]). The override is only as safe as its write permission: a user who
  could edit `Properties` could set another user's id and sign in as them. `Admin` is the default
  ([source][casdoor-properties-default]), but each organization can change it ([source][casdoor-modify-rule]).

## Phone numbers

Casdoor stores a phone number as a national number and a region, such as `13800138000` and `CN`, and keeps no
verification flag for it ([source][casdoor-user-fields]). The bridge therefore issues no phone number until the
IdP's claims say to trust Casdoor's handling of it. Select the token fields `Phone` and `CountryCode`, and add:

```json
"claims": { "phone": "phone", "phoneRegion": "countryCode", "phoneVerified": true }
```

The bridge joins the two into an E.164 number, `+8613800138000`, in access tokens and in `user-created` events.
A number that makes none with its region is left out: an unknown region, a trunk prefix (`013800138000`), a
number already in international form.

Casdoor stores the national number as an integer, so without any leading zero ([source][casdoor-phone-integer]).
Where that zero belongs to the number, as in Italian fixed lines and the numbers of Côte d'Ivoire and Congo,
Casdoor refuses a user's change to such a number as invalid, and stores one an administrator writes without the
zero: `0212345678` in Italy becomes `212345678`, which the bridge joins into `+39212345678`, not the number
meant. Do not map the phone for an organization whose administrators or syncers write such numbers.

`"phoneVerified": true` is sound only while every number a user can store was confirmed by a code. Casdoor
checks one when a user signs up with a phone ([source][casdoor-phone-signup]), signs up by a verification
code ([source][casdoor-phone-code-signup]), changes their number ([source][casdoor-phone-reset]) or sets up SMS
MFA ([source][casdoor-phone-mfa]), and it does not let users write the number through `update-user`
([source][casdoor-self-columns]). Keep these settings, on which that rests:

- **Sign-up item `Phone`: any rule but `No verification`**, which skips the code
  ([source][casdoor-phone-signup]).
- **Account item `Country code`: present, with the modify rule `Admin`.** Users may write their own region
  when the item allows it, or when the organization has no such item ([source][casdoor-region-item],
  [source][casdoor-modify-rule-nil]), and the same digits are another number in another region: `2087654321`
  is a number in the United States and in China. `Admin` is the default ([source][casdoor-region-default]).
- **Sign-in providers that report no phone number, or whose numbers you trust.** A user who signs up through
  an OAuth provider gets the number the provider reports, unchecked ([source][casdoor-phone-oauth]), and a
  Custom provider's user mapping can fill in a missing one ([source][casdoor-phone-mapping]). A mini program
  user's number comes from WeChat's phone number authorization ([source][casdoor-phone-miniprogram]).

Administrators, application credentials, syncers and uploads write numbers without a code. They are trusted
here as they are for the [user id override](#user-id-override).

These paths were also exercised against Casdoor 4.29.0: a sign-up and a change of number were refused without
the code, a user's `update-user` left the number alone, their change of region was refused under `Admin` and
accepted without the account item, and an administrator's `0212345678` was stored as `212345678`.

## Webhook

One Casdoor webhook per organization, each relayed by one bridge source that names that organization. Casdoor's
[webhook documentation][casdoor-webhooks] shows a payload that differs from what Casdoor sends: Casdoor sends
the [record][casdoor-records] of the API call. Those docs also leave out the extended user option, the token
fields and the names of the retry fields.

Webhooks need Casdoor 4.28 or later. The bridge names each event by the id of its record
([event id](api.md#casdoor-sources)), which earlier releases send as `0`. Those ids number the rows of one
database: after a restore from a backup, or a move to a new database that does not carry the records over,
Casdoor gives out ids it has used before, and products discard the events that carry them as repeats.

| Setting | Value |
|---|---|
| URL | `https://<bridge>/webhooks/<source>`, such as `https://id.cn.acme.example/webhooks/casdoor-acme` |
| Method, content type | `POST`, `application/json` |
| Headers | `Authorization: Bearer <secret>`, the source's [webhook secret](configuration.md#webhook-secrets) |
| Events | `new-user` and `delete-user` only |
| Is user extended (`isUserExtended`) | on |
| Token fields (`tokenFields`) | none |
| Object fields (`objectFields`) | All |
| Single org only (`singleOrgOnly`) | on |
| Organization | the product's organization |

The bridge source:

```json
"webhookSources": {
  "casdoor-acme": { "type": "casdoor", "idp": "casdoor", "organization": "acme", "uidField": "uid", "products": ["acme"] }
}
```

Why each setting:

- **A public address.** The webhooks of every organization but `built-in` may send requests only to Internet
  addresses ([Casdoor][casdoor-webhooks], [source][casdoor-public-only]), so the bridge must be reachable at
  one.
- **`organization` on the source.** The bridge drops any record, caller or deleted user of another
  organization itself ([filters](api.md#casdoor-sources)), whatever the webhook's options.
- **Only `new-user` and `delete-user`.** The console proposes `signup`, `login`, `logout` and `update-user`
  for a new webhook ([source][casdoor-console-default]): replace them. A `signup` record carries the sign-up
  form, whose `confirm` field holds the password in plain text, since Casdoor's mask list covers `password`
  but not `confirm` ([source][casdoor-mask]). The bridge ignores every other action anyway.
- **Extended user on, no token fields.** The bridge trusts a deletion only when the caller, `extendedUser`, is
  an admin of the organization. With the option off, Casdoor sends `extendedUser: null`
  ([source][casdoor-extended-user]), and every deletion is ignored, visible only as an `ignored` log line.
  Token fields would reduce `extendedUser` to the selected fields ([source][casdoor-token-fields]).
- **Object fields All.** Selected object fields filter `object` down to them ([source][casdoor-object-fields]),
  which can drop the user's `id`, `owner` or `properties`. Leaving none selected sends the whole object too.
- **Single org only on.** Off, a webhook receives the records of every organization ([Casdoor][casdoor-webhooks],
  [source][casdoor-single-org]). The bridge drops them, so this is a second line of defense: with it on, other
  organizations' records never leave Casdoor. Only a global admin can turn it off
  ([source][casdoor-single-org-admin]), and the console creates a webhook without it
  ([source][casdoor-console-default]), so check it on a webhook a global admin created.
- **Whole user rows on deletion.** When `uid` is mapped, a deletion's `object` must carry the user's
  `properties`, an object or `null`; without the member the bridge cannot tell "no override" from "override not
  sent", and answers `bad_payload`. Casdoor's console sends the whole user row. A deletion through the API
  must do the same.

### Retries

The bridge answers `502` when a delivery to any product fails, and Casdoor then delivers the webhook again.
Casdoor's defaults give up quickly: three attempts in total ([Casdoor][casdoor-webhooks]), a minute apart.
Set these webhook fields through Casdoor's API, since the console does not show them
([source][casdoor-webhook-struct]):

| Field | Meaning | Suggested |
|---|---|---|
| `maxRetries` | Attempts in total, not retries; default 3 | `10` |
| `retryInterval` | Seconds before the next attempt; default 60 | `60` |
| `useExponentialBackoff` | Double the wait after each attempt, up to an hour | `true` |

With the suggested values the attempts spread over about four hours. Casdoor's worker checks for due
deliveries every 30 seconds, so attempts are never closer than that ([source][casdoor-worker]). After an
attempt that gets a `5xx` answer, as the bridge's `502` is, or none, the webhook's later events wait for the
worker's next round ([source][casdoor-worker-order]).

`maxRetries` is copied into each delivery when Casdoor queues it ([source][casdoor-queue]); the interval, the
backoff and the headers are read from the webhook at each attempt ([source][casdoor-attempt]). Raising
`maxRetries` therefore applies only to later events, while a rotated bearer secret also applies to deliveries
already queued.

To set the fields, read the webhook with `GET /api/get-webhook?id=admin/<webhook name>`, change them, and post
the whole object back to `POST /api/update-webhook?id=admin/<webhook name>`, as an admin
([API][casdoor-api], [source][casdoor-webhook-api]). An organization admin must add
`&organization=<organization>` to the `get-webhook` request, or Casdoor answers `null`; a global admin need not
([source][casdoor-get-webhook], [source][casdoor-get-webhook-org]). The instance's Swagger page may not list the retry fields;
Casdoor reads them anyway ([source][casdoor-webhook-struct]).

### Restart after the first webhook

Casdoor starts its delivery worker at boot, and only when a webhook exists ([source][casdoor-worker-start]).
After adding the instance's first webhook, restart Casdoor, or nothing is delivered.

## What is not relayed

Casdoor's webhook body is an audit record of an API call, and for most actions its `object` is whatever the
caller sent. The bridge relays only what it can trust ([mapping](api.md#casdoor-sources)), so products do not
receive:

- **Profile updates.** An `update-user` body is the caller's, and users may update their own accounts.
  Products see a changed profile in the claims of the user's next access token.
- **Users created without a sign-up flow**: an admin's `add-user`, bulk uploads, LDAP or database syncers, and
  mini program code login. Only the sign-up flows ask for a `new-user` record ([password and code
  sign-up][casdoor-signup-record], [OAuth sign-up][casdoor-mfa]), so products first see these users in a
  token.
- **Deletions other than an organization admin's `delete-user`**: self-service `delete-own-account`
  ([source][casdoor-delete-own]), global admins (whose records belong to `built-in`), application credentials
  (whose records name an application, not a stored user, so `extendedUser` is `null`;
  [source][casdoor-record-actor]), any other caller who is not an admin of the organization, and an
  organization admin deleting their own account (Casdoor loads the caller only after the request is done
  ([source][casdoor-after-request]), when it no longer exists, so `extendedUser` is `null`). Those users lose
  access within the [revocation bound](api.md#processing): their refresh is refused, and their last tokens
  expire.
- **Every deletion when extended user is off**, as above.

`new-user` follows Casdoor's sign-up flows, not user creation itself ([source][casdoor-new-user]): it fires for
sign-ups still awaiting an admin's approval ([source][casdoor-signup-record]), and an MFA prompt during an
OAuth sign-up suppresses it ([source][casdoor-mfa]). `user-deleted` can also follow a soft deletion, in an
organization that enables it ([source][casdoor-soft-delete]), or a deletion that matched no user, which
Casdoor answers `ok` too ([source][casdoor-unaffected]). Products therefore create users on first sight, whether
from an event or a token ([integrate.md](integrate.md#data-rules)).

## WeChat mini programs

A mini program signs in with Casdoor's mini program code login:

1. In Casdoor, add a provider with the mini program's AppID and app secret, and add it to the mini program's
   application. Casdoor's [mini program guide][casdoor-miniprogram] says to use a provider of type `WeChat`;
   at the commit this release was checked against, Casdoor looks for one of type `WeChatMiniProgram`
   ([source][casdoor-miniprogram-provider]), so use that type.
2. The mini program calls [`wx.login`][wx-login] for a code, valid for five minutes and usable once
   ([login][wx-login-flow]), and posts it with `client_id` and `tag=wechat_miniprogram` to Casdoor's
   `/api/login/oauth/access_token` ([guide][casdoor-miniprogram], [source][casdoor-miniprogram-tag]). No client
   secret is involved: the WeChat app secret stays in Casdoor.
3. The client SDK does both steps: [`casdoorMiniProgramIdpToken`](integrate.md#wechat-mini-programs).

Add both the bridge's domain and Casdoor's domain to the mini program's server domain list. WeChat lets a mini
program call only the HTTPS domains listed there, and those domains need ICP filing ([network][wx-network]).

[casdoor-docs]: https://casdoor.ai/docs/basic/core-concepts/
[casdoor-config]: https://casdoor.ai/docs/basic/configuration/
[casdoor-issuer-doc]: https://casdoor.ai/docs/integration/go/oauth2-proxy/
[casdoor-oidc]: https://casdoor.ai/docs/how-to-connect/oidc-client/
[casdoor-application]: https://casdoor.ai/docs/application/overview/
[casdoor-app-settings]: https://casdoor.ai/docs/application/terminology/
[casdoor-refresh-doc]: https://casdoor.ai/docs/how-to-connect/oauth/
[casdoor-token-format]: https://casdoor.ai/docs/token/overview/
[casdoor-account-items]: https://casdoor.ai/docs/organization/accountCustomization/
[casdoor-webhooks]: https://casdoor.ai/docs/webhooks/overview/
[casdoor-records]: https://casdoor.ai/docs/organization/records/
[casdoor-api]: https://casdoor.ai/docs/basic/public-api/
[casdoor-miniprogram]: https://casdoor.ai/docs/integration/javascript/wechat_miniprogram/
[wx-login]: https://developers.weixin.qq.com/miniprogram/dev/api/open-api/login/wx.login.html
[wx-login-flow]: https://developers.weixin.qq.com/miniprogram/dev/framework/open-ability/login.html
[wx-network]: https://developers.weixin.qq.com/miniprogram/dev/framework/ability/network.html
[casdoor-commit]: https://github.com/casdoor/casdoor/tree/3d81f45bc98be0fe379b3a21973c783060066af5
[casdoor-origin]: https://github.com/casdoor/casdoor/blob/3d81f45bc98be0fe379b3a21973c783060066af5/object/wellknown_oidc_discovery.go#L96-L119
[casdoor-signing-method]: https://github.com/casdoor/casdoor/blob/3d81f45bc98be0fe379b3a21973c783060066af5/object/token_jwt.go#L820-L835
[casdoor-org-issuer]: https://github.com/casdoor/casdoor/blob/3d81f45bc98be0fe379b3a21973c783060066af5/object/wellknown_oidc_discovery.go#L137-L165
[casdoor-claims]: https://github.com/casdoor/casdoor/blob/3d81f45bc98be0fe379b3a21973c783060066af5/object/token_jwt.go#L678-L697
[casdoor-aud]: https://github.com/casdoor/casdoor/blob/3d81f45bc98be0fe379b3a21973c783060066af5/object/token_jwt.go#L703-L720
[casdoor-oauth-id]: https://github.com/casdoor/casdoor/blob/3d81f45bc98be0fe379b3a21973c783060066af5/controllers/auth.go#L1335-L1344
[casdoor-sub]: https://github.com/casdoor/casdoor/blob/3d81f45bc98be0fe379b3a21973c783060066af5/object/token_jwt.go#L688-L691
[casdoor-id-index]: https://github.com/casdoor/casdoor/blob/3d81f45bc98be0fe379b3a21973c783060066af5/object/user.go#L70
[casdoor-user-fields]: https://github.com/casdoor/casdoor/blob/3d81f45bc98be0fe379b3a21973c783060066af5/object/user.go#L83-L85
[casdoor-phone-integer]: https://github.com/casdoor/casdoor/blob/3d81f45bc98be0fe379b3a21973c783060066af5/util/validation.go#L90-L106
[casdoor-phone-signup]: https://github.com/casdoor/casdoor/blob/3d81f45bc98be0fe379b3a21973c783060066af5/controllers/account.go#L192-L200
[casdoor-phone-code-signup]: https://github.com/casdoor/casdoor/blob/3d81f45bc98be0fe379b3a21973c783060066af5/object/token_verification_code.go#L151-L172
[casdoor-phone-reset]: https://github.com/casdoor/casdoor/blob/3d81f45bc98be0fe379b3a21973c783060066af5/controllers/verification.go#L664-L684
[casdoor-phone-mfa]: https://github.com/casdoor/casdoor/blob/3d81f45bc98be0fe379b3a21973c783060066af5/controllers/mfa.go#L199-L212
[casdoor-self-columns]: https://github.com/casdoor/casdoor/blob/3d81f45bc98be0fe379b3a21973c783060066af5/object/user.go#L900-L930
[casdoor-region-item]: https://github.com/casdoor/casdoor/blob/3d81f45bc98be0fe379b3a21973c783060066af5/object/user_util.go#L783-L790
[casdoor-modify-rule-nil]: https://github.com/casdoor/casdoor/blob/3d81f45bc98be0fe379b3a21973c783060066af5/object/organization.go#L482-L485
[casdoor-region-default]: https://github.com/casdoor/casdoor/blob/3d81f45bc98be0fe379b3a21973c783060066af5/object/init.go#L72
[casdoor-phone-oauth]: https://github.com/casdoor/casdoor/blob/3d81f45bc98be0fe379b3a21973c783060066af5/controllers/auth.go#L1351-L1352
[casdoor-phone-mapping]: https://github.com/casdoor/casdoor/blob/3d81f45bc98be0fe379b3a21973c783060066af5/object/user_util.go#L536-L545
[casdoor-phone-miniprogram]: https://github.com/casdoor/casdoor/blob/3d81f45bc98be0fe379b3a21973c783060066af5/object/token_oauth.go#L723-L731
[casdoor-incremental]: https://github.com/casdoor/casdoor/blob/3d81f45bc98be0fe379b3a21973c783060066af5/object/user.go#L1951-L1971
[casdoor-custom-claims]: https://github.com/casdoor/casdoor/blob/3d81f45bc98be0fe379b3a21973c783060066af5/object/token_jwt.go#L480-L511
[casdoor-token-types]: https://github.com/casdoor/casdoor/blob/3d81f45bc98be0fe379b3a21973c783060066af5/object/token_jwt.go#L708-L728
[casdoor-grant-types]: https://github.com/casdoor/casdoor/blob/3d81f45bc98be0fe379b3a21973c783060066af5/object/token_oauth_util.go#L253-L265
[casdoor-refresh-expiry]: https://github.com/casdoor/casdoor/blob/3d81f45bc98be0fe379b3a21973c783060066af5/object/token_jwt.go#L659-L663
[casdoor-refresh-user]: https://github.com/casdoor/casdoor/blob/3d81f45bc98be0fe379b3a21973c783060066af5/object/token_oauth_util.go#L679-L700
[casdoor-properties-default]: https://github.com/casdoor/casdoor/blob/3d81f45bc98be0fe379b3a21973c783060066af5/object/init.go#L108
[casdoor-modify-rule]: https://github.com/casdoor/casdoor/blob/3d81f45bc98be0fe379b3a21973c783060066af5/object/user_util.go#L988-L1000
[casdoor-public-only]: https://github.com/casdoor/casdoor/blob/3d81f45bc98be0fe379b3a21973c783060066af5/object/webhook_util.go#L27-L38
[casdoor-console-default]: https://github.com/casdoor/casdoor/blob/3d81f45bc98be0fe379b3a21973c783060066af5/web/src/pages/defaults.ts#L669-L684
[casdoor-mask]: https://github.com/casdoor/casdoor/blob/3d81f45bc98be0fe379b3a21973c783060066af5/object/record.go#L40-L46
[casdoor-extended-user]: https://github.com/casdoor/casdoor/blob/3d81f45bc98be0fe379b3a21973c783060066af5/object/record.go#L444-L457
[casdoor-token-fields]: https://github.com/casdoor/casdoor/blob/3d81f45bc98be0fe379b3a21973c783060066af5/object/webhook_util.go#L42-L63
[casdoor-object-fields]: https://github.com/casdoor/casdoor/blob/3d81f45bc98be0fe379b3a21973c783060066af5/object/record.go#L440-L442
[casdoor-single-org]: https://github.com/casdoor/casdoor/blob/3d81f45bc98be0fe379b3a21973c783060066af5/object/record.go#L352-L356
[casdoor-single-org-admin]: https://github.com/casdoor/casdoor/blob/3d81f45bc98be0fe379b3a21973c783060066af5/controllers/webhook.go#L117-L121
[casdoor-webhook-struct]: https://github.com/casdoor/casdoor/blob/3d81f45bc98be0fe379b3a21973c783060066af5/object/webhook.go#L49-L52
[casdoor-worker]: https://github.com/casdoor/casdoor/blob/3d81f45bc98be0fe379b3a21973c783060066af5/object/webhook_worker.go#L32
[casdoor-worker-order]: https://github.com/casdoor/casdoor/blob/3d81f45bc98be0fe379b3a21973c783060066af5/object/webhook_worker.go#L151-L156
[casdoor-queue]: https://github.com/casdoor/casdoor/blob/3d81f45bc98be0fe379b3a21973c783060066af5/object/webhook_event.go#L255-L272
[casdoor-attempt]: https://github.com/casdoor/casdoor/blob/3d81f45bc98be0fe379b3a21973c783060066af5/object/webhook_worker.go#L162-L251
[casdoor-get-webhook]: https://github.com/casdoor/casdoor/blob/3d81f45bc98be0fe379b3a21973c783060066af5/controllers/webhook.go#L79-L89
[casdoor-get-webhook-org]: https://github.com/casdoor/casdoor/blob/3d81f45bc98be0fe379b3a21973c783060066af5/object/webhook.go#L127-L138
[casdoor-webhook-api]: https://github.com/casdoor/casdoor/blob/3d81f45bc98be0fe379b3a21973c783060066af5/controllers/webhook.go#L71-L125
[casdoor-worker-start]: https://github.com/casdoor/casdoor/blob/3d81f45bc98be0fe379b3a21973c783060066af5/object/webhook_worker.go#L41-L49
[casdoor-new-user]: https://github.com/casdoor/casdoor/blob/3d81f45bc98be0fe379b3a21973c783060066af5/routers/record.go#L166-L191
[casdoor-signup-record]: https://github.com/casdoor/casdoor/blob/3d81f45bc98be0fe379b3a21973c783060066af5/controllers/account.go#L323-L350
[casdoor-delete-own]: https://github.com/casdoor/casdoor/blob/3d81f45bc98be0fe379b3a21973c783060066af5/routers/router.go#L101
[casdoor-record-actor]: https://github.com/casdoor/casdoor/blob/3d81f45bc98be0fe379b3a21973c783060066af5/object/record.go#L217-L241
[casdoor-after-request]: https://github.com/casdoor/casdoor/blob/3d81f45bc98be0fe379b3a21973c783060066af5/routers/record.go#L187-L191
[casdoor-soft-delete]: https://github.com/casdoor/casdoor/blob/3d81f45bc98be0fe379b3a21973c783060066af5/object/user.go#L1469-L1480
[casdoor-unaffected]: https://github.com/casdoor/casdoor/blob/3d81f45bc98be0fe379b3a21973c783060066af5/controllers/base.go#L423-L431
[casdoor-mfa]: https://github.com/casdoor/casdoor/blob/3d81f45bc98be0fe379b3a21973c783060066af5/controllers/auth.go#L1418-L1425
[casdoor-miniprogram-provider]: https://github.com/casdoor/casdoor/blob/3d81f45bc98be0fe379b3a21973c783060066af5/object/provider.go#L272-L280
[casdoor-miniprogram-tag]: https://github.com/casdoor/casdoor/blob/3d81f45bc98be0fe379b3a21973c783060066af5/object/token_oauth.go#L65-L75
