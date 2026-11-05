## 0.2.0

- **Security Hardening & OAuth 2.1 Compliance (`draft-ietf-oauth-v2-1-17`):**
  - Special thanks to Brett Sutton ([@bsutton](https://github.com/bsutton)) for his security review and assistance in identifying and remediating these findings.
  - **Exclusive `S256` PKCE (`GHSA-fxjx-5532-g24j`):** Removed `plain` PKCE support across client and server (`CodeChallenge.plain`, `AuthCode`, `AuthorizeRequestValidator`, `TokenRequestHandler`) and enforced constant-time PKCE verifier comparisons via `CryptoService.safeEquals`.
  - **Authenticated Resource Transport & Redirect Protection (`GHSA-9567-wrwx-wvjx`):** Enforced HTTPS or local loopback HTTP (`localhost`, `127.0.0.1`, `::1`, `[::1]`) and `request.followRedirects = false` in `OAuthAuthenticatedClient.send` to prevent Bearer token leakage over cleartext HTTP or across redirects.
  - **Strict Redirect URI & Endpoint Validation (`GHSA-93g7-77mc-6fv9`):** Centralized URI validation in `redirect_uri_policy.dart`, enforcing `https`, loopback `http`, or reverse-domain private-use schemes (`^[a-z0-9]+(\.[a-z0-9-]+)+$`) without fragments or `userInfo` across `ClientRegistration`, `AuthRequest`, `AuthorizeRequestValidator`, and `HttpAdapter`.
  - **Pre-Buffer Token Payload Limits & Error Headers (`GHSA-4c5r-9x7r-gp8g`):** Updated `handleTokenRequest` to enforce the 10,240-byte payload limit while streaming chunks prior to UTF-8 decoding, validate `Content-Length`, handle malformed UTF-8 and percent-encoding as `400 Bad Request`, and return `Cache-Control: no-store` and `Pragma: no-cache` on all token error responses.
  - **Fail-Closed Token Endpoint TLS Check (`GHSA-m522-w2xp-g3x8`):** Changed the default value of `isHttps` from `true` to `false` on `TokenRequestHandler.handle` and `handleTokenRequest`.
  - **Atomic Single-Use Authorization Codes & Refresh Token Rotation (`GHSA-cq4q-qggc-qgxj`):** Replaced `AuthCodeRepository.markAsUsed` and `revokeTokensForCode` with atomic `tryConsume`, added `authorizationCode` lineage to `AccessToken` and `RefreshToken`, added `saveIssuedTokens`, `rotateRefreshToken`, and `revokeByAuthorizationCode` to `TokenRepository`, and enforced PKCE verification prior to code consumption/replay checks to prevent unauthenticated code-replay DoS (OAuth 2.1 Section 7.5.3).
- Added the `draft-ietf-oauth-v2-1-17.txt` specification reference and `SECURITY.txt` reporting policy to the repository.

## 0.1.0

- Initial version.
