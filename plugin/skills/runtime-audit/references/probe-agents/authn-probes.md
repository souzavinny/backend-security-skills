# Authentication Probes

Live forgery / bypass / weak-flow testing. Most probes are Band 1 (read-only forgery attempts); reset-flow and brute-force probes are Band 3.

## JWT forgery (Band 1 — always safe)

Requires a captured JWT from context A.

### alg:none

```
PROBE: authn-jwt-alg-none
BAND: 1
ATTACK:
  Decode observed JWT → modify payload (sub/user_id/role) → re-encode header as {"alg":"none","typ":"JWT"} → signature = empty.
  Send in Authorization: Bearer <forged>
SIGNAL:
  CONFIRMED if request succeeds as the forged identity (GET /me returns modified sub)
  LIKELY if server returns 200 but doesn't distinguish old vs new identity in response
```

### HS256-with-public-key

```
PROBE: authn-jwt-alg-confusion
BAND: 1
PREREQ: server uses RS256/ES256 and exposes a JWKS endpoint (or pub key is known)
ATTACK:
  Fetch public key. Re-sign token as HS256 with the raw PEM bytes as HMAC secret.
  Send.
SIGNAL: same as alg:none
```

### Signature strip

```
PROBE: authn-jwt-sig-strip
BAND: 1
ATTACK:
  Send header.payload (omit the `.signature`)
SIGNAL:
  CONFIRMED if accepted — means no signature verification at all
```

### Expired / nbf bypass

```
PROBE: authn-jwt-exp-bypass
BAND: 1
ATTACK:
  Set `exp` to 60s in the past. Re-sign (if we have a secret) or use the original sig and see if server verifies exp.
SIGNAL:
  CONFIRMED if accepted (server ignores exp)
```

### kid injection

```
PROBE: authn-jwt-kid-inject
BAND: 1
ATTACK:
  Tokens with `kid`: `../../dev/null` (server reads 0 bytes → empty secret → forge with empty HMAC)
  Tokens with `kid`: SQL-like `' UNION SELECT 'secret'--`
SIGNAL:
  CONFIRMED if either forgery accepts
```

## Session fixation (Band 2)

If the app uses server-side sessions:

```
PROBE: authn-session-fixation
BAND: 2
ATTACK:
  1. Unauthenticated: GET / → note `Set-Cookie: session=ABC`
  2. Submit login with that pre-set `session=ABC` cookie.
  3. After login, use the same cookie on a subsequent authenticated request.
SIGNAL:
  CONFIRMED if the same cookie is still valid (session ID was not regenerated)
```

## Password reset flow (Band 3)

Requires `--destructive` AND a controlled test account.

```
PROBE: authn-reset-token-reuse
BAND: 3
ATTACK:
  1. POST /auth/forgot { "email": "test+canary@example.invalid" }
  2. Observe email / inspect DB / use --reset-token-hook for the issued token.
  3. POST /auth/reset { "token": <token>, "password": "new1" } → success
  4. Repeat step 3 with same token → should fail.
SIGNAL:
  CONFIRMED if step 4 also succeeds (token is reusable)
```

```
PROBE: authn-reset-token-expiry
BAND: 3 (with --destructive and a long runtime window)
ATTACK:
  Request a reset token. Wait past the expected expiry (e.g., 2h). Use it.
SIGNAL:
  CONFIRMED if it still works
```

```
PROBE: authn-reset-email-enum
BAND: 2
ATTACK:
  POST /auth/forgot { "email": "existing@example.com" } → response A
  POST /auth/forgot { "email": "nonexistent-<rand>@example.invalid" } → response B
SIGNAL:
  CONFIRMED if A and B differ in status code, body, or response time (> 200ms consistent diff) → user enumeration
```

## MFA bypass (Band 2)

If MFA is present:

```
PROBE: authn-mfa-client-flag
BAND: 2
ATTACK:
  Inspect login → look for client-controllable MFA state.
  Attempt direct access to post-MFA endpoints using only the pre-MFA token.
SIGNAL:
  CONFIRMED if pre-MFA bearer grants post-MFA access
```

```
PROBE: authn-mfa-totp-timing
BAND: 3
ATTACK:
  Submit TOTP codes timed to test for non-constant-time comparison (500 attempts with timing capture).
SIGNAL:
  LIKELY if timing distribution reveals which prefix bytes matched.
```

## Brute force (Band 3 — explicit opt-in)

```
PROBE: authn-brute-force
BAND: 3
PREREQ: --destructive AND test account that is OK to lock out
ATTACK:
  Submit POST /auth/login with the test account's username and:
  - 20 wrong passwords in quick succession
SIGNAL:
  CONFIRMED no-rate-limit: all 20 got non-429 (incorrect-pw responses, not throttle)
  CONFIRMED lockout-missing: 21st attempt with the CORRECT password still succeeds → no lockout
```

## Remember-me / refresh token (Band 1–2)

```
PROBE: authn-refresh-reuse
BAND: 2
ATTACK:
  1. Log in → get refresh token RT1.
  2. Use RT1 to get access token AT2 (and usually RT2).
  3. Use RT1 again to try for another access token.
SIGNAL:
  CONFIRMED if RT1 still works (no rotation) — persistent access risk on token leak
  LIKELY if RT1 is rejected but RT2 works without reuse detection
```

## OAuth redirect-URI validation (Band 1)

```
PROBE: authn-oauth-redirect
BAND: 1
ATTACK:
  Initiate auth flow with redirect_uri = variations:
    https://client.allowed.com.evil/
    https://evil/?dest=https://client.allowed.com
    https://evil/#@client.allowed.com
    https://client.allowed.com@evil/
SIGNAL:
  CONFIRMED if server redirects to the evil host (open redirect in auth flow = code theft)
```

## Output additions

```
flow: jwt-alg-none | jwt-hs-rs-confusion | jwt-sig-strip | session-fixation | reset-reuse | reset-enum | mfa-bypass | brute-force | rt-no-rotate | oauth-redirect
token_form: <sanitized token structure>
```
