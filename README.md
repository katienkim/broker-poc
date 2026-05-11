# IAM Broker (Spring Boot POC)

Spring Boot 3.5.10 / Java 21 broker that accepts inbound auth from **PID** in
three modes (SAML, OIDC, or a legacy launch token), mints downstream vendor
tokens in **five formats** (IGTK / SAML / AES‑256‑GCM / RC4 / WPC OTP), and
exposes admin operations for revocation + emergency bypass. Backed by
Postgres with Flyway migrations.

## What this broker plays in an IdP-Initiated SSO flow

```
User logged into Dealers ──clicks vendor link──► Dealers asks PID for auth
                                                            │
                                                            ▼
                                                          PID authenticates
                                                            │
                                                            ▼
                         ┌──────────────────────────────────────────────────┐
                         │  Broker (this service)                            │
                         │                                                   │
                         │  Accepts PID's handoff via any of:                │
                         │   ─ POST /sso/saml/acs/pid     (SAML SP role)    │
                         │   ─ GET  /api/v1/auth/callback (OIDC RP role)    │
                         │   ─ GET  /sso/receive          (launch token)    │
                         │                                                   │
                         │  All three converge on PublishTokenService → mint │
                         │  a downstream token in the format the vendor needs │
                         └──────────────────────────────────────────────────┘
                                                            │
                                                            ▼
                                                          Vendor (auto-submit
                                                                   HTML form)
```

The same broker plays **two SAML roles**:
- **SAML SP** (inbound from PID) — `broker-sp.p12` keystore, `SamlSpKeyProvider`
- **SAML IdP** (outbound to vendors) — `broker-idp.p12` keystore, `SamlSigningKeyProvider`

---

## Repo layout

```
broker-poc/
├── docker-compose.yml          # full stack: traefik + postgres + broker + Node mocks
├── .env.example                # POC secrets / shared keys
└── apps/
    ├── iam-broker/                ← the Spring Boot service
    │   ├── build.gradle, Dockerfile
    │   ├── keystore/              ← SP + IdP PKCS12 keystores (gitignored)
    │   ├── idp-metadata/          ← PID's IdP metadata XML
    │   └── src/main/
    │       ├── java/com/hma/idpbrokerservice/
    │       │   ├── IamBrokerApplication.java
    │       │   ├── infrastructure/config/   ← SOAP wiring, WebClient
    │       │   ├── presentation/controller/ ← REST + /sso/receive + /sso/saml/* + /api/v1/auth/*
    │       │   └── sso/
    │       │       ├── config/         ← SsoProperties, SamlSecurityConfig
    │       │       ├── contract/       ← JAXB POJOs for the 5 SOAP services
    │       │       ├── domain/         ← UserContext, AuthenticatedUser, IssuedToken
    │       │       ├── endpoint/       ← Spring-WS @Endpoint per service
    │       │       ├── entity/, repository/  ← JPA tables (sso_system, token_h,
    │       │       │                          revocation, bypass, oauth_state,
    │       │       │                          inbound_saml_assertion_seen)
    │       │       ├── oidc/           ← OIDC RP: AuthController flow, JwtValidator,
    │       │       │                       TokenExchangeService, OidcStateCodeService
    │       │       ├── service/        ← PublishToken, AuthenticateUser, ...
    │       │       ├── service/client/ ← outbound WebClients (PID, Dealers, Dashboard)
    │       │       ├── service/support/← Audit, RateLimiter, Otp/Nonce stores,
    │       │       │                       MockPidTokenVerifier, InboundSamlReplayGuard
    │       │       └── token/          ← 5 token generators, SamlSpKeyProvider
    │       └── resources/
    │           ├── application.properties
    │           ├── application-sso*.yaml   ← SSO config (TTLs, keys, OIDC, SAML)
    │           ├── db/migration/           ← Flyway V1–V7
    │           └── xsd/, wsdl/             ← 5 SOAP contracts
    ├── dashboard/   ←  Node mock — live flow visualization
    ├── mock-pid/    ←  Node mock — local stand-in for hmg-Partner ID
    ├── portal/      ←  Node mock — dealer portal
    ├── role-api/    ←  Node mock — Dealers / role lookup
    └── vendor-app/  ←  Node mock — multi-format vendor (IGTK, SAML, AES, RC4, WPC)
```

---

## Prerequisites

- Docker Desktop (or `docker` + `docker compose` ≥ v2)
- Add to `/etc/hosts`:
  ```
  127.0.0.1 broker.sso.test portal.sso.test vendor.sso.test pid.sso.test dashboard.sso.test
  ```

You don't need Java or Gradle locally — the broker container builds itself
(`gradle:8.14-jdk21-alpine` for build, `eclipse-temurin:21-jre-alpine` at runtime).

---

## First-run setup

The broker needs **two PKCS12 keystores** for its SAML SP role (PID-facing) and
its SAML IdP role (vendor-facing). Generate both via the temurin Docker image
(so you don't need Java locally):

```bash
cd /Users/katiekim/Projects/IdP/broker-poc/apps/iam-broker

# SP-role keystore (cert published in /sso/saml/metadata to PID)
docker run --rm -v "$PWD/keystore:/keystore" eclipse-temurin:21-jre-alpine \
  keytool -genkeypair -alias broker-sp -keyalg RSA -keysize 2048 \
  -validity 730 -sigalg SHA256withRSA -keystore /keystore/broker-sp.p12 \
  -storetype PKCS12 -storepass changeit \
  -dname "CN=broker.sso.test, OU=HAEA, O=Hyundai, L=Fountain Valley, ST=CA, C=US"

# IdP-role keystore (signs SAML responses to vendor apps)
docker run --rm -v "$PWD/keystore:/keystore" eclipse-temurin:21-jre-alpine \
  keytool -genkeypair -alias broker-idp -keyalg RSA -keysize 2048 \
  -validity 730 -sigalg SHA256withRSA -keystore /keystore/broker-idp.p12 \
  -storetype PKCS12 -storepass changeit \
  -dname "CN=broker-idp.sso.test, OU=HAEA, O=Hyundai, L=Fountain Valley, ST=CA, C=US"
```

The keystores land in `apps/iam-broker/keystore/` (gitignored) and are mounted
into the container at `/keystore` by `docker-compose.yml`.

PID's IdP metadata is already in `apps/iam-broker/idp-metadata/pid-metadata.xml`.
If PID rotates their signing cert, drop the new metadata there.

---

## Run

```bash
cp .env.example .env
docker compose up --build
```

First boot is ~2 minutes (Gradle pulls dependencies and compiles). Restarts
afterward are seconds.

Useful URLs once the stack is up:

| URL | What it is |
|---|---|
| http://broker.sso.test:8000/ | Broker info page (lists endpoints) |
| http://broker.sso.test:8000/health | Health check |
| http://broker.sso.test:8000/sso/saml/metadata | SP metadata (give this URL to PID) |
| http://broker.sso.test:8000/ws/publishtoken.wsdl | SOAP contract |
| http://broker.sso.test:8000/swagger-ui.html | OpenAPI / Swagger UI |
| http://portal.sso.test:8000 | Portal (IdP-initiated flow) |
| http://vendor.sso.test:8000 | Vendor app |
| http://dashboard.sso.test:8000 | Live flow dashboard (visualises SAML, OIDC, launch-token) |

Stop the stack:
```bash
docker compose down        # keep Postgres data
docker compose down -v     # wipe Postgres volume too
```

---

## What the broker exposes

### Inbound auth (3 ways PID can hand the user off)

| Method + Path | Mode | Purpose |
|---|---|---|
| `POST /sso/saml/acs/pid` | SAML SP | Receives SAMLResponse from PID; validates sig + Conditions + replay; mints downstream vendor token |
| `GET  /api/v1/auth/login?target_vendor=X` | OIDC RP | Starts OIDC auth-code flow with PID |
| `GET  /api/v1/auth/callback` | OIDC RP | Exchanges code at PID's `/token`, validates id_token (RS256 + JWKS + nonce), mints downstream token |
| `GET  /sso/receive?launch_token=...` | Launch token | Legacy custom-JWT flow (HS256-verifiable when `MOCK_PID_REQUIRE_SIGNATURE=true`) |

All three converge on `PublishTokenService` → auto-submit HTML form to vendor.

### SOAP — single endpoint at `/ws`

Routing is by request root element + namespace. Five services share the endpoint:

| Service | WSDL | Purpose |
|---|---|---|
| `PublishToken` | `/ws/publishtoken.wsdl` | Mint a vendor token |
| `AuthenticateUser` | `/ws/authenticateuser.wsdl` | Validate + single-use consume |
| `OtpValidate` | `/ws/otpvalidate.wsdl` | WPC OTP validation |
| `AdminRevoke` | `/ws/adminrevoke.wsdl` | Revoke token or user (admin key) |
| `AdminBypass` | `/ws/adminbypass.wsdl` | Create/cancel emergency bypass (MFA-gated) |

### REST shims (same logic, different transport)

| Method + Path | Purpose |
|---|---|
| `POST /token/validate`, `/token/consume` | Validate token / single-use CSRF nonce |
| `POST /otp/validate` | WPC OTP validation |
| `POST /admin/revoke` | Revoke token/user (admin key) |
| `POST /admin/bypass`, `DELETE /admin/bypass/{id}` | Create/cancel bypass |
| `GET  /api/v1/saml/login?target_vendor=X` | Initiate SAML SP flow |
| `GET  /api/v1/saml/status`, `/api/v1/auth/status` | Diagnostic (config dump) |
| `GET  /health`, `GET /`, `GET /logout` | Status / info |

---

## Token formats (downstream to vendors)

Five generators live in `sso/token/`:

| Format | Generator | Notes |
|---|---|---|
| `igtk` | `IgtkTokenGenerator` | `PREFIX + SHA-256(src\|tgt\|uid\|ts)` opaque hash |
| `saml` | `SamlTokenGenerator` | XML signed with RSA-SHA256 via the IdP-role keystore |
| `aes256` | `Aes256GcmTokenGenerator` | AES-256-GCM authenticated encryption |
| `rc4` | `Rc4TokenGenerator` | RC4 + HMAC-SHA256 (deprecated; logs `DEPRECATED_TOKEN`) |
| `wpc-otp` | `WpcOtpTokenGenerator` | One-time numeric code |

TTLs and shared keys are configured in `application-sso.yaml`.

---

## SOAP demo — mint and validate an IGTK token

```bash
# Mint a token
curl -s -X POST http://broker.sso.test:8000/ws \
  -H 'Content-Type: text/xml; charset=utf-8' \
  -H 'SOAPAction: ' \
  -d '<?xml version="1.0"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
                  xmlns:tns="http://hyundaidealer.com/PublishTokenService/">
  <soapenv:Body>
    <tns:PublishToken>
      <SourceSYS_ID>portal</SourceSYS_ID>
      <TargetSYS_ID>vendor-igtk</TargetSYS_ID>
      <UserID>dealer.ca01</UserID>
      <CompanyCode>HMA</CompanyCode>
    </tns:PublishToken>
  </soapenv:Body>
</soapenv:Envelope>' | xmllint --format -
```

Response includes `htxtToken`, `URL_D`, `JTI`, and `ERETURN.TYPE=S`.

```bash
# Validate (single-use — second call returns TOKEN_ALREADY_USED)
curl -s -X POST http://broker.sso.test:8000/ws \
  -H 'Content-Type: text/xml; charset=utf-8' \
  -d '<?xml version="1.0"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
                  xmlns:tns="http://hyundaidealer.com/AuthenticateUserService/">
  <soapenv:Body>
    <tns:AuthenticateUser>
      <Token>H_abc123...</Token>
      <Format>igtk</Format>
    </tns:AuthenticateUser>
  </soapenv:Body>
</soapenv:Envelope>' | xmllint --format -
```

For a clickable client, import any `/ws/*.wsdl` into SoapUI.

---

## SAML SP smoke tests

```bash
# Should serve real metadata XML (no longer 503 — keystore is mounted)
curl http://broker.sso.test:8000/sso/saml/metadata

# Diagnostic
curl http://broker.sso.test:8000/api/v1/saml/status

# Initiate SAML flow — should 302 to /saml2/authenticate/pid
curl -i "http://broker.sso.test:8000/api/v1/saml/login?target_vendor=vendor-saml"
```

End-to-end SAML round-trip with PID requires the metadata to be registered on
PID's side (send them `http://broker.sso.test:8000/sso/saml/metadata`) and a
publicly-reachable broker URL (use ngrok / cloudflared if testing locally).

## OIDC RP smoke tests

OIDC is disabled by default (`OIDC_PID_ENABLED=false` in `.env`). When PID
issues you a `client_id` + `client_secret`:

```bash
# in .env
OIDC_PID_ENABLED=true
OIDC_PID_CLIENT_ID=<from PID team>
OIDC_PID_CLIENT_SECRET=<from PID team>
# defaults match HMG-Partner ID spec: /authorize, /token, /cert
```

```bash
docker compose up -d --build
curl http://broker.sso.test:8000/api/v1/auth/status
curl -i "http://broker.sso.test:8000/api/v1/auth/login?target_vendor=vendor-igtk"
# → 302 to https://stg-partner.hmg-corp.io/auth/authorize?...
```

---

## Database

Postgres, managed by Flyway. Seven migrations under
`apps/iam-broker/src/main/resources/db/migration/`:

| Migration | Creates |
|---|---|
| `V1__sso_system.sql` | `ia_tb_sso_sys_mngmt_m` (vendor catalog) + seed data |
| `V2__sso_token_history.sql` | `ia_tb_sso_token_h` (issued tokens) |
| `V3__sso_revocation.sql` | `ia_tb_sso_revocation` (token/user revocations) |
| `V4__sso_bypass.sql` | `ia_tb_sso_bypass` (emergency bypass grants) |
| `V5__drop_token_index.sql` | Drops a stale token index |
| `V6__oauth_state.sql` | `ia_tb_oauth_state` (state code + RelayState — shared by OIDC and SAML) |
| `V7__inbound_saml_assertion_seen.sql` | `ia_tb_inbound_saml_assertion_seen` (replay defense) |

Inspect the data:

```bash
docker compose exec postgres psql -U iam_broker -d iam_broker

iam_broker=> \dt
iam_broker=> select source_sys_id, source_sys_type, direct_reurl_d
             from ia_tb_sso_sys_mngmt_m;
iam_broker=> select jti, format, uid, target_sys_id, consumed, expires_at
             from ia_tb_sso_token_h order by issued_at desc limit 5;
iam_broker=> select state_code, flow, target_vendor, used, expires_at
             from ia_tb_oauth_state order by created_at desc limit 5;
```

---

## Configuration

Most knobs live in `apps/iam-broker/src/main/resources/application-sso.yaml`
under the `sso:` prefix:

- `sso.token.<format>.ttl-seconds` — TTL per format
- `sso.token.aes256.shared-key` / `sso.token.rc4.shared-key` — symmetric keys
- `sso.external.*` — outbound URLs (PID, Dealers, Dashboard)
- `sso.admin.api-key` / `sso.admin.require-mfa-header` — admin guard
- `sso.rate-limit.otp.*` — OTP rate-limit and lockout windows
- `sso.bypass.max-duration-minutes` — bypass cap
- `sso.oidc.pid.*` — OIDC RP wiring (client_id, endpoints, jwks-uri)
- `sso.saml-sp.*`, `sso.saml-idp.*` — SAML SP/IdP keystore paths and entity IDs
- `sso.mock-pid.require-signature` / `shared-secret` — HS256 enforcement on `/sso/receive`

Secrets and per-environment values are read from env vars (see `.env.example`).

---

## Tests

```bash
docker run --rm -v "$PWD/apps/iam-broker:/app" -w /app gradle:8.14-jdk21-alpine \
  gradle test --no-daemon
```

Current coverage:
- `MockPidTokenVerifierTest` — HS256 enforcement, alg:none rejection, expired-token rejection, fallback mode
- `JwtValidatorImplTest` — RS256-only, signature, exp/iat/iss/aud/sub, HMAC confusion attack, userinfo extraction

---

## Things to know

- **PKCS12 keystores are required before boot when SAML SP is enabled.** Set
  `SSO_SAML_SP_ENABLED=false` to skip if you haven't run keytool yet.
- **OIDC is disabled until you have PID client credentials.** Default
  `OIDC_PID_ENABLED=false`; turn on after the PID team issues a `client_id`.
- **Mock-PID launch token signature** is off by default (`MOCK_PID_REQUIRE_SIGNATURE=false`).
  Flip on after patching mock-pid to sign with HS256.
- **Postgres for POC; Oracle in production.** JPA queries are vendor-neutral —
  switching is a JDBC URL + driver change.
- **Hardcoded secrets in `.env.example`** are intentional for the POC.

---

## Troubleshooting

**Port 8000 in use** — another stack is bound to it; stop it before starting.

**Broker fails to boot with `SAML SP enabled but no signing cert`** —
keystore not generated or not mounted. Run the keytool commands in
[First-run setup](#first-run-setup), or set `SSO_SAML_SP_ENABLED=false`.

**Broker fails with `relation "ia_tb_sso_sys_mngmt_m" does not exist`** —
Postgres came up after the broker tried to migrate. Restart the broker:
`docker compose restart iam-broker`.

**`docker compose build` Gradle error** — make sure Docker Desktop is ≥ 4.x
(needs BuildKit). Try `DOCKER_BUILDKIT=1 docker compose build iam-broker`.

**Vendor app shows "CSRF validation failed"** — the 5-minute nonce TTL expired,
or the broker restarted between mint and consume. Start a fresh SSO flow.
