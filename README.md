# broker-spring — Slot-In Spring Port of the IAM Broker

A drop-in replacement for the Node IAM Broker in [`../poc/`](../poc/), rebuilt
in **Spring Boot 3.5.10 / Java 21** so it speaks the same wire protocols the
client backend already uses (`com.hma.idpbrokerservice.*`, SOAP at `/ws`,
SHA-256-hash IGTK, DB-backed token validity).

The "story" this stack tells: *the broker logic was rebuilt to match the
client's existing contract — drop it in tomorrow.*

The portal, mock-pid, vendor-app, role-api, and flow-dashboard are **the
same Node services from `../poc/apps/`**, unmodified. They build straight
out of the original folders via Docker context. Only the broker swapped.

---

## What changed vs `../poc/`

| Area | `../poc/` (Node) | `broker-spring/` |
|---|---|---|
| Broker stack | Node 20 / Express | Spring Boot 3.5.10 / Java 21 / Gradle |
| IGTK token | HS256 JWT wrapping `prefix+sha256(...)` | **`PREFIX + SHA-256(src\|tgt\|uid\|ts)`** — opaque hash, no JWT (matches client `TokenGenerator`) |
| SAML | XML, **unsigned**, base64 | **RSA-SHA256 XML-DSig** signed (Apache Santuario), KeyInfo carries the broker's RSA pub key |
| AES | AES-256-**CBC**, no MAC | **AES-256-GCM** (authenticated encryption — confidentiality + integrity in one primitive) |
| RC4 | RC4 + HMAC-SHA256 | unchanged (still deprecated; logs `DEPRECATED_TOKEN`) |
| WPC OTP | unchanged | unchanged |
| Token registry | in-memory `Map` | **Postgres** `ia_tb_sso_token_h` (replaces `token-registry.js` + `revocation-store.js` + `bypass-store.js`) |
| Vendor catalog | `target-systems.js` literal | **Postgres** `ia_tb_sso_sys_mngmt_m`, seeded by Flyway migration `V1` |
| Validity layer | 7-layer permission check | **System-level only** (target known + active) — Dealers owns user-level checks |
| SOAP services | none | **5** at `/ws`: `PublishToken`, `AuthenticateUser`, `OtpValidate`, `AdminRevoke`, `AdminBypass` |
| REST endpoints | `/sso/receive` + 5 admin/token paths | same surface kept as **REST shims** so unchanged Node mocks call into the broker |
| Persistence | none (restart = wipe) | Postgres + Flyway migrations `V1`–`V4` |

The SOAP `PublishToken` contract mirrors the client's
[`backend/src/main/resources/wsdl/publishtoken.wsdl`](../idp-ui-feature-Admin_System_Configuration/backend/src/main/resources/wsdl/publishtoken.wsdl)
exactly, including the `PARAMIN` → `PUBLISHOUT` shape with `htxtToken`,
`URL_D`, `URL_M`, and the `ERETURN` `TYPE`/`MESSAGE` block.

---

## Prerequisites

- Docker Desktop (or `docker` + `docker compose` ≥ v2)
- `/etc/hosts` entries (one-time, identical to the Node POC):
  ```
  127.0.0.1 broker.sso.test portal.sso.test vendor.sso.test pid.sso.test dashboard.sso.test
  ```

You do **not** need Java or Gradle installed locally — the broker container
builds itself from a multi-stage Dockerfile (`gradle:8.14-jdk21-alpine`
during build, `eclipse-temurin:21-jre-alpine` at runtime).

---

## Run

```bash
cd broker-spring
cp .env.example .env
docker compose up --build
# or detached:
docker compose up --build -d
```

First boot: ~2 minutes for the broker container (Gradle pulls dependencies
+ compiles). Subsequent restarts are seconds.

Then open one of:

| URL | Flow |
|---|---|
| http://portal.sso.test:8000 | Dealer Portal happy path (IdP-Initiated SSO) |
| http://vendor.sso.test:8000/app/haea | Vendor SP-Initiated → broker SAML |
| http://dashboard.sso.test:8000 | Live flow visualization |
| http://broker.sso.test:8000/ | Broker info page (lists endpoints) |
| http://broker.sso.test:8000/ws/publishtoken.wsdl | SOAP contract |

Stop the stack:
```bash
docker compose down              # keep Postgres data
docker compose down -v           # nuke Postgres volume (fresh start)
```

> **Side-by-side with `/poc`?** The two stacks share Traefik port `8000`, so
> only one can run at a time. Bring one down before bringing the other up.

---

## SOAP demo — calling `PublishToken` directly

The broker exposes a single SOAP endpoint at `/ws`. Routing happens by the
request's root XML element + namespace.

### `curl` example — mint an IGTK token

```bash
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

You'll get back `htxtToken`, `URL_D`, `JTI`, and `ERETURN.TYPE=S`.

### Validate that token (consumes it — single-use)

```bash
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

A second call with the same token returns `ERETURN.MESSAGE=TOKEN_ALREADY_USED`.

For a richer experience: import any of the WSDLs at `/ws/*.wsdl` into
**SoapUI** to get a clickable test client.

---

## Test users (unchanged from `/poc`)

OIDC users (mock Azure AD via `apps/role-api/src/fixtures.js`):

| Username | Role | Brand | Use for |
|---|---|---|---|
| `dealer.user1` | DEALER_MANAGER | H | Happy path |
| `dealer.user2` | DEALER_STAFF | GMA | Brand mismatch denial paths (now demoted to system-level only — see notes) |
| `vendor.user1` | VENDOR | H | Limited-role denial paths |
| `corp.user1` | CORPORATE | H | Should be denied for all vendors (in Node POC) |

PID users (`apps/mock-pid/src/users.js`): `test0901`, `dealer.ca01`, `corp.hq01`.

> **Note on user-level denials:** the Node POC's `permissions.js` enforced a
> 7-layer check (account status, role, dealer code, brand, etc.). Per the
> Apr 28 meeting (Yoonmi / Ahn Dae Hyun), the broker does **not** own user
> data — Dealers does. So `broker-spring` only validates **system-level**
> (target exists + active) and aggregates identity claims. User-level checks
> live with whoever owns the directory. This means `dealer.user2` with
> `GMA` brand will *succeed* against an `H`-only vendor in this stack —
> that's the intended behavior, and represents the live boundary.

---

## Inspect the data

```bash
docker compose exec postgres psql -U iam_broker -d iam_broker

iam_broker=> \dt
                      List of relations
 ...
 public | ia_tb_sso_bypass        | table
 public | ia_tb_sso_revocation    | table
 public | ia_tb_sso_sys_mngmt_m   | table
 public | ia_tb_sso_token_h       | table

iam_broker=> select source_sys_id, source_sys_type, direct_reurl_d
             from ia_tb_sso_sys_mngmt_m;
iam_broker=> select jti, format, uid, target_sys_id, consumed, expires_at
             from ia_tb_sso_token_h order by issued_at desc limit 5;
```

---

## Project layout (broker only)

```
broker-spring/apps/iam-broker/
├── build.gradle, settings.gradle, Dockerfile
└── src/main/
    ├── java/com/hma/idpbrokerservice/
    │   ├── IamBrokerApplication.java
    │   ├── infrastructure/config/   ← SOAP wiring, WebClient, properties scan
    │   ├── presentation/controller/ ← REST shims + /sso/receive + /health
    │   └── sso/
    │       ├── config/SsoProperties.java          ← @ConfigurationProperties("sso")
    │       ├── constants/IamCommentCodes.java
    │       ├── contract/                          ← JAXB-style POJOs (PARAMIN, PUBLISHOUT, etc.)
    │       ├── domain/                            ← UserContext, IssuedToken
    │       ├── endpoint/                          ← Spring-WS @Endpoint per service
    │       ├── entity/, repository/               ← JPA + Flyway tables
    │       ├── enums/TokenFormat.java
    │       ├── service/, service/impl/            ← PublishTokenServiceImpl is the heart
    │       ├── service/client/                    ← PID + Dealers + Dashboard WebClients
    │       ├── service/support/                   ← Audit, RateLimiter, OtpStore, NonceStore
    │       └── token/                             ← 5 generators (Igtk, Saml, Aes256Gcm, Rc4, WpcOtp)
    └── resources/
        ├── application.properties / application-sso*.yaml
        ├── db/migration/   ← Flyway V1–V4
        ├── xsd/, wsdl/     ← 5 SOAP contracts
```

---

## Things that look like quirks but aren't

- **REST shims (`/token/validate`, `/token/consume`, `/otp/validate`,
  `/admin/revoke`, `/admin/bypass`) coexist with SOAP** — same business
  logic, two transports. Lets the unchanged Node mocks talk to the broker.
  Real production swap may pick one transport and retire the other.
- **`/sso/receive` is HTTP, not SOAP.** Browsers can't POST a SOAP envelope
  from a 302 redirect, so PID's launch-token redirect lands here. It calls
  `PublishTokenService` internally, then auto-submits an HTML form to the
  vendor with `csrf_nonce`, `_flowId`, and the token field — exactly like
  the Node `routes/sso-launch.js`.
- **CSRF nonce uses an in-memory `NonceStore`,** not the DB. The DB-backed
  `markConsumed` is the canonical replay defense for SOAP callers; the
  in-memory map exists alongside it for the legacy REST `/token/consume`
  path. Restarts wipe in-flight nonces — fine, they're 5-minute TTL.
- **RSA keypair is generated at startup** (`SamlSigningKeyProvider`).
  Restarts invalidate previously issued SAML responses. Production would
  load the key from a vault.
- **Hardcoded POC secrets in `.env.example`** are intentional and committed.
- **Postgres replaces Oracle.** The client's real backend uses Oracle (`ojdbc11`),
  but Postgres in Docker is faster for local POC. JPA queries are vendor-neutral
  — moving to Oracle is a JDBC URL + driver swap.

---

## Where the SOAP contract lives

| Service | WSDL | Namespace |
|---|---|---|
| PublishToken | `/ws/publishtoken.wsdl` | `http://hyundaidealer.com/PublishTokenService/` |
| AuthenticateUser | `/ws/authenticateuser.wsdl` | `http://hyundaidealer.com/AuthenticateUserService/` |
| OtpValidate | `/ws/otpvalidate.wsdl` | `http://hyundaidealer.com/OtpValidateService/` |
| AdminRevoke | `/ws/adminrevoke.wsdl` | `http://hyundaidealer.com/AdminRevokeService/` |
| AdminBypass | `/ws/adminbypass.wsdl` | `http://hyundaidealer.com/AdminBypassService/` |

`PublishToken`'s shape matches the client backend's WSDL element-for-element
(`SourceSYS_ID`, `TargetSYS_ID`, `UserID`, `htxtToken`, `URL_D`, `URL_M`, `ERETURN`).

---

## Troubleshooting

**`docker compose up` says port 8000 is in use.**
The Node POC stack is already running. Run `cd ../poc && docker compose down`
first.

**Broker won't start — `relation "ia_tb_sso_sys_mngmt_m" does not exist`.**
Postgres came up after the broker tried to migrate. Restart the broker:
`docker compose restart iam-broker`.

**Vendor app shows "CSRF validation failed".**
The CSRF nonce expired (5-min TTL) or the broker restarted between mint and
consume. Start a fresh SSO from the portal.

**`docker compose build` fails with a Gradle error.**
Make sure you're on Docker Desktop ≥ 4.x; the multi-stage build needs
buildkit. `DOCKER_BUILDKIT=1 docker compose build iam-broker`.
