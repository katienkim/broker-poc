#!/usr/bin/env bash
# Local SAML inbound smoke test.
#
# Pretends to be PID: generates a test IdP keypair, swaps the broker's trust
# to that test IdP, then signs a SAMLResponse with the test private key and
# POSTs it to /sso/saml/acs/pid. Verifies that the broker accepts the
# assertion and emits the auto-submit HTML form.
#
# Re-run safe — once the test IdP keystore + metadata exist they're reused.
# To restore the real PID metadata afterwards: scripts/restore-pid-metadata.sh

set -euo pipefail

PROJECT_ROOT=$(cd "$(dirname "$0")/.." && pwd)
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
KEYSTORE_DIR="$PROJECT_ROOT/apps/iam-broker/keystore"
METADATA_DIR="$PROJECT_ROOT/apps/iam-broker/idp-metadata"
ENV_FILE="$PROJECT_ROOT/.env"

BROKER_HOST=${BROKER_HOST:-broker.sso.test:8000}
BROKER_BASE="http://$BROKER_HOST"

TEST_IDP_ALIAS=test-idp
TEST_IDP_STOREPASS=changeit
TEST_IDP_ENTITY_ID="https://test-idp.local/saml"
SP_ENTITY_ID=${SAML_SP_ENTITY_ID:-http://broker.sso.test:8000/sso/saml/metadata}
TARGET_VENDOR=${TARGET_VENDOR:-vendor-saml}
USER_ID=${USER_ID:-DLR011001703}

bold()  { printf '\n\033[1m== %s ==\033[0m\n' "$*"; }
log()   { printf '  %s\n' "$*"; }
ok()    { printf '  \033[32m✓\033[0m %s\n' "$*"; }
fail()  { printf '  \033[31m✗\033[0m %s\n' "$*"; exit 1; }

# ── 1. Test IdP keypair ─────────────────────────────────────────────────────
bold "1. Test IdP keypair"
if [[ ! -f "$KEYSTORE_DIR/test-idp.p12" ]]; then
    log "generating $KEYSTORE_DIR/test-idp.p12"
    docker run --rm -v "$KEYSTORE_DIR:/keystore" eclipse-temurin:21-jre-alpine \
        keytool -genkeypair \
            -alias "$TEST_IDP_ALIAS" \
            -keyalg RSA -keysize 2048 \
            -validity 365 -sigalg SHA256withRSA \
            -keystore /keystore/test-idp.p12 \
            -storetype PKCS12 -storepass "$TEST_IDP_STOREPASS" \
            -dname "CN=test-idp.local, OU=Test, O=Test, L=Test, ST=Test, C=US" \
            >/dev/null 2>&1
    ok "created"
else
    ok "$KEYSTORE_DIR/test-idp.p12 already exists"
fi

# ── 2. Test IdP metadata XML ────────────────────────────────────────────────
bold "2. Test IdP metadata"
TEST_METADATA="$METADATA_DIR/test-idp-metadata.xml"
if [[ ! -f "$TEST_METADATA" ]] || [[ "$KEYSTORE_DIR/test-idp.p12" -nt "$TEST_METADATA" ]]; then
    log "exporting cert + writing $TEST_METADATA"
    CERT_B64=$(docker run --rm -v "$KEYSTORE_DIR:/keystore" eclipse-temurin:21-jre-alpine \
        keytool -exportcert \
            -keystore /keystore/test-idp.p12 \
            -alias "$TEST_IDP_ALIAS" \
            -storepass "$TEST_IDP_STOREPASS" \
            -rfc 2>/dev/null \
        | sed -n '/BEGIN CERTIFICATE/,/END CERTIFICATE/p' \
        | sed '1d;$d' | tr -d '\n')

    cat > "$TEST_METADATA" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
                     xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
                     entityID="$TEST_IDP_ENTITY_ID">
  <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"
                       WantAuthnRequestsSigned="false">
    <md:KeyDescriptor use="signing">
      <ds:KeyInfo>
        <ds:X509Data>
          <ds:X509Certificate>$CERT_B64</ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </md:KeyDescriptor>
    <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</md:NameIDFormat>
    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                            Location="https://test-idp.local/saml/sso"/>
    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                            Location="https://test-idp.local/saml/sso"/>
  </md:IDPSSODescriptor>
</md:EntityDescriptor>
EOF
    ok "wrote $TEST_METADATA"
else
    ok "$TEST_METADATA already exists"
fi

# ── 3. Swap broker's trusted IdP metadata ───────────────────────────────────
bold "3. Swap broker trust to test IdP"
ACTIVE="$METADATA_DIR/pid-metadata.xml"
BACKUP="$METADATA_DIR/pid-metadata.xml.real.bak"

if [[ -f "$ACTIVE" ]] && [[ ! -f "$BACKUP" ]]; then
    # First time — back up the real PID metadata if it isn't the test one already
    if ! grep -q "$TEST_IDP_ENTITY_ID" "$ACTIVE" 2>/dev/null; then
        cp "$ACTIVE" "$BACKUP"
        log "backed up real PID metadata → $(basename "$BACKUP")"
    fi
fi
cp "$TEST_METADATA" "$ACTIVE"
ok "installed test-idp metadata as pid-metadata.xml"

if grep -q '^SAML_IDP_ENTITY_ID=' "$ENV_FILE"; then
    sed -i.tmp "s|^SAML_IDP_ENTITY_ID=.*|SAML_IDP_ENTITY_ID=$TEST_IDP_ENTITY_ID|" "$ENV_FILE"
    rm -f "$ENV_FILE.tmp"
else
    printf '\nSAML_IDP_ENTITY_ID=%s\n' "$TEST_IDP_ENTITY_ID" >> "$ENV_FILE"
fi
ok "set SAML_IDP_ENTITY_ID=$TEST_IDP_ENTITY_ID in .env"

# ── 4. Restart broker so it loads the new IdP cert ──────────────────────────
bold "4. Restart broker"
(cd "$PROJECT_ROOT" && docker compose restart iam-broker >/dev/null)
log "waiting for broker health (max 60s)…"
for i in $(seq 1 60); do
    if curl -sf -o /dev/null "$BROKER_BASE/health"; then
        ok "broker is healthy"
        break
    fi
    sleep 1
    if [[ "$i" == "60" ]]; then
        fail "broker did not become healthy. Run: docker compose logs iam-broker | tail -50"
    fi
done

# ── 5. Bootstrap a state code via /api/v1/saml/login ────────────────────────
bold "5. Get state code from /api/v1/saml/login"
LOCATION=$(curl -sD - -o /dev/null \
    "$BROKER_BASE/api/v1/saml/login?target_vendor=$TARGET_VENDOR" \
    | grep -iE '^location:' || true)
STATE_CODE=$(echo "$LOCATION" \
    | grep -oE 'RelayState=[^&[:space:]]+' \
    | cut -d= -f2 \
    | tr -d '\r\n')
if [[ -z "$STATE_CODE" ]]; then
    fail "couldn't extract state code from /api/v1/saml/login redirect. Got: $LOCATION"
fi
ok "state code: $STATE_CODE"

# ── 6. Build, sign, POST the SAML response ──────────────────────────────────
bold "6. Build + sign + POST SAML response"
docker run --rm \
    --add-host broker.sso.test:host-gateway \
    -v "$SCRIPT_DIR:/scripts:ro" \
    -v "$KEYSTORE_DIR:/keystore:ro" \
    python:3.12-slim \
    bash -c "pip install -q signxml cryptography requests lxml \
        && python /scripts/saml_sign_and_post.py \
            --acs-url '$BROKER_BASE/sso/saml/acs/pid' \
            --idp-entity-id '$TEST_IDP_ENTITY_ID' \
            --sp-entity-id '$SP_ENTITY_ID' \
            --state-code '$STATE_CODE' \
            --keystore /keystore/test-idp.p12 \
            --keystore-pass '$TEST_IDP_STOREPASS' \
            --alias '$TEST_IDP_ALIAS' \
            --user-id '$USER_ID'"
