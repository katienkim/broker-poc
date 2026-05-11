#!/usr/bin/env bash
# Restore real PID metadata after running test-saml-inbound.sh.

set -euo pipefail

PROJECT_ROOT=$(cd "$(dirname "$0")/.." && pwd)
METADATA_DIR="$PROJECT_ROOT/apps/iam-broker/idp-metadata"
ENV_FILE="$PROJECT_ROOT/.env"

ACTIVE="$METADATA_DIR/pid-metadata.xml"
BACKUP="$METADATA_DIR/pid-metadata.xml.real.bak"

if [[ ! -f "$BACKUP" ]]; then
    echo "No backup found at $BACKUP — nothing to restore."
    exit 0
fi

cp "$BACKUP" "$ACTIVE"
echo "Restored real PID metadata."

if grep -q '^SAML_IDP_ENTITY_ID=' "$ENV_FILE"; then
    sed -i.tmp 's|^SAML_IDP_ENTITY_ID=.*|SAML_IDP_ENTITY_ID=https://stg-partner.hmg-corp.io/auth|' "$ENV_FILE"
    rm -f "$ENV_FILE.tmp"
    echo "Reset SAML_IDP_ENTITY_ID in .env to https://stg-partner.hmg-corp.io/auth"
fi

(cd "$PROJECT_ROOT" && docker compose restart iam-broker >/dev/null)
echo "Restarted broker. PID trust restored."
