#!/bin/bash
# =============================================================================
# Console Auth Setup Script
# =============================================================================
# Generates bcrypt password hashes and shows how to seed Vault with user
# credentials for the console-auth service.
#
# Usage:
#   ./scripts/console-auth-setup.sh        # Interactive
#   ./scripts/console-auth-setup.sh admin  # Generate hash for "admin" user
#
# The USERS format for CONSOLE_AUTH_USERS:
#   username:bcrypt_hash:role:display_name,username2:bcrypt_hash2:role2:name2
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "=== Cobalto Console Auth — User Setup ==="
echo ""

# Check dependencies
if ! command -v python3 &>/dev/null; then
    echo "ERROR: python3 is required but not found."
    exit 1
fi

GENERATE_HASH="${1:-}"

if [ -n "$GENERATE_HASH" ]; then
    # Non-interactive: generate hash for given username
    USERNAME="$GENERATE_HASH"
    echo -n "Password for $USERNAME: "
    read -rs PASSWORD
    echo ""
    echo -n "Confirm password: "
    read -rs PASSWORD_CONFIRM
    echo ""

    if [ "$PASSWORD" != "$PASSWORD_CONFIRM" ]; then
        echo "ERROR: Passwords do not match."
        exit 1
    fi

    HASH=$(python3 -c "
import bcrypt
import sys
pw = sys.argv[1].encode('utf-8')
salt = bcrypt.gensalt(rounds=12)
hashed = bcrypt.hashpw(pw, salt)
print(hashed.decode('utf-8'))
" "$PASSWORD")

    echo ""
    echo "=== Generated User Entry ==="
    echo ""
    echo "username:${USERNAME}:${HASH}:admin:${USERNAME}"
    echo ""
    echo "Add this to the CONSOLE_AUTH_USERS config (comma-separated for multiple users)."
    echo ""
    echo "=== Vault Seed Command ==="
    echo ""
    cat <<VAULTCMD
  vault kv put secret/cobalto/console-auth/users credentials="${USERNAME}:${HASH}:admin:${USERNAME}"

  vault kv put secret/cobalto/console-auth/jwt secret="$(openssl rand -hex 32)"
VAULTCMD
    echo ""
    exit 0
fi

# Interactive mode
echo "This script will generate bcrypt password hashes for console-auth users."
echo ""
echo "Enter user credentials (leave username empty to finish):"
echo ""

USER_ENTRIES=()

while true; do
    echo -n "Username (or empty to finish): "
    read -r USERNAME

    if [ -z "$USERNAME" ]; then
        break
    fi

    echo -n "Role [analyst]: "
    read -r ROLE
    ROLE="${ROLE:-analyst}"

    echo -n "Display Name [$USERNAME]: "
    read -r DISPLAY_NAME
    DISPLAY_NAME="${DISPLAY_NAME:-$USERNAME}"

    echo -n "Password: "
    read -rs PASSWORD
    echo ""
    echo -n "Confirm password: "
    read -rs PASSWORD_CONFIRM
    echo ""

    if [ "$PASSWORD" != "$PASSWORD_CONFIRM" ]; then
        echo "ERROR: Passwords do not match. Skipping user '$USERNAME'."
        echo ""
        continue
    fi

    HASH=$(python3 -c "
import bcrypt
pw = '${PASSWORD}'.encode('utf-8')
salt = bcrypt.gensalt(rounds=12)
hashed = bcrypt.hashpw(pw, salt)
print(hashed.decode('utf-8'))
")

    USER_ENTRIES+=("${USERNAME}:${HASH}:${ROLE}:${DISPLAY_NAME}")
    echo "✓ Added user: $USERNAME (role: $ROLE)"
    echo ""
done

if [ ${#USER_ENTRIES[@]} -eq 0 ]; then
    echo "No users added. Exiting."
    exit 0
fi

# Join entries with commas
USERS_STRING=$(IFS=,; echo "${USER_ENTRIES[*]}")

echo ""
echo "============================================"
echo "Setup Complete"
echo "============================================"
echo ""
echo "=== Generated CONSOLE_AUTH_USERS ==="
echo ""
echo "$USERS_STRING"
echo ""
echo "=== Vault Seed Commands ==="
echo ""
echo "  vault kv put secret/cobalto/console-auth/users credentials='$USERS_STRING'"
echo "  vault kv put secret/cobalto/console-auth/jwt secret='$(openssl rand -hex 32)'"
echo ""
echo "=== Manual K8s Secret (if ESO is not configured) ==="
echo ""
echo "kubectl create secret generic console-auth-secrets \\"
echo "  --namespace cobalto \\"
echo "  --from-literal=jwt_secret='$(openssl rand -hex 32)' \\"
echo "  --from-literal=users='$USERS_STRING'"
echo ""
