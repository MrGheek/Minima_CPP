#!/usr/bin/env bash
set -euo pipefail

# Pure Minima — Secure Restore Script
# Restores from a backup archive and/or encrypted seed export.

DATA_DIR="${HOME}/.minima"
BACKUP_FILE=""
SEED_FILE=""
PASSWORD=""

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

usage() {
    echo "Usage: $0 -f BACKUP_FILE [-s SEED_EXPORT] [-p PASSWORD] [-d DATA_DIR]"
    echo ""
    echo "  -f BACKUP_FILE  Required. The backup .tar.gz file to restore."
    echo "  -s SEED_EXPORT  Optional. Encrypted seed export file (.enc)."
    echo "  -p PASSWORD     Required if -s is provided. Password to decrypt the seed export."
    echo "  -d DATA_DIR     Minima data directory (default: ~/.minima)"
    echo ""
    echo "This script:"
    echo "  1. Restores the Minima data directory from the backup archive"
    echo "  2. If a seed export is provided, imports the encrypted seed phrase"
    exit 1
}

while getopts "f:s:p:d:h" opt; do
    case $opt in
        f) BACKUP_FILE="$OPTARG" ;;
        s) SEED_FILE="$OPTARG" ;;
        p) PASSWORD="$OPTARG" ;;
        d) DATA_DIR="$OPTARG" ;;
        h) usage ;;
        *) usage ;;
    esac
done

if [ -z "$BACKUP_FILE" ]; then
    echo -e "${RED}Error: Backup file is required.${NC}"
    usage
fi

if [ ! -f "$BACKUP_FILE" ]; then
    echo -e "${RED}Error: Backup file not found: ${BACKUP_FILE}${NC}"
    exit 1
fi

if [ -n "$SEED_FILE" ] && [ -z "$PASSWORD" ]; then
    echo -e "${RED}Error: Password is required when restoring from a seed export.${NC}"
    usage
fi

if [ -n "$SEED_FILE" ] && [ ! -f "$SEED_FILE" ]; then
    echo -e "${RED}Error: Seed export file not found: ${SEED_FILE}${NC}"
    exit 1
fi

echo -e "${GREEN}==> Pure Minima Secure Restore${NC}"
echo "    Backup file: $BACKUP_FILE"
if [ -n "$SEED_FILE" ]; then
    echo "    Seed export: $SEED_FILE"
fi
echo "    Data directory: $DATA_DIR"
echo ""

# Confirm overwrite
echo -e "${YELLOW}WARNING: This will OVERWRITE your current data at ${DATA_DIR}${NC}"
read -rp "Continue? (y/N) " CONFIRM
if [ "$CONFIRM" != "y" ] && [ "$CONFIRM" != "Y" ]; then
    echo "Aborted."
    exit 0
fi

# Step 1: Backup existing data if present
if [ -d "$DATA_DIR" ]; then
    OLD_BACKUP="${DATA_DIR}.bak.$(date +%Y%m%d_%H%M%S)"
    mv "$DATA_DIR" "$OLD_BACKUP"
    echo -e "${GREEN}    Existing data moved to: ${OLD_BACKUP}${NC}"
fi

# Step 2: Restore data directory
echo -e "${YELLOW}==> Restoring data directory...${NC}"
mkdir -p "$DATA_DIR"
tar xzf "$BACKUP_FILE" -C "$(dirname "$DATA_DIR")"
echo -e "${GREEN}    Data directory restored.${NC}"

# Step 3: Import seed if provided
if [ -n "$SEED_FILE" ]; then
    echo ""
    echo -e "${YELLOW}==> Importing encrypted seed phrase...${NC}"

    # Copy seed file to a location the node can access
    SEED_DEST="${DATA_DIR}/seed-import.enc"
    cp "$SEED_FILE" "$SEED_DEST"

    if command -v minima &>/dev/null; then
        minima -daemon -rpcenable &
        MINIMA_PID=$!
        sleep 3

        if minima -rpc -command="vault action:import password:${PASSWORD} file:${SEED_DEST}" -rpcpassword="" 2>/dev/null; then
            echo -e "${GREEN}    Seed phrase imported and private keys restored!${NC}"
        else
            echo -e "${RED}    WARNING: Could not import seed phrase automatically.${NC}"
            echo "    Start the node and run manually:"
            echo "    vault action:import password:YOUR_PASSWORD file:${SEED_DEST}"
        fi

        kill "$MINIMA_PID" 2>/dev/null || true
        wait "$MINIMA_PID" 2>/dev/null || true
    else
        echo -e "${YELLOW}    minima binary not found. Start the node and run:${NC}"
        echo "    vault action:import password:YOUR_PASSWORD file:${SEED_DEST}"
    fi

    # Clean up the temporary copy
    rm -f "$SEED_DEST"
fi

echo ""
echo -e "${GREEN}==> Restore Complete${NC}"
echo ""
echo "    Next steps:"
echo "    1. Start the node: minima -daemon"
echo "    2. Verify: vault action:status"
echo "    3. Lock the node: vault action:passwordlock password:YOUR_PASSWORD"
