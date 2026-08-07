#!/usr/bin/env bash
set -euo pipefail

# Pure Minima — Secure Backup Script
# Uses the new vault export workflow with mandatory password encryption.

DATA_DIR="${HOME}/.minima"
BACKUP_DIR="${HOME}/minima-backups"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
BACKUP_FILE="${BACKUP_DIR}/minima-backup-${TIMESTAMP}.tar.gz"
SEED_EXPORT="${BACKUP_DIR}/seed-export-${TIMESTAMP}.enc"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

usage() {
    echo "Usage: $0 -p PASSWORD [-d DATA_DIR] [-o OUTPUT_DIR]"
    echo ""
    echo "  -p PASSWORD    Required. Password to encrypt the seed phrase export."
    echo "  -d DATA_DIR    Minima data directory (default: ~/.minima)"
    echo "  -o OUTPUT_DIR  Backup output directory (default: ~/minima-backups)"
    echo ""
    echo "This script:"
    echo "  1. Exports your seed phrase encrypted with your password"
    echo "  2. Creates a tar.gz of your Minima data directory"
    echo "  3. Both files are stored in the output directory"
    exit 1
}

PASSWORD=""
while getopts "p:d:o:h" opt; do
    case $opt in
        p) PASSWORD="$OPTARG" ;;
        d) DATA_DIR="$OPTARG" ;;
        o) BACKUP_DIR="$OPTARG" ;;
        h) usage ;;
        *) usage ;;
    esac
done

if [ -z "$PASSWORD" ]; then
    echo -e "${RED}Error: Password is required.${NC}"
    echo "Use -p to provide a password for encrypting your seed phrase."
    echo ""
    usage
fi

mkdir -p "$BACKUP_DIR"

echo -e "${GREEN}==> Pure Minima Secure Backup${NC}"
echo "    Data directory: $DATA_DIR"
echo "    Output directory: $BACKUP_DIR"
echo ""

# Step 1: Export encrypted seed phrase
echo -e "${YELLOW}==> Step 1: Exporting encrypted seed phrase...${NC}"

if command -v minima &>/dev/null; then
    # Try to export via RPC if node is running
    SEED_EXPORT_PATH="${BACKUP_DIR}/seed-export-${TIMESTAMP}.enc"
    if minima -rpc -command="vault action:export password:${PASSWORD} file:${SEED_EXPORT_PATH}" -rpcpassword="" 2>/dev/null; then
        echo -e "${GREEN}    Seed phrase exported to: ${SEED_EXPORT_PATH}${NC}"
    else
        echo -e "${YELLOW}    Could not connect to running node. Starting temporary daemon...${NC}"
        minima -daemon -rpcenable &
        MINIMA_PID=$!
        sleep 3

        if minima -rpc -command="vault action:export password:${PASSWORD} file:${SEED_EXPORT_PATH}" -rpcpassword="" 2>/dev/null; then
            echo -e "${GREEN}    Seed phrase exported to: ${SEED_EXPORT_PATH}${NC}"
        else
            echo -e "${RED}    WARNING: Could not export seed phrase. Is the node running?${NC}"
            echo "    You can manually export with: vault action:export password:YOUR_PASSWORD file:seed-export.enc"
        fi

        kill "$MINIMA_PID" 2>/dev/null || true
        wait "$MINIMA_PID" 2>/dev/null || true
    fi
else
    echo -e "${RED}    WARNING: minima binary not found in PATH.${NC}"
    echo "    You can manually export with: vault action:export password:YOUR_PASSWORD file:seed-export.enc"
fi

echo ""

# Step 2: Backup data directory
echo -e "${YELLOW}==> Step 2: Creating data directory backup...${NC}"

if [ -d "$DATA_DIR" ]; then
    tar czf "$BACKUP_FILE" -C "$(dirname "$DATA_DIR")" "$(basename "$DATA_DIR")" 2>/dev/null
    echo -e "${GREEN}    Data backup created: ${BACKUP_FILE}${NC}"
    echo "    Size: $(du -h "$BACKUP_FILE" | cut -f1)"
else
    echo -e "${YELLOW}    No data directory found at ${DATA_DIR}${NC}"
fi

echo ""
echo -e "${GREEN}==> Backup Complete${NC}"
echo ""
echo "    Files created:"
if [ -f "$SEED_EXPORT" ]; then
    echo "    - Encrypted seed: ${SEED_EXPORT}"
fi
if [ -f "$BACKUP_FILE" ]; then
    echo "    - Data archive:   ${BACKUP_FILE}"
fi
echo ""
echo -e "${YELLOW}    IMPORTANT: Store your password securely and separately from these files!${NC}"
echo -e "${YELLOW}    To restore, use: scripts/restore.sh -p YOUR_PASSWORD -f ${BACKUP_FILE}${NC}"
