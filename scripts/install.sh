#!/usr/bin/env bash
set -euo pipefail

echo "==> Pure Minima Installer"

OS="$(uname -s)"
ARCH="$(uname -m)"

if [ "$OS" = "Darwin" ]; then
    echo "==> Installing dependencies (macOS)..."
    brew install cmake sqlite3 openssl zlib curl boost
    OPENSSL_ROOT="$(brew --prefix openssl)"
elif [ "$OS" = "Linux" ]; then
    echo "==> Installing dependencies (Linux)..."
    sudo apt-get update
    sudo apt-get install -y build-essential cmake libsqlite3-dev libssl-dev zlib1g-dev libcurl4-openssl-dev libboost-dev
    OPENSSL_ROOT=""
else
    echo "Unsupported OS: $OS"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
BUILD_DIR="$SCRIPT_DIR/build"

echo "==> Building Pure Minima..."
mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"
if [ -n "$OPENSSL_ROOT" ]; then
    cmake .. -DCMAKE_BUILD_TYPE=Release -DOPENSSL_ROOT_DIR="$OPENSSL_ROOT"
else
    cmake .. -DCMAKE_BUILD_TYPE=Release
fi
make -j"$(nproc 2>/dev/null || sysctl -n hw.ncpu)"

echo "==> Installing binary..."
sudo cp minima /usr/local/bin/minima
sudo chmod 755 /usr/local/bin/minima

if [ "$OS" = "Linux" ]; then
    echo "==> Installing systemd service..."
    sudo cp "$SCRIPT_DIR/scripts/minima.service" /etc/systemd/system/minima.service
    sudo systemctl daemon-reload
    echo "==> To start the service:"
    echo "    sudo systemctl enable minima"
    echo "    sudo systemctl start minima"
elif [ "$OS" = "Darwin" ]; then
    echo "==> Installing launchd service..."
    sudo mkdir -p /usr/local/var/log
    sudo cp "$SCRIPT_DIR/scripts/com.minima.plist" /Library/LaunchDaemons/com.minima.node.plist
    echo "==> To load the service:"
    echo "    sudo launchctl load /Library/LaunchDaemons/com.minima.node.plist"
fi

echo ""
echo "==> Pure Minima installed successfully."
echo ""

# Post-install security guidance
echo "=== POST-INSTALL SECURITY SETUP ==="
echo ""
echo "1. FIRST RUN: Start the node to generate your seed phrase:"
echo "   minima"
echo ""
echo "2. EXPORT YOUR SEED (encrypted with a password):"
echo "   vault action:export password:YOUR_STRONG_PASSWORD file:seed-backup.enc"
echo ""
echo "3. LOCK YOUR NODE (encrypt seed at rest):"
echo "   vault action:passwordlock password:YOUR_STRONG_PASSWORD"
echo ""
echo "4. VERIFY:"
echo "   vault action:status"
echo ""
echo "5. STORE YOUR BACKUP OFFLINE:"
echo "   Keep seed-backup.enc on a USB drive or encrypted cloud storage."
echo "   Store your password separately (password manager, paper backup)."
echo "   NEVER share your seed phrase or password with anyone."
echo ""
echo "6. FOR RPC ACCESS (optional):"
echo "   Start with: minima -daemon -rpcenable -rpcpassword \"STRONG_UNIQUE_PASSWORD\""
echo ""
echo "See README.md and SECURITY.md for full documentation."
