#!/bin/bash

set -e

# GreninjaSec Installer Script
echo "🥷 GreninjaSec Installer"
echo "========================"
echo ""

# Detect OS and Architecture
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

case "$OS" in
    linux*)
        OS="linux"
        ;;
    darwin*)
        OS="darwin"
        ;;
    *)
        echo "❌ Unsupported operating system: $OS"
        exit 1
        ;;
esac

case "$ARCH" in
    x86_64)
        ARCH="amd64"
        ;;
    amd64)
        ARCH="amd64"
        ;;
    arm64)
        ARCH="arm64"
        ;;
    aarch64)
        ARCH="arm64"
        ;;
    *)
        echo "❌ Unsupported architecture: $ARCH"
        exit 1
        ;;
esac

# Get latest release version from GitHub API
echo "📡 Fetching latest version..."
LATEST_VERSION=$(curl -s https://api.github.com/repos/akashgreninja/greninjaSec/releases/latest | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')

if [ -z "$LATEST_VERSION" ]; then
    echo "❌ Failed to fetch latest version"
    exit 1
fi

echo "✅ Latest version: $LATEST_VERSION"
echo ""

# Construct download URL
BINARY_NAME="greninjasec-${OS}-${ARCH}"
DOWNLOAD_URL="https://github.com/akashgreninja/greninjaSec/releases/download/${LATEST_VERSION}/${BINARY_NAME}"

echo "📥 Downloading GreninjaSec..."
echo "URL: $DOWNLOAD_URL"

# Download binary
TMP_DIR=$(mktemp -d)
TMP_FILE="$TMP_DIR/greninjasec"

if ! curl -L -o "$TMP_FILE" "$DOWNLOAD_URL"; then
    echo "❌ Failed to download binary"
    rm -rf "$TMP_DIR"
    exit 1
fi

# Make executable
chmod +x "$TMP_FILE"

# Determine install location
INSTALL_DIR="/usr/local/bin"
if [ ! -w "$INSTALL_DIR" ]; then
    echo ""
    echo "⚠️  Requires sudo to install to $INSTALL_DIR"
    sudo mv "$TMP_FILE" "$INSTALL_DIR/greninjasec"
else
    mv "$TMP_FILE" "$INSTALL_DIR/greninjasec"
fi

# Clean up
rm -rf "$TMP_DIR"

echo ""
echo "✅ GreninjaSec $LATEST_VERSION installed successfully!"
echo ""
echo "🚀 Quick start:"
echo "   greninjasec --help"
echo "   greninjasec --all --attack-chains --path /path/to/your/code"
echo ""
echo "📖 Documentation: https://github.com/akashgreninja/greninjaSec"
