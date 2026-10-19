#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

if ! command -v node >/dev/null 2>&1 || ! command -v npm >/dev/null 2>&1; then
  echo "CyberGuard needs Node.js 18+ and npm."
  echo "On Kali/Debian, install Node.js from a trusted repository, then run this script again."
  exit 1
fi

NODE_MAJOR="$(node -p 'Number(process.versions.node.split(".")[0])')"
if [ "$NODE_MAJOR" -lt 18 ]; then
  echo "Node.js 18 or newer is required. Current version: $(node --version)"
  exit 1
fi

if [ ! -d node_modules ]; then
  echo "Installing project dependencies..."
  npm install
fi

echo
echo "CyberGuard Local Lab"
echo "1) Diagnostics only (recommended default)"
echo "2) Enable limited authorized website/Nmap checks"
read -r -p "Choose 1 or 2 [1]: " choice
case "${choice:-1}" in
  1) export CYBERGUARD_ENABLE_SCANS=false ;;
  2)
    echo
    echo "Use scans only against systems you own or are explicitly authorized to test."
    read -r -p "Type AUTHORIZED to enable bounded checks: " confirmation
    if [ "$confirmation" != "AUTHORIZED" ]; then
      echo "Checks remain disabled."
      export CYBERGUARD_ENABLE_SCANS=false
    else
      export CYBERGUARD_ENABLE_SCANS=true
    fi
    ;;
  *) echo "Invalid choice."; exit 1 ;;
esac

echo
echo "Running syntax and unit tests..."
npm test
echo
echo "Open this address on the same device: http://127.0.0.1:3000"
echo "Press Ctrl+C in this terminal to stop CyberGuard."
npm start
