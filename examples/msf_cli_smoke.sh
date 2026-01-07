#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

export MSF_PYNATIVE_HOME
MSF_PYNATIVE_HOME="$(mktemp -d)"
trap 'rm -rf "$MSF_PYNATIVE_HOME"' EXIT

echo "[*] Using temporary MSF_PYNATIVE_HOME: $MSF_PYNATIVE_HOME"

"$ROOT/msf" workspace
"$ROOT/msf" search tomcat_enum --limit 1
"$ROOT/msf" use auxiliary/scanner/http/tomcat_enum
"$ROOT/msf" set RHOSTS 127.0.0.1
"$ROOT/msf" set RPORT 80
"$ROOT/msf" show options
"$ROOT/msf" run --dry-run

echo "[+] msf CLI smoke run complete"

