#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

out="$(mktemp -t msfvenom_stub.XXXXXX)"
trap 'rm -f "$out"' EXIT

"$ROOT/msfvenom" -f elf -o "$out"
chmod +x "$out"

echo "[*] Generated: $out"
echo "[*] Running stub:"
"$out"

