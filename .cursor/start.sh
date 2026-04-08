#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

if [ ! -f config/database.yml ]; then
  cp config/database.yml.github_actions config/database.yml
fi

run_as_postgres() {
  if command -v sudo >/dev/null 2>&1; then
    sudo -u postgres bash -lc "$1"
  else
    su postgres -s /bin/bash -lc "$1"
  fi
}

if command -v pg_lsclusters >/dev/null 2>&1 && command -v pg_ctlcluster >/dev/null 2>&1; then
  cluster_version="$(pg_lsclusters --no-header 2>/dev/null | awk 'NR==1 {print $1}')"

  if [ -n "$cluster_version" ]; then
    pg_ctlcluster "$cluster_version" main start >/dev/null 2>&1 || true
    run_as_postgres "psql -tc \"ALTER USER postgres WITH PASSWORD 'postgres';\"" >/dev/null 2>&1 || true
    run_as_postgres "createdb -O postgres metasploit_framework_development" >/dev/null 2>&1 || true
    run_as_postgres "createdb -O postgres metasploit_framework_test" >/dev/null 2>&1 || true
  fi
fi
