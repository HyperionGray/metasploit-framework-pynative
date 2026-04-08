#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

bundle config set --local path "${BUNDLE_PATH:-vendor/bundle}"
bundle config set --local without "${BUNDLE_WITHOUT:-coverage}"
bundle config set --local force_ruby_platform true

if [ ! -f config/database.yml ]; then
  cp config/database.yml.github_actions config/database.yml
fi

bundle install --jobs "${BUNDLE_JOBS:-4}" --retry 3
python3 -m pip install -r requirements.txt
