#!/bin/bash

cd /workspace

echo "Running the specific failing test..."

# Try to run just the md5_lookup test to see the exact error
RAILS_ENV=test bundle exec rspec spec/tools/md5_lookup_spec.rb -v 2>&1 | head -50