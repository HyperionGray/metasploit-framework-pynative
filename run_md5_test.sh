#!/bin/bash

cd /workspace

echo "Running the md5_lookup test to see specific errors..."

# Set up environment
export RAILS_ENV=test
export BUNDLE_WITHOUT="coverage development pcap"

# Run just the md5_lookup test
bundle exec rspec spec/tools/md5_lookup_spec.rb --format documentation --backtrace