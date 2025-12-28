#!/usr/bin/env ruby
# -*- coding: binary -*-
#
# $Id$
#
# This user interface listens on a port and provides clients that connect to
# it with an RPC or JSON-RPC interface to the Metasploit Framework.
#
# $Revision$
#

# Show informational message about Python alternatives (unless quiet mode)
unless ENV['MSF_QUIET'] || ARGV.include?('-q')
  $stderr.puts "\n" + "="*70
  $stderr.puts "  MsfRPCd - RPC Daemon (Legacy Ruby Version)"
  $stderr.puts "="*70
  $stderr.puts "  NOTE: This is the legacy Ruby version."
  $stderr.puts "  For the primary Python-native experience, use:"
  $stderr.puts "    python3 msfrpcd.py"
  $stderr.puts "="*70 + "\n"
end

RPC_TYPE = 'Msg'
WS_TAG = 'msf-ws'
WS_RPC_TAG = 'msf-json-rpc'
WS_CONF = "#{WS_RPC_TAG}.ru"
WS_ENV = 'production'


def start_json_rpc_service(conf:, address:, port:, ssl:, ssl_key:, ssl_cert:,
                           ssl_disable_verify:, daemonize:, log:, pid:)