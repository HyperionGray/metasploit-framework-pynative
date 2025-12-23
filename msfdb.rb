#!/usr/bin/env ruby

# Show informational message about Python alternatives (unless quiet mode)
unless ENV['MSF_QUIET'] || ARGV.include?('-q')
  $stderr.puts "\n" + "="*70
  $stderr.puts "  Msfdb - Metasploit Database Manager (Legacy Ruby Version)"
  $stderr.puts "="*70
  $stderr.puts "  NOTE: This is the legacy Ruby version."
  $stderr.puts "  For the primary Python-native experience, use:"
  $stderr.puts "    python3 msfdb.py"
  $stderr.puts "="*70 + "\n"
end

require 'fileutils'
require 'io/console'
require 'json'
require 'net/http'
require 'net/https'
require 'open3'
require 'optparse'
require 'rex/socket'
require 'rex/text'
require 'securerandom'
require 'uri'
require 'yaml'
require 'pg'


include Rex::Text::Color

msfbase = __FILE__
while File.symlink?(msfbase)
  msfbase = File.expand_path(File.readlink(msfbase), File.dirname(msfbase))
end

$:.unshift(File.expand_path(File.join(File.dirname(msfbase), 'lib')))
$:.unshift(ENV['MSF_LOCAL_LIB']) if ENV['MSF_LOCAL_LIB']

require 'msfdb_helpers/pg_ctlcluster'
require 'msfdb_helpers/pg_ctl'
require 'msfdb_helpers/standalone'

require 'msfenv'

@script_name = File.basename(__FILE__)
@framework = File.expand_path(File.dirname(__FILE__))

@localconf = Msf::Config.config_directory
@db = "#{@localconf}/db"
@db_conf = "#{@localconf}/database.yml"
@pg_cluster_conf_root = "#{@localconf}/.local/etc/postgresql"
@db_driver = nil

@ws_tag = 'msf-ws'
@ws_conf = File.join(@framework, "#{@ws_tag}.ru")
@ws_ssl_key_default = "#{@localconf}/#{@ws_tag}-key.pem"
@ws_ssl_cert_default = "#{@localconf}/#{@ws_tag}-cert.pem"
@ws_log = "#{@localconf}/logs/#{@ws_tag}.log"
@ws_pid = "#{@localconf}/#{@ws_tag}.pid"

@current_user = ENV['LOGNAME'] || ENV['USERNAME'] || ENV['USER']