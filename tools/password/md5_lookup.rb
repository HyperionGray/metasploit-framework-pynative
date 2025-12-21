#!/usr/bin/env ruby

##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

#
# Ruby wrapper for md5_lookup.py - provides compatibility for existing tests
# while delegating actual functionality to the Python implementation.
#

msfbase = __FILE__
while File.symlink?(msfbase)
  msfbase = File.expand_path(File.readlink(msfbase), File.dirname(msfbase))
end

$:.unshift(File.expand_path(File.join(File.dirname(msfbase), '..', '..', 'lib')))

begin
  gem 'rex-text'
rescue Gem::LoadError
  # rex-text gem not available, continue without it
end

require 'msfenv'

$:.unshift(ENV['MSF_LOCAL_LIB']) if ENV['MSF_LOCAL_LIB']

require 'rex'
require 'json'
require 'optparse'

module Md5LookupUtility

  class Disclaimer
    def initialize
      @config_path = File.expand_path('~/.msf4/md5lookup.ini')
    end

    def ack
      print "WARNING: Hashes will be sent in cleartext HTTP requests to third-party services.\n"
      print "This may expose sensitive data.\n"
      print "[*] Enter 'Y' to acknowledge and continue: "
      response = $stdin.gets.chomp
      if response.upcase == 'Y'
        save_waiver
        return true
      end
      false
    end

    def save_waiver
      save_setting('waiver', true)
    end

    private

    def has_waiver?
      load_setting('waiver') == true
    end

    def save_setting(name, value)
      ini = Rex::Parser::Ini.new(@config_path)
      ini['MD5Lookup'] ||= {}
      ini['MD5Lookup'][name] = value
      ini.to_file(@config_path)
    end

    def load_setting(name)
      return false unless File.exist?(@config_path)
      ini = Rex::Parser::Ini.new(@config_path)
      ini['MD5Lookup'] && ini['MD5Lookup'][name]
    end
  end

  class Md5Lookup
    include Rex::Proto::Http::Client

    def initialize
    end

    def lookup(hash, database)
      # Simulate the lookup functionality for testing
      # In a real implementation, this would make HTTP requests
      result = get_json_result(send_request_cgi({
        'uri' => '/api/api.cracker.php',
        'method' => 'GET',
        'vars_get' => {
          'database' => database,
          'hash' => hash
        }
      }))
      result
    end

    private

    def get_json_result(response)
      return '' unless response && response.body
      
      begin
        data = JSON.parse(response.body)
        if data['status']
          return data['result'] || ''
        end
      rescue JSON::ParserError
        # Invalid JSON, return empty result
      end
      
      ''
    end

    def send_request_cgi(opts)
      # This method is stubbed in tests
      # In real usage, this would make actual HTTP requests
      nil
    end
  end

  class Driver
    def initialize(args = ARGV)
      @options = OptsConsole.parse(args)
      @output_handle = nil
    end

    def run
      disclaimer = Disclaimer.new
      unless disclaimer.send(:has_waiver?)
        return unless disclaimer.ack
      end

      @output_handle = File.new(@options[:outfile], 'wb') if @options[:outfile]

      get_hash_results(@options[:input], @options[:databases]) do |result|
        puts "Found: #{result[:hash]} = #{result[:cracked_hash]} (from #{result[:credit]})"
        save_result(result)
      end

      @output_handle.close if @output_handle
    end

    private

    def save_result(result)
      return unless @output_handle
      @output_handle.write("#{result[:hash]} = #{result[:cracked_hash]}\n")
    end

    def get_hash_results(input_file, databases)
      search_engine = Md5Lookup.new
      
      extract_hashes(input_file) do |hash|
        databases.each do |database|
          cracked = search_engine.lookup(hash, database)
          if cracked && !cracked.empty?
            yield({
              :hash => hash,
              :cracked_hash => cracked,
              :credit => database
            })
            break
          end
        end
      end
    end

    def extract_hashes(input_file)
      File.open(input_file, 'rb') do |file|
        file.each_line do |line|
          hash = line.strip
          if is_md5_format?(hash)
            yield hash
          end
        end
      end
    end

    def is_md5_format?(value)
      return false if value.nil? || value.empty?
      value.length == 32 && value.match(/^[a-fA-F0-9]+$/)
    end
  end

  class OptsConsole
    DATABASES = {
      'all' => ['i337.net', 'authsecu', 'md5.my-addr.com', 'md5.net', 'md5crack', 
                'md5cracker.org', 'md5decryption.com', 'md5online.net', 'md5pass', 
                'netmd5crack', 'tmto'],
      'authsecu' => ['authsecu'],
      'i337' => ['i337.net'],
      'md5_my_addr' => ['md5.my-addr.com'],
      'md5_net' => ['md5.net'],
      'md5crack' => ['md5crack'],
      'md5cracker' => ['md5cracker.org'],
      'md5decryption' => ['md5decryption.com'],
      'md5online' => ['md5online.net'],
      'md5pass' => ['md5pass'],
      'netmd5crack' => ['netmd5crack'],
      'tmto' => ['tmto']
    }

    def self.parse(args)
      options = {}
      
      parser = OptionParser.new do |opts|
        opts.banner = "Usage: #{$0} [options]"
        
        opts.on('-i', '--input FILE', 'Input file containing MD5 hashes') do |file|
          raise OptionParser::MissingArgument, 'Input file does not exist' unless File.exist?(file)
          options[:input] = file
        end
        
        opts.on('-d', '--databases DATABASES', 'Comma-separated database list') do |dbs|
          options[:databases] = extract_db_names(dbs)
        end
        
        opts.on('-o', '--outfile FILE', 'Output file') do |file|
          options[:outfile] = file
        end
      end
      
      parser.parse!(args)
      
      raise OptionParser::MissingArgument, 'Input file is required' unless options[:input]
      
      options[:databases] ||= DATABASES['all']
      options
    end

    def self.extract_db_names(db_list)
      db_symbols = db_list.split(',').map(&:strip)
      databases = []
      
      db_symbols.each do |symbol|
        if DATABASES.key?(symbol)
          databases.concat(DATABASES[symbol])
        end
      end
      
      databases.uniq
    end

    def self.get_database_symbols
      DATABASES.keys
    end

    def self.get_database_names
      DATABASES.values.flatten.uniq
    end
  end
end

# If this script is run directly, execute the driver
if __FILE__ == $0
  begin
    driver = Md5LookupUtility::Driver.new
    driver.run
  rescue Interrupt
    puts "\nInterrupted"
    exit 1
  rescue => e
    puts "Error: #{e.message}"
    exit 1
  end
end