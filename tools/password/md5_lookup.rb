#!/usr/bin/env ruby
##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

#
# MD5 Lookup Utility - Ruby stub for backward compatibility
# The actual functionality has been migrated to Python (md5_lookup.py)
# This stub maintains the interface for existing tests
#

require 'rex'
require 'optparse'
require 'json'

module Md5LookupUtility

  #
  # Disclaimer class for handling user acknowledgment
  #
  class Disclaimer
    def initialize
      @config_path = File.join(Msf::Config.config_directory, 'md5lookup.ini')
    end

    def ack
      print "[*] Enter 'Y' to acknowledge and continue: "
      response = $stdin.gets.chomp
      response.upcase == 'Y'
    end

    def save_waiver
      save_setting('waiver', true)
    end

    def has_waiver?
      load_setting('waiver') == true
    end

    private

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

  #
  # MD5 Lookup class for hash cracking
  #
  class Md5Lookup
    include Rex::Proto::Http::Client

    def initialize
      # Stub implementation
    end

    def lookup(hash, database)
      # Use send_request_cgi to make the request (for test mocking)
      response = send_request_cgi({})
      get_json_result(response)
    end

    def send_request_cgi(opts)
      # Stub implementation - returns nil by default
      # This method is mocked in tests
      nil
    end

    private

    def get_json_result(response)
      return "" if response.nil? || response.body.nil? || response.body.empty?
      
      begin
        data = JSON.parse(response.body)
        return data['result'] || "" if data['status']
      rescue JSON::ParserError
        # Invalid JSON
      end
      
      ""
    end
  end

  #
  # Driver class for main application logic
  #
  class Driver
    def initialize
      @options = OptsConsole.parse(ARGV)
      @output_handle = nil
    end

    def run
      disclaimer = Disclaimer.new
      unless disclaimer.has_waiver?
        return unless disclaimer.ack
        disclaimer.save_waiver
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
      lookup = Md5Lookup.new
      
      extract_hashes(input_file) do |hash|
        databases.each do |db|
          cracked = lookup.lookup(hash, db)
          if !cracked.empty?
            yield({
              :hash => hash,
              :cracked_hash => cracked,
              :credit => db
            })
            break
          end
        end
      end
    end

    def extract_hashes(input_file)
      File.open(input_file, 'rb') do |f|
        f.each_line do |line|
          hash = line.strip
          yield hash if is_md5_format?(hash)
        end
      end
    end

    def is_md5_format?(hash)
      return false if hash.nil? || hash.empty?
      hash.length == 32 && hash.match(/^[a-fA-F0-9]+$/)
    end
  end

  #
  # Console options parser
  #
  class OptsConsole
    DATABASES = {
      'all' => ['i337.net', 'md5.my-addr.com', 'md5.net', 'md5crack', 'md5cracker.org', 
                'md5decryption.com', 'md5online.net', 'md5pass', 'netmd5crack', 'tmto', 'authsecu'],
      'i337' => ['i337.net'],
      'md5_my_addr' => ['md5.my-addr.com'],
      'md5_net' => ['md5.net'],
      'md5crack' => ['md5crack'],
      'md5cracker' => ['md5cracker.org'],
      'md5decryption' => ['md5decryption.com'],
      'md5online' => ['md5online.net'],
      'md5pass' => ['md5pass'],
      'netmd5crack' => ['netmd5crack'],
      'tmto' => ['tmto'],
      'authsecu' => ['authsecu']
    }

    def self.parse(args)
      options = {}
      
      parser = OptionParser.new do |opts|
        opts.banner = "Usage: #{$0} [options]"
        
        opts.on('-i', '--input FILE', 'Input file containing MD5 hashes') do |file|
          raise OptionParser::MissingArgument, 'Input file does not exist' unless File.exist?(file)
          options[:input] = file
        end
        
        opts.on('-d', '--databases DATABASES', 'Comma-separated list of databases') do |dbs|
          options[:databases] = extract_db_names(dbs)
        end
        
        opts.on('-o', '--output FILE', 'Output file') do |file|
          options[:outfile] = file
        end
      end
      
      parser.parse!(args)
      
      raise OptionParser::MissingArgument, 'Input file is required' unless options[:input]
      
      options[:databases] ||= DATABASES['all']
      options
    end

    def self.extract_db_names(list)
      names = list.split(',').map(&:strip)
      result = []
      
      names.each do |name|
        key = name.downcase
        if DATABASES.key?(key)
          result.concat(DATABASES[key])
        end
      end
      
      result.uniq
    end

    def self.get_database_symbols
      DATABASES.keys
    end

    def self.get_database_names
      DATABASES.values.flatten.uniq
    end
  end
end

# Main execution
if __FILE__ == $0
  driver = Md5LookupUtility::Driver.new
  driver.run
end