#!/usr/bin/env ruby

##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

msfbase = __FILE__
while File.symlink?(msfbase)
  msfbase = File.expand_path(File.readlink(msfbase), File.dirname(msfbase))
end

$:.unshift(File.expand_path(File.join(File.dirname(msfbase), '..', '..', 'lib')))

require 'msfenv'
require 'rex'
require 'optparse'
require 'json'

module Md5LookupUtility

  class Disclaimer
    def initialize
      @config_path = File.join(Msf::Config.config_directory, 'md5lookup.ini')
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
      setting = load_setting('waiver')
      setting == true || setting == 'true'
    end

    def save_setting(name, value)
      ini = Rex::Parser::Ini.new(@config_path)
      ini['MD5Lookup'] ||= {}
      ini['MD5Lookup'][name] = value
      ini.to_file(@config_path)
    end

    def load_setting(name)
      return nil unless File.exist?(@config_path)
      ini = Rex::Parser::Ini.new(@config_path)
      ini['MD5Lookup'] && ini['MD5Lookup'][name]
    end
  end

  class Md5Lookup
    include Rex::Proto::Http::Client

    DATABASES = {
      'all' => nil,
      'authsecu' => 'authsecu',
      'i337' => 'i337.net',
      'md5_my_addr' => 'md5.my-addr.com',
      'md5_net' => 'md5.net',
      'md5crack' => 'md5crack',
      'md5cracker' => 'md5cracker.org',
      'md5decryption' => 'md5decryption.com',
      'md5online' => 'md5online.net',
      'md5pass' => 'md5pass',
      'netmd5crack' => 'netmd5crack',
      'tmto' => 'tmto'
    }

    LOOKUP_ENDPOINTS = [
      'https://md5cracker.org/api/api.cracker.php',
      'http://md5cracker.org/api/api.cracker.php'
    ]

    def initialize
      super
    end

    def lookup(hash_value, database)
      LOOKUP_ENDPOINTS.each do |endpoint|
        uri = URI.parse(endpoint)
        
        opts = {
          'method' => 'GET',
          'uri' => "#{uri.path}?database=#{database}&hash=#{hash_value}",
          'rhost' => uri.host,
          'rport' => uri.port || (uri.scheme == 'https' ? 443 : 80),
          'ssl' => uri.scheme == 'https'
        }

        begin
          res = send_request_cgi(opts)
          next unless res && res.code == 200
          
          result = get_json_result(res)
          return result if result && !result.empty?
        rescue => e
          # Continue to next endpoint on error
          next
        end
      end
      
      ''
    end

    private

    def get_json_result(response)
      return '' if response.body.nil? || response.body.empty?
      
      begin
        data = JSON.parse(response.body)
        if data['status'] == true || data['status'] == 'true'
          return data['result'] || ''
        end
      rescue JSON::ParserError
        # Invalid JSON, return empty
      end
      
      ''
    end
  end

  class Driver
    def initialize
      @options = OptsConsole.parse(ARGV)
      @output_handle = nil
    end

    def run
      disclaimer = Disclaimer.new
      unless disclaimer.send(:has_waiver?)
        return unless disclaimer.ack
      end

      @output_handle = File.new(@options[:outfile], 'wb') if @options[:outfile]

      get_hash_results(@options[:input], @options[:databases]) do |result|
        print_result(result)
        save_result(result) if @output_handle
      end

      @output_handle.close if @output_handle
    end

    private

    def print_result(result)
      puts "Found: #{result[:hash]} = #{result[:cracked_hash]} (from #{result[:credit]})"
    end

    def save_result(result)
      @output_handle.write("#{result[:hash]} = #{result[:cracked_hash]}\n")
    end

    def get_hash_results(input_file, databases)
      search_engine = Md5Lookup.new
      
      extract_hashes(input_file) do |hash|
        databases.each do |db|
          cracked = search_engine.lookup(hash, db)
          if cracked && !cracked.empty?
            result = {
              hash: hash,
              cracked_hash: cracked,
              credit: db
            }
            yield result
            break
          end
        end
      end
    end

    def extract_hashes(input_file)
      File.open(input_file, 'rb') do |f|
        f.each_line do |line|
          hash = line.strip
          next if hash.empty?
          
          if is_md5_format?(hash)
            yield hash
          end
        end
      end
    end

    def is_md5_format?(value)
      return false if value.nil? || value.empty?
      value.length == 32 && value.match?(/\A[a-fA-F0-9]+\z/)
    end
  end

  class OptsConsole
    def self.parse(argv)
      options = {}
      
      parser = OptionParser.new do |opts|
        opts.banner = "Usage: #{$0} [options]"
        
        opts.on('-i', '--input FILE', 'Input file containing MD5 hashes') do |file|
          raise OptionParser::MissingArgument, 'Input file is required' unless file
          raise OptionParser::InvalidArgument, 'Input file does not exist' unless File.exist?(file)
          options[:input] = file
        end
        
        opts.on('-d', '--databases DATABASES', 'Comma-separated database names') do |dbs|
          options[:databases] = extract_db_names(dbs)
        end
        
        opts.on('-o', '--outfile FILE', 'Output file') do |file|
          options[:outfile] = file
        end
        
        opts.on('-h', '--help', 'Show this help') do
          puts opts
          exit
        end
      end
      
      parser.parse!(argv)
      
      raise OptionParser::MissingArgument, 'Input file is required' unless options[:input]
      options[:databases] ||= get_database_names
      
      options
    end

    def self.extract_db_names(db_list)
      return get_database_names if db_list.downcase.include?('all')
      
      names = db_list.split(',').map(&:strip)
      valid_names = []
      
      names.each do |name|
        symbol = name.downcase
        if Md5Lookup::DATABASES.key?(symbol) && Md5Lookup::DATABASES[symbol]
          valid_names << Md5Lookup::DATABASES[symbol]
        end
      end
      
      valid_names.empty? ? get_database_names : valid_names
    end

    def self.get_database_symbols
      Md5Lookup::DATABASES.keys.reject { |k| Md5Lookup::DATABASES[k].nil? }
    end

    def self.get_database_names
      Md5Lookup::DATABASES.values.compact
    end
  end
end

# If this file is executed directly, run the driver
if __FILE__ == $0
  begin
    driver = Md5LookupUtility::Driver.new
    driver.run
  rescue => e
    $stderr.puts "Error: #{e.message}"
    exit 1
  end
end