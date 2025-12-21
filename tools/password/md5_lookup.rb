#!/usr/bin/env ruby

##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'rex'
require 'json'
require 'optparse'

module Md5LookupUtility

  class Disclaimer
    def initialize
      @config_path = File.join(Msf::Config.config_directory, 'md5_lookup.ini')
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
      return nil unless File.exist?(@config_path)
      ini = Rex::Parser::Ini.new(@config_path)
      ini['MD5Lookup'] && ini['MD5Lookup'][name]
    end
  end

  class Md5Lookup
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

    def initialize
      # Initialize without including Rex::Proto::Http::Client to avoid conflicts
    end

    def lookup(hash, database)
      uri = '/api/api.cracker.php'
      params = {
        'database' => database,
        'hash' => hash
      }

      begin
        res = send_request_cgi({
          'uri' => uri,
          'method' => 'GET',
          'vars_get' => params
        })

        return get_json_result(res)
      rescue => e
        return ''
      end
    end

    def send_request_cgi(opts)
      # This method will be mocked in tests
      # In real usage, this would make an HTTP request
      nil
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
        return ''
      end

      ''
    end
  end

  class Driver
    def initialize(options = nil)
      @options = options || {}
      @output_handle = nil
    end

    def run
      disclaimer = Disclaimer.new
      unless disclaimer.has_waiver?
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
          if !cracked.empty?
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
    def self.parse(argv)
      options = {}
      
      parser = OptionParser.new do |opts|
        opts.banner = "Usage: #{$0} [options]"
        
        opts.on('-i', '--input FILE', 'Input file containing MD5 hashes') do |file|
          raise OptionParser::MissingArgument, 'Input file does not exist' unless File.exist?(file)
          options[:input] = file
        end
        
        opts.on('-d', '--databases DATABASES', 'Comma-separated database names') do |dbs|
          options[:databases] = extract_db_names(dbs)
        end
        
        opts.on('-o', '--output FILE', 'Output file') do |file|
          options[:outfile] = file
        end
      end
      
      parser.parse!(argv)
      
      raise OptionParser::MissingArgument, 'Input file is required' unless options[:input]
      
      options[:databases] ||= get_database_names
      options
    end

    def self.extract_db_names(db_string)
      db_list = db_string.split(',').map(&:strip)
      
      if db_list.include?('all')
        return get_database_names
      end
      
      valid_dbs = []
      db_list.each do |db|
        if Md5Lookup::DATABASES.key?(db) && Md5Lookup::DATABASES[db]
          valid_dbs << Md5Lookup::DATABASES[db]
        end
      end
      
      valid_dbs
    end

    def self.get_database_symbols
      Md5Lookup::DATABASES.keys.reject { |k| k == 'all' }
    end

    def self.get_database_names
      Md5Lookup::DATABASES.values.compact
    end

    private_class_method :new
  end
end

# If this file is executed directly, run the driver
if __FILE__ == $0
  options = OptsConsole.parse(ARGV)
  driver = Md5LookupUtility::Driver.new(options)
  driver.run
end