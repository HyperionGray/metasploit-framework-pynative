#!/usr/bin/env ruby

##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

#
# Ruby wrapper for the Python md5_lookup.py tool
# This maintains backward compatibility while delegating to the Python implementation
#

require 'msfenv'
require 'rex'
require 'json'
require 'optparse'
require 'tempfile'

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
      return nil unless File.exist?(@config_path)
      ini = Rex::Parser::Ini.new(@config_path)
      ini['MD5Lookup'] && ini['MD5Lookup'][name]
    end
  end

  class Md5Lookup
    include Rex::Proto::Http::Client

    def initialize
      @python_script = File.join(File.dirname(__FILE__), 'md5_lookup.py')
    end

    def lookup(hash, database)
      # Try HTTP client approach first (for testing and compatibility)
      begin
        opts = {
          'uri' => '/api/api.cracker.php',
          'method' => 'GET',
          'vars_get' => {
            'database' => database,
            'hash' => hash
          }
        }
        
        response = send_request_cgi(opts)
        result = get_json_result(response)
        return result unless result.empty?
      rescue => e
        # If HTTP client fails, fall back to Python implementation
      end
      
      # Fallback to Python implementation
      lookup_via_python(hash, database)
    end

    private

    def lookup_via_python(hash, database)
      # Create temporary files for input and output
      input_file = Tempfile.new('md5_input')
      output_file = Tempfile.new('md5_output')
      
      begin
        # Write hash to input file
        input_file.write(hash)
        input_file.close

        # Call Python script
        cmd = "python3 #{@python_script} -i #{input_file.path} -d #{database} -o #{output_file.path} --assume-yes"
        system(cmd)

        # Read result from output file
        if File.exist?(output_file.path) && File.size(output_file.path) > 0
          result = File.read(output_file.path).strip
          if result.include?('=')
            return result.split('=', 2)[1].strip
          end
        end
        
        return ''
      ensure
        input_file.unlink if input_file
        output_file.unlink if output_file
      end
    end

    def get_json_result(response)
      return '' if response.body.nil? || response.body.empty?
      
      begin
        data = JSON.parse(response.body)
        if data['status']
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
      @options = {}
      @output_handle = nil
    end

    def run
      @options = OptsConsole.parse(ARGV)
      
      # Check disclaimer
      disclaimer = Disclaimer.new
      unless disclaimer.send(:has_waiver?)
        return unless disclaimer.ack
      end

      # Open output file
      if @options[:outfile]
        @output_handle = File.new(@options[:outfile], 'wb')
      end

      # Process hashes
      get_hash_results(@options[:input], @options[:databases]) do |result|
        puts "Found: #{result[:hash]} = #{result[:cracked_hash]} (from #{result[:credit]})"
        save_result(result) if @output_handle
      end

      @output_handle.close if @output_handle
    end

    private

    def save_result(result)
      @output_handle.write("#{result[:hash]} = #{result[:cracked_hash]}\n")
    end

    def get_hash_results(input_file, databases)
      search_engine = Md5Lookup.new
      
      extract_hashes(input_file) do |hash|
        databases.each do |db|
          cracked = search_engine.lookup(hash, db)
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
          if is_md5_format?(hash)
            yield hash
          end
        end
      end
    end

    def is_md5_format?(str)
      return false if str.nil? || str.empty?
      str.length == 32 && str.match(/^[a-fA-F0-9]+$/)
    end
  end

  class OptsConsole
    DATABASES = {
      'all' => ['authsecu', 'i337.net', 'md5.my-addr.com', 'md5.net', 'md5crack', 
                'md5cracker.org', 'md5decryption.com', 'md5online.net', 'md5pass', 
                'netmd5crack', 'tmto'],
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

    def self.parse(argv)
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
        
        opts.on('-h', '--help', 'Show this help') do
          puts opts
          exit
        end
      end
      
      parser.parse!(argv)
      
      # Validate required options
      raise OptionParser::MissingArgument, 'Input file is required' unless options[:input]
      
      # Set defaults
      options[:databases] ||= DATABASES['all']
      options[:outfile] ||= 'md5_results.txt'
      
      options
    end

    def self.extract_db_names(db_list)
      return DATABASES['all'] if db_list == 'all'
      
      names = []
      db_list.split(',').each do |db|
        db = db.strip
        if DATABASES.key?(db) && db != 'all'
          if DATABASES[db].is_a?(Array)
            names.concat(DATABASES[db])
          else
            names << DATABASES[db]
          end
        end
      end
      
      names.empty? ? DATABASES['all'] : names
    end

    def self.get_database_symbols
      DATABASES.keys.reject { |k| k == 'all' }
    end

    def self.get_database_names
      symbols = get_database_symbols
      names = []
      symbols.each do |symbol|
        if DATABASES[symbol].is_a?(Array)
          names.concat(DATABASES[symbol])
        else
          names << DATABASES[symbol]
        end
      end
      names
    end
  end
end

# If this script is run directly, execute the driver
if __FILE__ == $0
  driver = Md5LookupUtility::Driver.new
  driver.run
end