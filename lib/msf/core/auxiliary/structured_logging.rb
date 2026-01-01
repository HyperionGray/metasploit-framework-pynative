# -*- coding: binary -*-

require 'json'
require 'csv'
require 'fileutils'

module Msf

###
#
# This module provides structured logging capabilities for auxiliary modules.
# It addresses issue #17852 by providing production-ready logging methods that
# complement the existing print_* methods with structured, persistent logging.
#
###

module Auxiliary::StructuredLogging

  # Log levels for auxiliary operations
  LOG_LEVEL_INFO    = 'info'
  LOG_LEVEL_SUCCESS = 'success'
  LOG_LEVEL_WARNING = 'warning'
  LOG_LEVEL_ERROR   = 'error'
  LOG_LEVEL_DEBUG   = 'debug'

  # Output formats
  FORMAT_JSON = 'json'
  FORMAT_CSV  = 'csv'
  FORMAT_TEXT = 'text'

  # Default configuration
  DEFAULT_LOG_DIR = 'auxiliary_logs'
  DEFAULT_FORMAT  = FORMAT_JSON
  DEFAULT_ENABLED = true

  #
  # Initialize structured logging for the auxiliary module
  #
  def initialize_structured_logging
    @structured_log_enabled = datastore['AUX_LOG_ENABLED'] != false
    @structured_log_format  = datastore['AUX_LOG_FORMAT'] || DEFAULT_FORMAT
    @structured_log_dir     = datastore['AUX_LOG_DIR'] || File.join(Msf::Config.log_directory, DEFAULT_LOG_DIR)
    @structured_log_file    = nil
    @structured_log_mutex   = Mutex.new
    @structured_log_session_id = Rex::Text.rand_text_alphanumeric(8)
    @structured_log_start_time = Time.now
    @structured_log_entries = []
    
    # Create log directory if it doesn't exist
    if @structured_log_enabled
      begin
        FileUtils.mkdir_p(@structured_log_dir)
      rescue => e
        print_warning("Failed to create auxiliary log directory: #{e.message}")
        @structured_log_enabled = false
      end
    end
  end

  #
  # Get the log file path for this auxiliary module instance
  #
  def structured_log_file_path
    return nil unless @structured_log_enabled
    
    if @structured_log_file.nil?
      timestamp = @structured_log_start_time.strftime('%Y%m%d_%H%M%S')
      module_name = self.fullname.gsub('/', '_').gsub(' ', '_')
      filename = "#{module_name}_#{timestamp}_#{@structured_log_session_id}"
      
      case @structured_log_format.downcase
      when FORMAT_JSON
        filename += '.json'
      when FORMAT_CSV
        filename += '.csv'
      when FORMAT_TEXT
        filename += '.log'
      else
        filename += '.log'
      end
      
      @structured_log_file = File.join(@structured_log_dir, filename)
    end
    
    @structured_log_file
  end

  #
  # Log a structured result from auxiliary module execution
  #
  # @param opts [Hash] the logging options
  # @option opts [String] :level the log level (info, success, warning, error, debug)
  # @option opts [String] :message the human-readable message
  # @option opts [Hash] :data additional structured data to log
  # @option opts [String] :host the target host (optional)
  # @option opts [Integer] :port the target port (optional)
  # @option opts [String] :service the service name (optional)
  # @option opts [String] :type the type of result (scan, exploit, gather, etc.)
  # @option opts [Hash] :metadata additional metadata
  #
  def log_auxiliary_result(opts = {})
    return unless @structured_log_enabled
    
    # Validate required parameters
    opts[:level] ||= LOG_LEVEL_INFO
    opts[:message] ||= 'Auxiliary module result'
    opts[:timestamp] = Time.now.utc.iso8601
    opts[:session_id] = @structured_log_session_id
    opts[:module] = self.fullname
    
    # Add context information
    opts[:target] = {
      host: opts[:host] || datastore['RHOSTS'] || datastore['RHOST'],
      port: opts[:port] || datastore['RPORT'],
      service: opts[:service]
    }.compact
    
    # Add module metadata
    opts[:module_info] = {
      name: self.name,
      description: self.description,
      author: self.author,
      references: self.references
    }.compact
    
    # Store the entry
    @structured_log_mutex.synchronize do
      @structured_log_entries << opts.dup
      write_log_entry(opts)
    end
    
    # Also output to console if verbose
    if datastore['VERBOSE'] || datastore['AUX_LOG_VERBOSE']
      case opts[:level]
      when LOG_LEVEL_SUCCESS
        vprint_good("#{opts[:message]} (logged)")
      when LOG_LEVEL_ERROR
        vprint_error("#{opts[:message]} (logged)")
      when LOG_LEVEL_WARNING
        vprint_warning("#{opts[:message]} (logged)")
      else
        vprint_status("#{opts[:message]} (logged)")
      end
    end
    
    opts
  end

  #
  # Log progress information for long-running auxiliary operations
  #
  # @param opts [Hash] the progress options
  # @option opts [Integer] :current current progress value
  # @option opts [Integer] :total total expected value
  # @option opts [String] :message progress message
  # @option opts [Hash] :data additional progress data
  #
  def log_auxiliary_progress(opts = {})
    return unless @structured_log_enabled
    
    current = opts[:current] || 0
    total = opts[:total] || 100
    percentage = total > 0 ? (current.to_f / total * 100).round(2) : 0
    
    progress_opts = {
      level: LOG_LEVEL_INFO,
      type: 'progress',
      message: opts[:message] || "Progress: #{current}/#{total} (#{percentage}%)",
      data: {
        current: current,
        total: total,
        percentage: percentage
      }.merge(opts[:data] || {})
    }
    
    log_auxiliary_result(progress_opts)
  end

  #
  # Log performance metrics for auxiliary operations
  #
  # @param opts [Hash] the metrics options
  # @option opts [String] :operation the operation name
  # @option opts [Float] :duration duration in seconds
  # @option opts [Hash] :metrics additional metrics data
  #
  def log_auxiliary_metrics(opts = {})
    return unless @structured_log_enabled
    
    metrics_opts = {
      level: LOG_LEVEL_DEBUG,
      type: 'metrics',
      message: opts[:message] || "Performance metrics for #{opts[:operation]}",
      data: {
        operation: opts[:operation],
        duration: opts[:duration],
        timestamp: Time.now.utc.iso8601
      }.merge(opts[:metrics] || {})
    }
    
    log_auxiliary_result(metrics_opts)
  end

  #
  # Log a finding or discovery from auxiliary module
  #
  # @param opts [Hash] the finding options
  # @option opts [String] :type the type of finding
  # @option opts [String] :severity the severity level
  # @option opts [Hash] :details the finding details
  #
  def log_auxiliary_finding(opts = {})
    return unless @structured_log_enabled
    
    finding_opts = {
      level: opts[:severity] == 'high' ? LOG_LEVEL_ERROR : LOG_LEVEL_SUCCESS,
      type: 'finding',
      message: opts[:message] || "Finding: #{opts[:type]}",
      data: {
        finding_type: opts[:type],
        severity: opts[:severity] || 'medium',
        details: opts[:details] || {}
      },
      host: opts[:host],
      port: opts[:port],
      service: opts[:service]
    }
    
    log_auxiliary_result(finding_opts)
  end

  #
  # Write a log entry to the appropriate output format
  #
  private def write_log_entry(entry)
    return unless @structured_log_enabled
    
    file_path = structured_log_file_path
    return unless file_path
    
    begin
      case @structured_log_format.downcase
      when FORMAT_JSON
        write_json_entry(file_path, entry)
      when FORMAT_CSV
        write_csv_entry(file_path, entry)
      when FORMAT_TEXT
        write_text_entry(file_path, entry)
      end
    rescue => e
      # Don't let logging errors break the module
      vprint_error("Failed to write auxiliary log entry: #{e.message}")
    end
  end

  #
  # Write entry in JSON format
  #
  private def write_json_entry(file_path, entry)
    File.open(file_path, 'a') do |f|
      f.puts(JSON.generate(entry))
    end
  end

  #
  # Write entry in CSV format
  #
  private def write_csv_entry(file_path, entry)
    # Flatten the entry for CSV
    flattened = flatten_hash(entry)
    
    # Check if file exists to determine if we need headers
    write_headers = !File.exist?(file_path)
    
    CSV.open(file_path, 'a') do |csv|
      if write_headers
        csv << flattened.keys
      end
      csv << flattened.values
    end
  end

  #
  # Write entry in text format
  #
  private def write_text_entry(file_path, entry)
    File.open(file_path, 'a') do |f|
      f.puts("[#{entry[:timestamp]}] [#{entry[:level].upcase}] #{entry[:message]}")
      if entry[:data] && !entry[:data].empty?
        f.puts("  Data: #{entry[:data].inspect}")
      end
      if entry[:target] && !entry[:target].empty?
        f.puts("  Target: #{entry[:target].inspect}")
      end
      f.puts("")
    end
  end

  #
  # Flatten a nested hash for CSV output
  #
  private def flatten_hash(hash, prefix = '')
    result = {}
    hash.each do |key, value|
      new_key = prefix.empty? ? key.to_s : "#{prefix}.#{key}"
      if value.is_a?(Hash)
        result.merge!(flatten_hash(value, new_key))
      elsif value.is_a?(Array)
        result[new_key] = value.join(';')
      else
        result[new_key] = value
      end
    end
    result
  end

  #
  # Get all logged entries for this session
  #
  def get_auxiliary_log_entries
    @structured_log_entries.dup
  end

  #
  # Export logged entries to a specific format
  #
  # @param format [String] the output format (json, csv, text)
  # @param file_path [String] the output file path
  #
  def export_auxiliary_logs(format = FORMAT_JSON, file_path = nil)
    return [] unless @structured_log_enabled
    
    entries = get_auxiliary_log_entries
    return entries if entries.empty?
    
    if file_path
      case format.downcase
      when FORMAT_JSON
        File.write(file_path, JSON.pretty_generate(entries))
      when FORMAT_CSV
        CSV.open(file_path, 'w') do |csv|
          if entries.first
            flattened_first = flatten_hash(entries.first)
            csv << flattened_first.keys
            entries.each do |entry|
              flattened = flatten_hash(entry)
              csv << flattened.values
            end
          end
        end
      when FORMAT_TEXT
        File.open(file_path, 'w') do |f|
          entries.each do |entry|
            f.puts("[#{entry[:timestamp]}] [#{entry[:level].upcase}] #{entry[:message]}")
            if entry[:data] && !entry[:data].empty?
              f.puts("  Data: #{entry[:data].inspect}")
            end
            f.puts("")
          end
        end
      end
      print_good("Auxiliary logs exported to: #{file_path}")
    end
    
    entries
  end

  #
  # Generate a summary of logged activities
  #
  def generate_auxiliary_log_summary
    return {} unless @structured_log_enabled
    
    entries = get_auxiliary_log_entries
    return {} if entries.empty?
    
    summary = {
      session_id: @structured_log_session_id,
      module: self.fullname,
      start_time: @structured_log_start_time.utc.iso8601,
      end_time: Time.now.utc.iso8601,
      duration: Time.now - @structured_log_start_time,
      total_entries: entries.length,
      entries_by_level: {},
      entries_by_type: {},
      targets: [],
      findings_count: 0
    }
    
    entries.each do |entry|
      # Count by level
      level = entry[:level] || LOG_LEVEL_INFO
      summary[:entries_by_level][level] = (summary[:entries_by_level][level] || 0) + 1
      
      # Count by type
      type = entry[:type] || 'general'
      summary[:entries_by_type][type] = (summary[:entries_by_type][type] || 0) + 1
      
      # Collect unique targets
      if entry[:target] && entry[:target][:host]
        target_key = "#{entry[:target][:host]}:#{entry[:target][:port]}"
        summary[:targets] << target_key unless summary[:targets].include?(target_key)
      end
      
      # Count findings
      summary[:findings_count] += 1 if entry[:type] == 'finding'
    end
    
    summary
  end

  #
  # Clean up old log files (called automatically)
  #
  def cleanup_old_auxiliary_logs(days_to_keep = 30)
    return unless @structured_log_enabled && File.directory?(@structured_log_dir)
    
    cutoff_time = Time.now - (days_to_keep * 24 * 60 * 60)
    
    Dir.glob(File.join(@structured_log_dir, '*')).each do |file_path|
      next unless File.file?(file_path)
      
      if File.mtime(file_path) < cutoff_time
        begin
          File.delete(file_path)
          vprint_status("Cleaned up old auxiliary log: #{File.basename(file_path)}")
        rescue => e
          vprint_warning("Failed to clean up log file #{file_path}: #{e.message}")
        end
      end
    end
  end

end

end