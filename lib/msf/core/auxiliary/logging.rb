# -*- coding: binary -*-
require 'securerandom'
require 'json'

module Msf::Auxiliary::Logging
  #
  # Enhanced logging methods specifically designed for auxiliary modules
  # Provides structured, contextual logging with automatic metadata inclusion
  #

  # Initialize logging context when module is loaded
  def initialize_logging_context
    @logging_context = {
      module_name: self.fullname,
      start_time: Time.now,
      operation_id: SecureRandom.hex(8)
    }
    @operation_stats = {
      operations_count: 0,
      success_count: 0,
      failure_count: 0,
      warning_count: 0
    }
    @progress_tracker = nil
  rescue => e
    # Don't let logging initialization break the module
    @logging_context = {}
    @operation_stats = {}
    @progress_tracker = nil
  end

  #
  # Enhanced status logging with automatic context
  # @param msg [String] The message to log
  # @param context [Hash] Additional context information
  # @param target [String] Target identifier (host:port, URL, etc.)
  #
  def log_status(msg, context: {}, target: nil)
    ensure_logging_initialized
    formatted_msg = build_contextual_message(msg, :status, context, target)
    print_status(formatted_msg)
    log_to_framework(:info, msg, context.merge(target: target))
    @operation_stats[:operations_count] += 1 if @operation_stats
  rescue => e
    # Fallback to basic logging if enhanced logging fails
    print_status(msg)
  end

  #
  # Enhanced success logging with automatic context and statistics
  # @param msg [String] The message to log
  # @param context [Hash] Additional context information
  # @param target [String] Target identifier
  # @param data [Hash] Structured data to store in database
  #
  def log_success(msg, context: {}, target: nil, data: {})
    ensure_logging_initialized
    formatted_msg = build_contextual_message(msg, :success, context, target)
    print_good(formatted_msg)
    log_to_framework(:info, msg, context.merge(target: target, result: 'success'))
    
    # Store structured data if provided
    if data.any? && respond_to?(:store_loot)
      store_structured_result(:success, msg, target, data)
    end
    
    @operation_stats[:success_count] += 1 if @operation_stats
    @operation_stats[:operations_count] += 1 if @operation_stats
  rescue => e
    # Fallback to basic logging if enhanced logging fails
    print_good(msg)
  end

  #
  # Enhanced error logging with automatic context and error tracking
  # @param msg [String] The message to log
  # @param context [Hash] Additional context information
  # @param target [String] Target identifier
  # @param error [Exception] Exception object if available
  #
  def log_error(msg, context: {}, target: nil, error: nil)
    ensure_logging_initialized
    formatted_msg = build_contextual_message(msg, :error, context, target)
    print_error(formatted_msg)
    
    error_context = context.merge(target: target, result: 'error')
    if error
      error_context.merge!(
        error_class: error.class.name,
        error_message: error.message,
        backtrace: error.backtrace&.first(5)
      )
    end
    
    log_to_framework(:error, msg, error_context)
    @operation_stats[:failure_count] += 1 if @operation_stats
    @operation_stats[:operations_count] += 1 if @operation_stats
  rescue => e
    # Fallback to basic logging if enhanced logging fails
    print_error(msg)
  end

  #
  # Enhanced warning logging with automatic context
  # @param msg [String] The message to log
  # @param context [Hash] Additional context information
  # @param target [String] Target identifier
  #
  def log_warning(msg, context: {}, target: nil)
    ensure_logging_initialized
    formatted_msg = build_contextual_message(msg, :warning, context, target)
    print_warning(formatted_msg)
    log_to_framework(:warn, msg, context.merge(target: target, result: 'warning'))
    @operation_stats[:warning_count] += 1 if @operation_stats
    @operation_stats[:operations_count] += 1 if @operation_stats
  rescue => e
    # Fallback to basic logging if enhanced logging fails
    print_warning(msg)
  end

  #
  # Verbose versions of enhanced logging methods
  #
  def vlog_status(msg, context: {}, target: nil)
    return unless verbose_logging_enabled?
    log_status(msg, context: context, target: target)
  end

  def vlog_success(msg, context: {}, target: nil, data: {})
    return unless verbose_logging_enabled?
    log_success(msg, context: context, target: target, data: data)
  end

  def vlog_error(msg, context: {}, target: nil, error: nil)
    return unless verbose_logging_enabled?
    log_error(msg, context: context, target: target, error: error)
  end

  def vlog_warning(msg, context: {}, target: nil)
    return unless verbose_logging_enabled?
    log_warning(msg, context: context, target: target)
  end

  #
  # Progress tracking for long-running operations
  # @param total [Integer] Total number of operations
  # @param description [String] Description of the operation
  #
  def start_progress_tracking(total, description = "Processing")
    @progress_tracker = {
      total: total,
      current: 0,
      description: description,
      start_time: Time.now,
      last_update: Time.now
    }
    log_status("Starting #{description} (#{total} items)")
  end

  #
  # Update progress and optionally log progress messages
  # @param increment [Integer] Number to increment progress by (default: 1)
  # @param msg [String] Optional message to log with progress
  #
  def update_progress(increment = 1, msg = nil)
    return unless @progress_tracker

    @progress_tracker[:current] += increment
    current = @progress_tracker[:current]
    total = @progress_tracker[:total]
    
    # Calculate progress percentage and ETA
    percentage = (current.to_f / total * 100).round(1)
    elapsed = Time.now - @progress_tracker[:start_time]
    eta = current > 0 ? (elapsed * (total - current) / current) : 0
    
    # Log progress every 10% or every 30 seconds, whichever comes first
    time_since_update = Time.now - @progress_tracker[:last_update]
    should_update = (current % (total / 10).ceil == 0) || (time_since_update > 30)
    
    if should_update || current == total
      progress_msg = "#{@progress_tracker[:description]}: #{current}/#{total} (#{percentage}%)"
      progress_msg += ", ETA: #{format_duration(eta)}" if eta > 0 && current < total
      progress_msg += " - #{msg}" if msg
      
      if current == total
        elapsed_str = format_duration(elapsed)
        log_success("#{@progress_tracker[:description]} completed in #{elapsed_str}")
      else
        log_status(progress_msg)
      end
      
      @progress_tracker[:last_update] = Time.now
    end
  end

  #
  # Finish progress tracking and log summary
  #
  def finish_progress_tracking
    return unless @progress_tracker
    
    if @progress_tracker[:current] < @progress_tracker[:total]
      update_progress(0, "Finished early")
    end
    
    @progress_tracker = nil
  end

  #
  # Log operation performance metrics
  # @param operation [String] Name of the operation
  # @param duration [Float] Duration in seconds
  # @param context [Hash] Additional context
  #
  def log_performance(operation, duration, context: {})
    return unless performance_logging_enabled?
    
    perf_msg = "Performance: #{operation} completed in #{format_duration(duration)}"
    perf_context = context.merge(
      operation: operation,
      duration_seconds: duration,
      performance_metric: true
    )
    
    vlog_status(perf_msg, context: perf_context)
  end

  #
  # Execute a block and automatically log performance
  # @param operation [String] Name of the operation
  # @param context [Hash] Additional context
  # @yield Block to execute and time
  # @return Result of the block
  #
  def with_performance_logging(operation, context: {})
    start_time = Time.now
    result = yield
    duration = Time.now - start_time
    log_performance(operation, duration, context: context)
    result
  rescue => e
    duration = Time.now - start_time
    log_error("#{operation} failed after #{format_duration(duration)}", 
              context: context, error: e)
    raise
  end

  #
  # Log operation statistics summary
  #
  def log_operation_summary
    return unless @operation_stats && @operation_stats[:operations_count] > 0
    
    total_duration = @logging_context && @logging_context[:start_time] ? 
                     Time.now - @logging_context[:start_time] : 0
    summary = [
      "Operations: #{@operation_stats[:operations_count]}",
      "Successes: #{@operation_stats[:success_count]}",
      "Failures: #{@operation_stats[:failure_count]}",
      "Warnings: #{@operation_stats[:warning_count]}",
      "Duration: #{format_duration(total_duration)}"
    ].join(", ")
    
    log_status("Summary - #{summary}")
  rescue => e
    # Don't let summary logging break the module
  end

  private

  #
  # Ensure logging context is initialized
  #
  def ensure_logging_initialized
    return if @logging_context && @operation_stats
    initialize_logging_context
  end

  #
  # Build a contextual message with automatic metadata
  #
  def build_contextual_message(msg, level, context, target)
    parts = []
    
    # Add target information if provided
    if target
      parts << "[#{target}]"
    end
    
    # Add timing information if enabled
    if timing_enabled? && @logging_context && @logging_context[:start_time]
      elapsed = Time.now - @logging_context[:start_time]
      parts << "[#{format_duration(elapsed)}]"
    end
    
    # Add context information if provided and verbose
    if context.any? && verbose_logging_enabled?
      context_str = context.map { |k, v| "#{k}=#{v}" }.join(" ")
      parts << "[#{context_str}]"
    end
    
    # Combine parts with the message
    prefix = parts.empty? ? "" : "#{parts.join(" ")} "
    "#{prefix}#{msg}"
  rescue => e
    # If contextual message building fails, just return the original message
    msg
  end

  #
  # Log to the framework logging system
  #
  def log_to_framework(level, msg, context)
    return unless framework_logging_enabled?
    
    log_context = (@logging_context || {}).merge(context || {})
    source = "aux:#{self.refname}" rescue "aux:unknown"
    
    case level
    when :debug
      dlog(msg, source, 2) if respond_to?(:dlog)
    when :info
      ilog("#{msg} #{log_context}", source, 1) if respond_to?(:ilog)
    when :warn
      wlog("#{msg} #{log_context}", source, 1) if respond_to?(:wlog)
    when :error
      elog("#{msg} #{log_context}", source, 0) if respond_to?(:elog)
    end
  rescue => e
    # Don't let framework logging failures break the module
  end

  #
  # Store structured result data
  #
  def store_structured_result(result_type, message, target, data)
    return unless respond_to?(:store_loot)
    
    loot_data = {
      result_type: result_type,
      message: message,
      target: target,
      timestamp: Time.now.iso8601,
      module_name: self.fullname,
      operation_id: @logging_context[:operation_id],
      data: data
    }
    
    store_loot(
      "auxiliary.result",
      "application/json",
      target || "unknown",
      loot_data.to_json,
      "#{self.refname}_result.json",
      message
    )
  rescue => e
    # Don't let loot storage failures break the module
    vlog_warning("Failed to store structured result: #{e.message}")
  end

  #
  # Format duration in human-readable format
  #
  def format_duration(seconds)
    return "0s" if seconds < 1
    
    if seconds < 60
      "#{seconds.round(1)}s"
    elsif seconds < 3600
      minutes = (seconds / 60).to_i
      secs = (seconds % 60).to_i
      "#{minutes}m#{secs}s"
    else
      hours = (seconds / 3600).to_i
      minutes = ((seconds % 3600) / 60).to_i
      "#{hours}h#{minutes}m"
    end
  end

  #
  # Check if verbose logging is enabled
  #
  def verbose_logging_enabled?
    (datastore && datastore['VERBOSE']) || (framework && framework.datastore && framework.datastore['VERBOSE'])
  rescue => e
    false
  end

  #
  # Check if timing information should be included
  #
  def timing_enabled?
    (datastore && datastore['AUX_TIMING']) || (framework && framework.datastore && framework.datastore['AUX_TIMING'])
  rescue => e
    false
  end

  #
  # Check if performance logging is enabled
  #
  def performance_logging_enabled?
    (datastore && datastore['AUX_PERFORMANCE']) || (framework && framework.datastore && framework.datastore['AUX_PERFORMANCE'])
  rescue => e
    false
  end

  #
  # Check if framework logging is enabled
  #
  def framework_logging_enabled?
    (datastore && datastore['AUX_FRAMEWORK_LOG']) || (framework && framework.datastore && framework.datastore['AUX_FRAMEWORK_LOG'])
  rescue => e
    false
  end

  #
  # Override initialize to set up logging context
  #
  def self.included(base)
    base.class_eval do
      alias_method :original_initialize, :initialize
      
      def initialize(info = {})
        original_initialize(info)
        
        begin
          initialize_logging_context
          
          # Register new datastore options if OptBool is available
          if defined?(Msf::OptBool)
            register_advanced_options([
              Msf::OptBool.new('AUX_TIMING', [false, 'Include timing information in auxiliary log messages', false]),
              Msf::OptBool.new('AUX_PERFORMANCE', [false, 'Enable performance logging for auxiliary operations', false]),
              Msf::OptBool.new('AUX_FRAMEWORK_LOG', [false, 'Enable framework-level logging for auxiliary operations', false])
            ])
          end
        rescue => e
          # Don't let logging initialization break module loading
        end
      end
    end
  rescue => e
    # Don't let the include process break if something goes wrong
  end
end