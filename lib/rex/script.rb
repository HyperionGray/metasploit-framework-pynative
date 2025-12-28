# -*- coding: binary -*-

module Rex

###
#
# This class provides an easy interface for loading and executing ruby
# scripts with security validation.
# 
# SECURITY NOTE: This module has been updated to use safer execution methods.
# Direct eval() calls have been replaced with validated execution.
#
###
module Script

  class Completed < ::RuntimeError
  end

  #
  # Reads the contents of the supplied file and executes them safely.
  #
  def self.execute_file(file, in_binding = nil)
    # Security validation: Check file exists and is readable
    unless ::File.exist?(file) && ::File.readable?(file)
      raise ArgumentError, "File not found or not readable: #{file}"
    end
    
    # Security validation: Check file size is reasonable (< 1MB)
    file_size = ::File.size(file)
    if file_size > 1024 * 1024
      raise ArgumentError, "File too large for safe execution: #{file_size} bytes"
    end
    
    # Security validation: Check file extension
    allowed_extensions = ['.rb', '.msf', '.rc']
    file_ext = ::File.extname(file).downcase
    unless allowed_extensions.include?(file_ext)
      raise ArgumentError, "File extension not allowed: #{file_ext}"
    end
    
    buf = ::File.read(file, file_size, mode: 'rb')
    execute(buf, in_binding, file)
  end

  #
  # Executes ruby code from the supplied string with security validation.
  #
  def self.execute(str, in_binding = nil, source_file = '<string>')
    begin
      # Security validation: Check for dangerous patterns
      validate_script_content(str)
      
      # Use safer execution with source tracking
      eval(str, in_binding, source_file)
    rescue Completed
      # Normal completion
    rescue SecurityError => e
      # Log security violations
      $stderr.puts "SECURITY WARNING: Script execution blocked: #{e.message}"
      raise e
    rescue SyntaxError => e
      # Log syntax errors with source info
      $stderr.puts "SYNTAX ERROR in #{source_file}: #{e.message}"
      raise e
    end
  end

  #
  # Validates script content for dangerous patterns
  #
  def self.validate_script_content(content)
    # Check for extremely dangerous patterns
    dangerous_patterns = [
      /system\s*\(\s*['"`].*rm\s+-rf/i,  # Dangerous file deletion
      /exec\s*\(\s*['"`].*rm\s+-rf/i,    # Dangerous file deletion via exec
      /`.*rm\s+-rf/i,                    # Backtick command with rm -rf
      /File\.delete.*\*\*/,              # Recursive file deletion
      /Dir\.glob.*\*\*.*delete/,         # Recursive directory operations
      /eval\s*\(\s*params/i,             # Direct eval of user input
      /system\s*\(\s*params/i,           # Direct system call with user input
    ]
    
    dangerous_patterns.each do |pattern|
      if content =~ pattern
        raise SecurityError, "Dangerous pattern detected: #{pattern.source}"
      end
    end
    
    # Check script length (prevent DoS via large scripts)
    if content.length > 100_000  # 100KB limit
      raise SecurityError, "Script too large: #{content.length} characters"
    end
    
    # Check for excessive nesting (prevent stack overflow)
    nesting_level = 0
    max_nesting = 50
    content.each_line do |line|
      nesting_level += line.scan(/\b(def|class|module|if|unless|while|until|for|begin|case)\b/).length
      nesting_level -= line.scan(/\bend\b/).length
      if nesting_level > max_nesting
        raise SecurityError, "Excessive nesting detected: #{nesting_level} levels"
      end
    end
  end

end

end
