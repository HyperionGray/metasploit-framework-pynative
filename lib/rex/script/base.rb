# -*- coding: binary -*-
module Rex
module Script
class Base

  class OutputSink
    def print(msg); end
    def print_line(msg); end
    def print_status(msg); end
    def print_good(msg); end
    def print_error(msg); end
    alias_method :print_bad, :print_error
    def print_warning(msg); end
  end

  attr_accessor :client, :framework, :path, :error, :args
  attr_accessor :session, :sink, :workspace

  def initialize(client, path)
    self.client    = client
    self.framework = client.framework
    self.path      = path
    self.sink      = OutputSink.new

    if(client.framework.db and client.framework.db.active)
      self.workspace = client.framework.db.find_workspace( client.workspace.to_s ) || client.framework.db.workspace
    end

    # Convenience aliases
    self.session   = self.client
  end

  def output
    client.user_output || self.sink
  end

  def completed
    raise Rex::Script::Completed
  end

  def run(args=[])
    self.args = args = args.flatten
    begin
      # Security validation before execution
      validate_script_file(self.path)
      
      # Read script content
      script_content = ::File.read(self.path, ::File.size(self.path))
      
      # Validate script content for security issues
      Rex::Script.validate_script_content(script_content)
      
      # Execute with source file tracking for better error reporting
      eval(script_content, binding, self.path)
    rescue ::Interrupt
      # User interrupted execution
    rescue ::Rex::Script::Completed
      # Normal script completion
    rescue ::SecurityError => e
      # Security validation failed
      self.error = e
      output.print_error("SECURITY: Script execution blocked: #{e.message}")
      raise e
    rescue ::Exception => e
      # Other execution errors
      self.error = e
      output.print_error("Script execution failed: #{e.message}")
      raise e
    end
  end

  private

  #
  # Validates the script file before execution
  #
  def validate_script_file(file_path)
    # Check file exists and is readable
    unless ::File.exist?(file_path) && ::File.readable?(file_path)
      raise SecurityError, "Script file not found or not readable: #{file_path}"
    end
    
    # Check file size is reasonable (< 1MB)
    file_size = ::File.size(file_path)
    if file_size > 1024 * 1024
      raise SecurityError, "Script file too large for safe execution: #{file_size} bytes"
    end
    
    # Check file is within allowed directories
    allowed_script_dirs = [
      ::File.join(framework.root, 'scripts'),
      ::File.join(framework.root, 'modules'),
      ::File.join(framework.root, 'plugins'),
      '/tmp/msf_scripts'  # Temporary script directory
    ]
    
    file_realpath = ::File.realpath(file_path)
    unless allowed_script_dirs.any? { |dir| file_realpath.start_with?(::File.realpath(dir)) rescue false }
      raise SecurityError, "Script file not in allowed directory: #{file_realpath}"
    end
    
    # Check file extension
    allowed_extensions = ['.rb', '.msf', '.rc']
    file_ext = ::File.extname(file_path).downcase
    unless allowed_extensions.include?(file_ext)
      raise SecurityError, "Script file extension not allowed: #{file_ext}"
    end
  end

  def print(*args);         output.print(*args);          end
  def print_status(*args);  output.print_status(*args);   end
  def print_error(*args);   output.print_error(*args);    end
  def print_good(*args);    output.print_good(*args);     end
  def print_line(*args);    output.print_line(*args);     end

end
end
end

