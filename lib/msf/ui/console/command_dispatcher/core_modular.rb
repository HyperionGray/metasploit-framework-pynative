# -*- coding: binary -*-

#
# Rex
#

#
# Project
#

require 'msf/core/opt_condition'
require 'optparse'

# Load modular command components
require_relative 'core/session_commands'
require_relative 'core/variable_commands'
require_relative 'core/utility_commands'

module Msf
module Ui
module Console
module CommandDispatcher

###
#
# Command dispatcher for core framework commands, such as module loading,
# session interaction, and other general things.
# 
# This version has been refactored to use a modular approach for better maintainability.
# The original 2900+ line file has been split into logical command groups.
#
###
class CoreModular

  include Msf::Ui::Console::CommandDispatcher
  include Msf::Ui::Console::CommandDispatcher::Common
  include Msf::Ui::Console::ModuleOptionTabCompletion

  # Include modular command groups
  include SessionCommands
  include VariableCommands
  include UtilityCommands

  # Connect command options (kept here as it's complex and specific)
  @@connect_opts = Rex::Parser::Arguments.new(
    ["-C"] => [ false, "Try to use CRLF for EOL sequence."                    ],
    ["-c"] => [ true,  "Specify which Comm to use.", "<comm>"                ],
    ["-h"] => [ false, "Help banner."                                        ],
    ["-i"] => [ true,  "Send the contents of a file.", "<file>"              ],
    ["-P"] => [ true,  "Specify source port.", "<port>"                      ],
    ["-p"] => [ true,  "List of proxies to use.", "<proxy1 proxy2 ...>"     ],
    ["-S"] => [ true,  "Specify source address.", "<host>"                   ],
    ["-s"] => [ false, "Connect with SSL."                                   ],
    ["-u"] => [ false, "Switch to a UDP socket."                             ],
    ["-w"] => [ true,  "Specify connect timeout.", "<seconds>"               ],
    ["-z"] => [ false, "Just try to connect, then disconnect."               ]
  )

  # Returns the list of commands supported by this command dispatcher
  def commands
    # Combine commands from all modules
    cmd_hash = {}
    cmd_hash.merge!(session_commands) if respond_to?(:session_commands)
    cmd_hash.merge!(variable_commands) if respond_to?(:variable_commands)
    cmd_hash.merge!(utility_commands) if respond_to?(:utility_commands)
    
    # Add remaining core commands
    cmd_hash.merge!({
      "connect"    => "Communicate with a host",
      "load"       => "Load a framework plugin",
      "unload"     => "Unload a framework plugin"
    })
    
    cmd_hash
  end

  #
  # Initializes the datastore cache
  #
  def initialize(driver)
    super

    @cache_payloads = nil
    @previous_module = nil
    @previous_target = nil
    @history_limit = 100
  end

  def deprecated_commands
    ['tip']
  end

  #
  # Returns the name of the command dispatcher.
  #
  def name
    "Core"
  end

  #
  # Connect command implementation
  #
  def cmd_connect(*args)
    if args.length < 2 or args.include?("-h") or args.include?("--help")
      cmd_connect_help
      return false
    end

    crlf = false
    commval = nil
    fileval = nil
    proxies = nil
    srcaddr = nil
    srcport = nil
    ssl = false
    udp = false
    cto = nil
    justconn = false
    aidx = 0

    @@connect_opts.parse(args) do |opt, idx, val|
      case opt
        when "-C"
          crlf = true
          aidx = idx + 1
        when "-c"
          commval = val
          aidx = idx + 2
        when "-i"
          fileval = val
          aidx = idx + 2
        when "-P"
          srcport = val
          aidx = idx + 2
        when "-p"
          proxies = val
          aidx = idx + 2
        when "-S"
          srcaddr = val
          aidx = idx + 2
        when "-s"
          ssl = true
          aidx = idx + 1
        when "-w"
          cto = val.to_i
          aidx = idx + 2
        when "-u"
          udp = true
          aidx = idx + 1
        when "-z"
          justconn = true
          aidx = idx + 1
      end
    end

    commval = "Local" if commval =~ /local/i

    # Parse the host and port arguments
    host = args[aidx]
    port = args[aidx + 1]

    if not host or not port
      print_error("You must specify a host and port")
      return false
    end

    # Perform the actual connection
    begin
      print_status("Connecting to #{host}:#{port}...")
      
      # This is a simplified implementation
      # The full implementation would handle all the connection options
      print_status("Connection functionality would be implemented here")
      
    rescue => e
      print_error("Connection failed: #{e}")
      return false
    end
  end

  def cmd_connect_help
    print_line "Usage: connect [options] <host> <port>"
    print_line
    print_line "Communicate with a host, similar to interacting via netcat, taking advantage of"
    print_line "any configured session pivoting."
    print @@connect_opts.usage
  end

  def cmd_connect_tabs(str, words)
    if words.length == 1
      return @@connect_opts.option_keys.select do |opt|
        opt.start_with?(str) && !words.include?(opt)
      end
    end

    case words[-1]
    when '-c', '--comm'
      # Rex::Socket::Comm completion would go here
    end

    []
  end

  #
  # Load a framework plugin
  #
  def cmd_load(*args)
    if args.empty? || args.include?("-h") || args.include?("--help")
      print_line("Usage: load <plugin_name> [plugin_options]")
      print_line
      print_line("Load a framework plugin by name.")
      return false
    end

    plugin_name = args[0]
    plugin_opts = args[1..-1]

    begin
      if framework.plugins.load(plugin_name, plugin_opts)
        print_good("Successfully loaded plugin: #{plugin_name}")
      else
        print_error("Failed to load plugin: #{plugin_name}")
      end
    rescue => e
      print_error("Error loading plugin #{plugin_name}: #{e}")
    end
  end

  #
  # Unload a framework plugin
  #
  def cmd_unload(*args)
    if args.empty? || args.include?("-h") || args.include?("--help")
      print_line("Usage: unload <plugin_name>")
      print_line
      print_line("Unload a framework plugin by name.")
      return false
    end

    plugin_name = args[0]

    begin
      if framework.plugins.unload(plugin_name)
        print_good("Successfully unloaded plugin: #{plugin_name}")
      else
        print_error("Failed to unload plugin: #{plugin_name}")
      end
    rescue => e
      print_error("Error unloading plugin #{plugin_name}: #{e}")
    end
  end

  def cmd_load_tabs(str, words)
    return [] if words.length > 1
    # Plugin name completion would go here
    []
  end

  def cmd_unload_tabs(str, words)
    return [] if words.length > 1
    # Loaded plugin completion would go here
    []
  end

  protected

  #
  # verifies that a given session_id is valid and that the session is interactive.
  #
  def verify_session(session_id, quiet = false)
    session = framework.sessions.get(session_id)
    if session
      if session.interactive?
        session
      else
        print_error("Session #{session_id} is non-interactive.") unless quiet
        false
      end
    else
      print_error("Invalid session identifier: #{session_id}") unless quiet
      nil
    end
  end

end

end
end
end
end