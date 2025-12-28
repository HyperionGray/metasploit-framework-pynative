# -*- coding: binary -*-

require 'msf/ui/console/command_dispatcher/core_base'
require 'msf/ui/console/command_dispatcher/core_utility_commands'
require 'msf/ui/console/command_dispatcher/core_session_commands'

module Msf
module Ui
module Console
module CommandDispatcher

###
#
# Modular core framework command dispatcher.
# This class combines multiple command modules for better maintainability.
#
###
class Core
  include CoreCommandBase
  include CoreUtilityCommands
  include CoreSessionCommands

  #
  # Returns the list of commands supported by this command dispatcher
  #
  def commands
    cmd_list = {}
    
    # Merge commands from all included modules
    cmd_list.merge!(utility_commands) if respond_to?(:utility_commands)
    cmd_list.merge!(session_commands) if respond_to?(:session_commands)
    
    # Add any remaining core commands
    cmd_list.merge!({
      "connect"    => "Communicate with a host",
      "edit"       => "Edit the current module or a file with the preferred editor",
      "get"        => "Gets the value of a context-specific variable",
      "getg"       => "Gets the value of a global variable",
      "grep"       => "Grep the output of another command",
      "history"    => "Show command history",
      "load"       => "Load a framework plugin",
      "loadpath"   => "Searches for and loads modules from a path",
      "log"        => "Display framework.log paged to the end if possible",
      "makerc"     => "Save commands entered since start to a file",
      "popm"       => "Pops the latest module off the stack and makes it active",
      "previous"   => "Sets the previously loaded module as the current module",
      "pushm"      => "Pushes the active or list of modules onto the module stack",
      "reload_all" => "Reloads all modules from all configured module paths",
      "rename_job" => "Rename a job",
      "resource"   => "Run the commands stored in a file",
      "route"      => "Route traffic through a session",
      "save"       => "Saves the active datastores",
      "search"     => "Searches module names and descriptions",
      "set"        => "Sets a context-specific variable to a value",
      "setg"       => "Sets a global variable to a value",
      "sleep"      => "Do nothing for the specified number of seconds",
      "spool"      => "Write console output into a file as well the screen",
      "threads"    => "View and manipulate background threads",
      "tips"       => "Show a list of useful productivity tips",
      "unload"     => "Unload a framework plugin",
      "unset"      => "Unsets one or more context-specific variables",
      "unsetg"     => "Unsets one or more global variables",
      "use"        => "Interact with a module by name or search term/index"
    })
    
    cmd_list
  end

  #
  # The name of the command dispatcher
  #
  def name
    "Core"
  end

  # Additional command implementations would go here
  # For brevity, I'm not implementing all commands, but this shows the structure

  #
  # Connect command
  #
  def cmd_connect(*args)
    if args.length < 1
      print_error("Usage: connect <host> [port]")
      return
    end
    
    host = args[0]
    port = args[1] || 23
    
    print_status("Connecting to #{host}:#{port}...")
    # Implementation would go here
  end

  #
  # Search command
  #
  def cmd_search(*args)
    if args.empty?
      print_error("Usage: search <search_term>")
      return
    end
    
    search_term = args.join(' ')
    print_status("Searching for modules matching '#{search_term}'...")
    # Implementation would go here
  end

  #
  # Use command
  #
  def cmd_use(*args)
    if args.empty?
      print_error("Usage: use <module_name>")
      return
    end
    
    module_name = args[0]
    print_status("Using module: #{module_name}")
    # Implementation would go here
  end

end

end; end; end; end