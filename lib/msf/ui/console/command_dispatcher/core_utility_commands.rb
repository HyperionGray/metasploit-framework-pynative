# -*- coding: binary -*-

require 'msf/ui/console/command_dispatcher/core_base'

module Msf
module Ui
module Console
module CommandDispatcher

#
# Core utility commands (help, banner, color, cd, etc.)
#
module CoreUtilityCommands
  include CoreCommandBase

  #
  # Returns utility command definitions
  #
  def utility_commands
    {
      "?"          => "Help menu",
      "banner"     => "Display an awesome metasploit banner",
      "cd"         => "Change the current working directory",
      "color"      => "Toggle color",
      "help"       => "Help menu",
      "history"    => "Show command history",
      "load"       => "Load a framework plugin",
      "quit"       => "Exit the console",
      "exit"       => "Exit the console",
      "version"    => "Show the framework and console library version numbers"
    }
  end

  #
  # Display help menu
  #
  def cmd_help(*args)
    if args.empty?
      print_line("Core Commands")
      print_line("=============")
      print_line()
      
      tbl = Table.new(
        Table::Style::Default,
        'Header'  => "Core Commands",
        'Prefix'  => "\n",
        'Postfix' => "\n",
        'Columns' => ['Command', 'Description']
      )

      utility_commands.each_pair do |name, desc|
        tbl << [name, desc]
      end

      print_line(tbl.to_s)
    else
      # Handle specific command help
      cmd = args[0]
      help_method = "cmd_#{cmd}_help"
      if respond_to?(help_method)
        send(help_method)
      else
        print_error("No help available for '#{cmd}'")
      end
    end
  end

  alias cmd_? cmd_help

  #
  # Display banner
  #
  def cmd_banner(*args)
    banner = framework.banner
    print_line(banner)
  end

  #
  # Color command help
  #
  def cmd_color_help
    print_line "Usage: color <'true'|'false'|'auto'>"
    print_line
    print_line "Enable or disable color output."
    print_line
  end

  #
  # Toggle color output
  #
  def cmd_color(*args)
    case args[0]
    when "auto"
      driver.output.auto_color
    when "true"
      driver.output.enable_color
    when "false"
      driver.output.disable_color
    else
      cmd_color_help
      return
    end
  end

  #
  # Tab completion for the color command
  #
  def cmd_color_tabs(str, words)
    return [] if words.length > 1
    %w[auto true false]
  end

  #
  # Change directory help
  #
  def cmd_cd_help
    print_line "Usage: cd <directory>"
    print_line
    print_line "Change the current working directory"
    print_line
  end

  #
  # Change the current working directory
  #
  def cmd_cd(*args)
    if args.length == 0
      print_error("No path specified")
      return
    end

    path = args[0]
    
    begin
      Dir.chdir(path)
      print_status("Changed directory to #{Dir.pwd}")
    rescue Errno::ENOENT
      print_error("Directory '#{path}' does not exist")
    rescue Errno::EACCES
      print_error("Permission denied accessing '#{path}'")
    rescue => e
      print_error("Error changing directory: #{e.message}")
    end
  end

  #
  # Version command
  #
  def cmd_version(*args)
    print_line("Framework: #{Msf::Framework::Version}")
    print_line("Console  : #{Msf::Framework::RepoRevision}")
  end

  #
  # Quit/Exit commands
  #
  def cmd_quit(*args)
    driver.stop
  end

  alias cmd_exit cmd_quit

end

end; end; end; end