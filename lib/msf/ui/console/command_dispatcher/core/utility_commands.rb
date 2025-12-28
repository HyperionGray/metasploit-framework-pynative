# -*- coding: binary -*-

module Msf
module Ui
module Console
module CommandDispatcher

###
#
# Utility commands for the core command dispatcher
#
###
module UtilityCommands

  def utility_commands
    {
      "?"          => "Help menu",
      "banner"     => "Display an awesome metasploit banner",
      "cd"         => "Change the current working directory",
      "connect"    => "Communicate with a host",
      "color"      => "Toggle color",
      "debug"      => "Display information useful for debugging",
      "exit"       => "Exit the console",
      "features"   => "Display the list of not yet released features that can be opted in to",
      "grep"       => "Grep the output of another command",
      "help"       => "Help menu",
      "history"    => "Show command history",
      "quit"       => "Exit the console",
      "repeat"     => "Repeat a list of commands",
      "route"      => "Route traffic through a session",
      "sleep"      => "Do nothing for the specified number of seconds",
      "tips"       => "Show a list of useful productivity tips",
      "threads"    => "View and manipulate background threads",
      "version"    => "Show the framework and console library version numbers",
      "spool"      => "Write console output into a file as well the screen"
    }
  end

  #
  # Display help
  #
  def cmd_help(*args)
    if args.empty?
      print(driver.help_to_s)
    else
      cmd = args.first
      if driver.commands.include?(cmd)
        help_method = "cmd_#{cmd}_help"
        if respond_to?(help_method)
          send(help_method)
        else
          print_error("No help available for #{cmd}")
        end
      else
        print_error("Unknown command: #{cmd}")
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
  # Change directory
  #
  def cmd_cd(*args)
    if args.empty?
      print_line("Usage: cd <directory>")
      return false
    end

    begin
      Dir.chdir(args[0])
      print_line("Changed directory to #{Dir.pwd}")
    rescue => e
      print_error("Failed to change directory: #{e}")
    end
  end

  #
  # Toggle color output
  #
  def cmd_color(*args)
    case args[0]
    when 'true', 'on', '1'
      driver.output.auto_color
    when 'false', 'off', '0'
      driver.output.disable_color
    when '%bld', '%red', '%grn', '%blu', '%yel', '%mag', '%cyn', '%whi', '%clr'
      print_line("#{args[0]}Color test")
    else
      driver.output.auto_color
    end
  end

  #
  # Exit the console
  #
  def cmd_exit(*args)
    driver.stop
  end

  alias cmd_quit cmd_exit

  #
  # Sleep for specified seconds
  #
  def cmd_sleep(*args)
    if args.empty?
      print_line("Usage: sleep <seconds>")
      return false
    end

    seconds = args[0].to_f
    if seconds > 0
      print_status("Sleeping for #{seconds} seconds...")
      sleep(seconds)
    else
      print_error("Invalid sleep duration")
    end
  end

  #
  # Show version information
  #
  def cmd_version(*args)
    print_line("Framework: #{Msf::Framework::Version}")
    print_line("Console  : #{Msf::Framework::Version}")
  end

  #
  # Show command history
  #
  def cmd_history(*args)
    if args.include?('-c') || args.include?('--clear')
      driver.input.clear_history if driver.input.respond_to?(:clear_history)
      print_status("Command history cleared")
      return
    end

    if driver.input.respond_to?(:history)
      history = driver.input.history
      if history.empty?
        print_line("No command history available")
      else
        history.each_with_index do |cmd, idx|
          print_line("#{idx.to_s.rjust(3)}: #{cmd}")
        end
      end
    else
      print_error("History not available for this input type")
    end
  end

  #
  # Show productivity tips
  #
  def cmd_tips(*args)
    tips = [
      "Use 'help <command>' to get detailed help for any command",
      "Use tab completion to speed up command entry",
      "Use 'sessions -l' to list all active sessions",
      "Use 'search' to find modules by name, platform, or type",
      "Use 'info' to get detailed information about a module",
      "Use 'show options' to see required and optional parameters",
      "Use 'set' and 'setg' to configure module options",
      "Use 'save' to persist your configuration across restarts"
    ]

    print_line("Productivity Tips:")
    print_line("=" * 50)
    tips.each_with_index do |tip, idx|
      print_line("#{idx + 1}. #{tip}")
    end
  end

  #
  # Show features
  #
  def cmd_features(*args)
    print_line("Available Features:")
    print_line("=" * 50)
    print_line("No experimental features are currently available.")
  end

  #
  # Tab completion for utility commands
  #
  def cmd_cd_tabs(str, words)
    return [] if words.length > 1
    
    # Complete directory names
    begin
      Dir.glob("#{str}*").select { |f| File.directory?(f) }
    rescue
      []
    end
  end

  def cmd_help_tabs(str, words)
    return [] if words.length > 1
    driver.commands.keys.select { |cmd| cmd.start_with?(str) }
  end

  def cmd_color_tabs(str, words)
    return [] if words.length > 1
    %w[true false on off %bld %red %grn %blu %yel %mag %cyn %whi %clr].select { |opt| opt.start_with?(str) }
  end

end

end
end
end
end