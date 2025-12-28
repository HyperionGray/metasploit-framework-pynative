# -*- coding: binary -*-

module Msf
module Ui
module Console
module CommandDispatcher

###
#
# Variable management commands for the core command dispatcher
#
###
module VariableCommands

  # setg command options
  @@setg_opts = Rex::Parser::Arguments.new(
    ["-h", "--help"] => [ false, "Help banner."],
    ["-c", "--clear"] => [ false, "Clear the values, explicitly setting to nil (default)"]
  )

  @@set_opts = @@setg_opts.merge(
    ["-g", "--global"] => [ false, "Operate on global datastore variables"]
  )

  # unset command options
  @@unsetg_opts = Rex::Parser::Arguments.new(
    ["-h", "--help"] => [ false, "Help banner."],
  )

  @@unset_opts = @@unsetg_opts.merge(
    ["-g", "--global"] => [ false, "Operate on global datastore variables"]
  )

  def variable_commands
    {
      "get"        => "Gets the value of a context-specific variable",
      "getg"       => "Gets the value of a global variable",
      "set"        => "Sets a context-specific variable to a value",
      "setg"       => "Sets a global variable to a value",
      "unset"      => "Unsets one or more context-specific variables",
      "unsetg"     => "Unsets one or more global variables",
      "save"       => "Saves the active datastores"
    }
  end

  #
  # Gets the value of a context-specific variable
  #
  def cmd_get(*args)
    if args.empty?
      print_error("Usage: get <variable name>")
      return false
    end

    var_name = args[0]
    if active_module
      value = active_module.datastore[var_name]
    else
      value = framework.datastore[var_name]
    end

    if value.nil?
      print_line("#{var_name} => ")
    else
      print_line("#{var_name} => #{value}")
    end
  end

  #
  # Gets the value of a global variable
  #
  def cmd_getg(*args)
    if args.empty?
      print_error("Usage: getg <variable name>")
      return false
    end

    var_name = args[0]
    value = framework.datastore[var_name]

    if value.nil?
      print_line("#{var_name} => ")
    else
      print_line("#{var_name} => #{value}")
    end
  end

  #
  # Sets a context-specific variable to a value
  #
  def cmd_set(*args)
    if args.length < 2
      print_error("Usage: set <variable name> <value>")
      return false
    end

    var_name = args[0]
    var_value = args[1..-1].join(' ')

    if active_module
      active_module.datastore[var_name] = var_value
      print_line("#{var_name} => #{var_value}")
    else
      framework.datastore[var_name] = var_value
      print_line("#{var_name} => #{var_value}")
    end
  end

  #
  # Sets a global variable to a value
  #
  def cmd_setg(*args)
    if args.length < 2
      print_error("Usage: setg <variable name> <value>")
      return false
    end

    var_name = args[0]
    var_value = args[1..-1].join(' ')

    framework.datastore[var_name] = var_value
    print_line("#{var_name} => #{var_value}")
  end

  #
  # Unsets one or more context-specific variables
  #
  def cmd_unset(*args)
    if args.empty?
      print_error("Usage: unset <variable name> [variable name ...]")
      return false
    end

    args.each do |var_name|
      if active_module
        active_module.datastore.delete(var_name)
      else
        framework.datastore.delete(var_name)
      end
      print_line("Unsetting #{var_name}...")
    end
  end

  #
  # Unsets one or more global variables
  #
  def cmd_unsetg(*args)
    if args.empty?
      print_error("Usage: unsetg <variable name> [variable name ...]")
      return false
    end

    args.each do |var_name|
      framework.datastore.delete(var_name)
      print_line("Unsetting #{var_name}...")
    end
  end

  #
  # Saves the active datastores
  #
  def cmd_save(*args)
    if args.include?("-h") || args.include?("--help")
      print_line("Usage: save")
      print_line
      print_line("Save the active datastore contents to disk for automatic loading when")
      print_line("the console starts up.")
      return
    end

    begin
      framework.save_config
      print_line("Saved configuration to: #{Msf::Config.config_file}")
    rescue => e
      print_error("Failed to save configuration: #{e}")
    end
  end

  #
  # Tab completion for variable commands
  #
  def cmd_get_tabs(str, words)
    return [] if words.length > 1
    
    if active_module
      active_module.datastore.keys.select { |k| k.start_with?(str) }
    else
      framework.datastore.keys.select { |k| k.start_with?(str) }
    end
  end

  def cmd_getg_tabs(str, words)
    return [] if words.length > 1
    framework.datastore.keys.select { |k| k.start_with?(str) }
  end

  def cmd_set_tabs(str, words)
    return [] if words.length > 2
    return [] if words.length == 2  # Don't complete values
    
    if active_module
      active_module.datastore.keys.select { |k| k.start_with?(str) }
    else
      framework.datastore.keys.select { |k| k.start_with?(str) }
    end
  end

  def cmd_setg_tabs(str, words)
    return [] if words.length > 2
    return [] if words.length == 2  # Don't complete values
    framework.datastore.keys.select { |k| k.start_with?(str) }
  end

  def cmd_unset_tabs(str, words)
    if active_module
      active_module.datastore.keys.select { |k| k.start_with?(str) && !words.include?(k) }
    else
      framework.datastore.keys.select { |k| k.start_with?(str) && !words.include?(k) }
    end
  end

  def cmd_unsetg_tabs(str, words)
    framework.datastore.keys.select { |k| k.start_with?(str) && !words.include?(k) }
  end

end

end
end
end
end