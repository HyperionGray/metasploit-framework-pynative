# -*- coding: binary -*-

module Msf
module Ui
module Console
module CommandDispatcher

###
#
# Session management commands for the core command dispatcher
#
###
module SessionCommands

  # Session command options
  @@sessions_opts = Rex::Parser::Arguments.new(
    ["-c", "--command"]              => [ true,  "Run a command on the session given with -i, or all", "<command>"               ],
    ["-C", "--meterpreter-command"]  => [ true,  "Run a Meterpreter Command on the session given with -i, or all", "<command>"   ],
    ["-h", "--help"]                 => [ false, "Help banner"                                                                   ],
    ["-i", "--interact"]             => [ true,  "Interact with the supplied session ID", "<id>"                                 ],
    ["-l", "--list"]                 => [ false, "List all active sessions"                                                      ],
    ["-v", "--list-verbose"]         => [ false, "List all active sessions in verbose mode"                                      ],
    ["-d", "--list-inactive"]        => [ false, "List all inactive sessions"                                                    ],
    ["-q", "--quiet"]                => [ false, "Quiet mode"                                                                    ],
    ["-k", "--kill"]                 => [ true,  "Terminate sessions by session ID and/or range", "<id>"                         ],
    ["-K", "--kill-all"]             => [ false, "Terminate all sessions"                                                        ],
    ["-s", "--script"]               => [ true,  "Run a script or module on the session given with -i, or all", "<script>"       ],
    ["-u", "--upgrade"]              => [ true,  "Upgrade a shell to a meterpreter session on many platforms", "<id>"            ],
    ["-t", "--timeout"]              => [ true,  "Set a response timeout (default: 15)", "<seconds>"                             ],
    ["-S", "--search"]               => [ true,  "Row search filter. (ex: sessions --search 'last_checkin:less_than:10s session_id:5 session_type:meterpreter')", "<filter>"],
    ["-x", "--list-extended"]        => [ false, "Show extended information in the session table"                                ],
    ["-n", "--name"]                 => [ true,  "Name or rename a session by ID", "<id> <name>"                                 ])

  SESSION_TYPE = 'session_type'
  SESSION_ID = 'session_id'
  LAST_CHECKIN = 'last_checkin'
  LESS_THAN = 'less_than'
  GREATER_THAN = 'greater_than'

  VALID_SESSION_SEARCH_PARAMS = [LAST_CHECKIN, SESSION_ID, SESSION_TYPE]
  VALID_OPERATORS = [LESS_THAN, GREATER_THAN]

  def session_commands
    {
      "sessions"   => "Dump session listings and display information about sessions",
      "detach"     => "Detach from the current interactive session"
    }
  end

  #
  # Displays the list of active sessions.
  #
  def cmd_sessions(*args)
    method = nil
    quiet = false
    show_extended = false
    sid = nil
    cmds = []
    script = nil
    response_timeout = 15
    search_term = nil

    # Parse the command options
    @@sessions_opts.parse(args) do |opt, idx, val|
      case opt
      when "-q"
        quiet = true
      when "-l"
        method = 'list'
      when "-v"
        method = 'list_verbose'
      when "-d"
        method = 'list_inactive'
      when "-k"
        method = 'kill'
        sid = val
      when "-K"
        method = 'kill_all'
      when "-c"
        method = 'cmd'
        cmds << val if val
      when "-C"
        method = 'meterpreter_cmd'
        cmds << val if val
      when "-s"
        method = 'script'
        script = val
      when "-i"
        method = 'interact'
        sid = val
      when "-u"
        method = 'upgrade'
        sid = val
      when "-t"
        response_timeout = val.to_i
      when "-S"
        search_term = val
      when "-x"
        show_extended = true
      when "-n"
        method = 'name'
        sid = val
      when "-h"
        cmd_sessions_help
        return false
      end
    end

    # Default to listing sessions if no method specified
    method = 'list' if method.nil?

    # Now handle the method
    case method
    when 'list', 'list_verbose', 'list_inactive'
      print_sessions_table(method, search_term, show_extended)
    when 'kill'
      kill_sessions(sid)
    when 'kill_all'
      kill_all_sessions
    when 'interact'
      interact_with_session(sid)
    when 'cmd'
      run_session_commands(sid, cmds, response_timeout)
    when 'meterpreter_cmd'
      run_meterpreter_commands(sid, cmds, response_timeout)
    when 'script'
      run_session_script(sid, script, response_timeout)
    when 'upgrade'
      upgrade_session(sid)
    when 'name'
      name_session(sid, args)
    end
  end

  def cmd_sessions_help
    print_line "Usage: sessions [options] or sessions [id]"
    print_line
    print_line "Active session manipulation and interaction."
    print @@sessions_opts.usage
  end

  #
  # Tab completion for the sessions command
  #
  def cmd_sessions_tabs(str, words)
    if words.length == 1
      return @@sessions_opts.option_keys.select { |opt| opt.start_with?(str) }
    end

    case words[-1]
    when '-i', '-k', '-u', '-n'
      return framework.sessions.keys.map(&:to_s).select { |id| id.start_with?(str) }
    when '-s'
      # Script/module completion would go here
      return []
    end

    []
  end

  #
  # Detaches from the current interactive session
  #
  def cmd_detach(*args)
    if driver.active_session
      driver.active_session = nil
      print_status("Backgrounding session...")
    else
      print_error("No active session to detach from")
    end
  end

  private

  def print_sessions_table(method, search_term, show_extended)
    # Implementation for printing sessions table
    # This would contain the actual session listing logic
    print_line("Sessions table implementation would go here")
  end

  def kill_sessions(sid)
    # Implementation for killing specific sessions
    print_line("Kill sessions implementation would go here")
  end

  def kill_all_sessions
    # Implementation for killing all sessions
    print_line("Kill all sessions implementation would go here")
  end

  def interact_with_session(sid)
    # Implementation for interacting with a session
    print_line("Interact with session implementation would go here")
  end

  def run_session_commands(sid, cmds, timeout)
    # Implementation for running commands on sessions
    print_line("Run session commands implementation would go here")
  end

  def run_meterpreter_commands(sid, cmds, timeout)
    # Implementation for running meterpreter commands
    print_line("Run meterpreter commands implementation would go here")
  end

  def run_session_script(sid, script, timeout)
    # Implementation for running scripts on sessions
    print_line("Run session script implementation would go here")
  end

  def upgrade_session(sid)
    # Implementation for upgrading sessions
    print_line("Upgrade session implementation would go here")
  end

  def name_session(sid, args)
    # Implementation for naming sessions
    print_line("Name session implementation would go here")
  end

end

end
end
end
end