# PwnMode: Venv-Style Session Interaction

## Overview

This feature changes how Metasploit Framework handles session interaction for console-based sessions (like meterpreter and SQL sessions). Instead of spawning a completely new shell, the main console prompt is updated to show you're in "pwnmode" - similar to how Python virtual environments work.

## What Changed?

### Before (Traditional Behavior)
When you ran `sessions -i <id>`, Metasploit would:
1. Spawn a completely new console/shell
2. You'd lose context of the main MSF console
3. Had to exit the session to get back to MSF commands

### After (New PwnMode Behavior)

For **console-based sessions** (meterpreter, SQL):
1. Run `sessions -i <id>` 
2. Your prompt changes to show the active session: `(meterpreter:1) msf6 >`
3. You stay in the main console - MSF commands still work
4. Unknown commands are automatically routed to the session
5. Use `detach` command to return to normal mode

For **stream-based sessions** (command shells):
- Traditional behavior is preserved (spawns interactive session)
- This is necessary because these sessions are stream-based

## Usage Examples

### Interacting with a Meterpreter Session

```
msf6 > sessions -i 1
[*] Starting interaction with HOSTNAME (192.168.1.100:4444)...
Use 'detach' to return to the main console

(meterpreter:1) msf6 > sysinfo
Computer        : HOSTNAME
OS              : Windows 10 (10.0 Build 19041).
Architecture    : x64
...

(meterpreter:1) msf6 > sessions
Active sessions
===============
  Id  Name  Type         Information  Connection
  --  ----  ----         -----------  ----------
  1         meterpreter  NT AUTHOR... 192.168.1.100:4444

(meterpreter:1) msf6 > help
Core Commands
=============
  Command     Description
  -------     -----------
  ?           Help menu
  detach      Detach from the current interactive session
  ...

(meterpreter:1) msf6 > detach
[*] Detaching from session 1 (HOSTNAME (192.168.1.100:4444))...
[+] Returned to main console
msf6 >
```

### Multiple Sessions

```
msf6 > sessions -i 1
(meterpreter:1) msf6 > pwd
C:\Users\victim

(meterpreter:1) msf6 > detach
msf6 > sessions -i 2
(meterpreter:2) msf6 > pwd
/home/victim

(meterpreter:2) msf6 > detach
msf6 >
```

## Benefits

1. **Better Context Awareness**: Always know which session you're in via the prompt
2. **Seamless Command Access**: MSF commands work while in session mode
3. **Improved Workflow**: Switch between sessions and console without losing context
4. **Familiar Pattern**: Works like Python venv, Git branches, or Docker containers
5. **Non-Disruptive**: Command shells still work the traditional way

## Commands

### `detach`
Exits session interaction mode and returns to the main console.

```
(meterpreter:1) msf6 > detach
[*] Detaching from session 1...
[+] Returned to main console
msf6 >
```

## Technical Details

### Supported Session Types (New Behavior)
- Meterpreter sessions (all platforms)
- SQL sessions (MySQL, PostgreSQL, MSSQL)
- SMB sessions
- LDAP sessions
- Any session with a `console` attribute

### Unsupported Session Types (Traditional Behavior)
- Command shell sessions
- Any stream-based interactive session

### How It Works
1. When you interact with a console-based session, the driver's `active_session` is set
2. The prompt is updated to show the session info
3. The session's console UI is initialized with the driver's input/output
4. Unknown commands are routed to the session's console via `unknown_command`
5. When you detach, the session UI is reset and `active_session` is cleared

## Troubleshooting

### Commands not working in session mode
If commands aren't being routed to the session:
- Make sure you're using a console-based session (meterpreter, SQL)
- Try using `detach` and re-entering the session
- Check that the session is still active with `sessions -l`

### Want the old behavior back?
For command shells, the traditional behavior is automatically used. For other session types, you can:
1. Use the session's native interact method directly (not implemented in this version)
2. Or use the new behavior which should be more convenient

## Future Enhancements

Potential improvements for future versions:
- Add Ctrl+Z signal handling for detaching (currently use `detach` command)
- Support custom prompt formats via datastore
- Add session command history separate from main console
- Improve tab completion for session commands
