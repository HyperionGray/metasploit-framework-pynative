This is the folder where all of Metasploit's modules live. These modules are scripts in Ruby that interface with
Metasploit itself to perform some specific task. There are various types of modules, such as `exploit` modules to
exploit a vulnerability and gain a shell, `auxiliary` to perform a non-shell gaining activity, `payloads` for
Metasploit's various payloads (which are also modules), and `post` for post exploitation modules.

## New: Simulated Malware Category

Under `post/multi/malware/`, you'll find a new category of **Simulated Malware** modules designed for penetration testing
and red team exercises. These modules demonstrate realistic malware behaviors (persistence, file dropping, C2 beaconing)
while including **automatic time-bomb cleanup** mechanisms to ensure responsible testing without manual artifact removal.

Key features:
- **Time-Bomb Mechanism**: All artifacts automatically self-destruct after a configurable time period
- **Multi-Platform**: Support for Windows, Linux, macOS, and Unix systems
- **Safe for Testing**: Simulated payloads with predictable, documented behavior
- **Automatic Cleanup**: No manual intervention required to remove test artifacts

Available modules:
- `timebomb_persistence.rb` - Persistent backdoor with auto-cleanup
- `file_dropper_timebomb.rb` - File dropper with automatic file removal
- `beacon_timebomb.rb` - C2 beacon simulation with auto-cleanup

See [post/multi/malware/README.md](post/multi/malware/README.md) for detailed documentation.