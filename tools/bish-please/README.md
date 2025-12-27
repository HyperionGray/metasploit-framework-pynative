# Bish-Please: Smart Shell Navigation Tool

🚀 A frecency-based directory jumping tool with visual prompt integration for bash and zsh.

## Features

- **Frecency-Based Navigation**: Combines frequency and recency to intelligently rank directories
- **Quick Bookmarks**: Save frequently-used directories with memorable aliases
- **Fuzzy Search**: Find directories by name across your filesystem
- **Automatic Tracking**: Learns your navigation patterns automatically
- **Visual Prompt**: Beautiful, informative prompt when you type `bish`
- **Shell Integration**: Works seamlessly with bash and zsh
- **Tab Completion**: Smart completion for bookmarks and commands

## Installation

### Automatic Installation

```bash
cd tools/bish-please
./install.sh
```

The installer will:
1. Copy files to installation directory
2. Set up shell integration in your `.bashrc` or `.zshrc`
3. Create convenient symlinks
4. Initialize the database

### Manual Installation

1. Copy files to your desired location:
```bash
mkdir -p ~/.local/bin/bish-please
cp bish.py bish.sh ~/.local/bin/bish-please/
chmod +x ~/.local/bin/bish-please/bish.py
```

2. Add to your shell profile (`~/.bashrc` or `~/.zshrc`):
```bash
source ~/.local/bin/bish-please/bish.sh
```

3. Restart your shell or source the file:
```bash
source ~/.bashrc  # or ~/.zshrc
```

## Quick Start

### Visual Prompt

Simply type `bish` to see the visual prompt with quick help:

```
╔════════════════════════════════════════════════════════════╗
║           🚀 BISH-PLEASE: Smart Navigation Tool           ║
╚════════════════════════════════════════════════════════════╝

Quick Commands:
  bish j <alias>        Jump to bookmarked directory
  bish add <alias> .    Bookmark current directory
  bish ls               List all bookmarks
  bish search <query>   Search directories
  bish stats            Show usage statistics

Full help: bish help
```

### Basic Commands

```bash
# Add a bookmark for current directory
bish add myproject .

# Add a bookmark for a specific directory
bish add msf /opt/metasploit-framework

# Jump to a bookmarked directory
bish j msf

# List all bookmarks
bish ls

# Search for directories
bish search exploit

# Show usage statistics
bish stats

# Remove a bookmark
bish remove myproject
```

## How It Works

### Frecency Algorithm

Bish-please uses a **frecency** algorithm that combines:
- **Frequency**: How often you visit a directory
- **Recency**: How recently you visited it

This means:
- Directories you visit often get higher scores
- Recently visited directories are prioritized
- Old, rarely-used directories naturally fade from results

### Automatic Tracking

Every time you change directories, bish-please automatically:
1. Records the visit in its database
2. Updates the frecency score
3. Makes that directory searchable

No manual indexing required!

### Smart Search

When you jump or search, bish-please:
1. First checks for exact bookmark alias matches
2. Then searches indexed directories by frecency
3. Falls back to filesystem search if needed

## Commands

### Jump Commands

```bash
bish j <alias>          # Jump to bookmarked directory
bish jump <alias>       # Same as 'j'
bish j                  # List all bookmarks (same as 'bish ls')
```

### Bookmark Management

```bash
bish add <alias> [dir]  # Add bookmark (defaults to current dir)
bish remove <alias>     # Remove bookmark
bish ls                 # List all bookmarks
bish list               # Same as 'ls'
```

### Search and Discovery

```bash
bish search <query>     # Search directories by name
bish find <query>       # Same as 'search'
bish search -l 20 <q>   # Limit to 20 results
```

### Statistics and Maintenance

```bash
bish stats              # Show usage statistics
bish cleanup            # Remove old entries (90+ days)
bish cleanup -d 30      # Remove entries older than 30 days
```

### Help

```bash
bish                    # Show visual prompt with quick help
bish help               # Show detailed help
bish --help             # Show command-line help
```

## Examples

### Metasploit Framework Integration

```bash
# Add bookmarks for common MSF directories
bish add msf $MSF_ROOT
bish add modules $MSF_ROOT/modules
bish add exploits $MSF_ROOT/modules/exploits
bish add payloads $MSF_ROOT/modules/payloads
bish add tools $MSF_ROOT/tools

# Quick navigation
bish j exploits
bish j payloads
bish j msf

# Search for specific modules
bish search windows
bish search http
```

### Development Workflow

```bash
# Bookmark your projects
bish add project ~/projects/myapp
bish add web ~/projects/webapp
bish add api ~/projects/api

# Quick switching between projects
bish j project
# ... do some work ...
bish j api
# ... work on API ...
bish j web
# ... work on web app ...

# After a few weeks, most-used projects will rank higher
bish search proj  # Shows project in frecency order
```

### System Navigation

```bash
# Common system directories
bish add logs /var/log
bish add etc /etc
bish add tmp /tmp

# Quick access
bish j logs
bish j etc
```

## Configuration

### Database Location

By default, bish-please uses `.bish.sqlite` in:
1. `$MSF_ROOT/.bish.sqlite` if in Metasploit environment
2. Current directory otherwise

You can specify a custom database location:
```bash
python3 bish.py --db /path/to/custom.db stats
```

### Shell Integration

The shell integration script (`bish.sh`) automatically:
- Detects your shell (bash or zsh)
- Sets up directory tracking hooks
- Installs tab completion
- Provides the `bish` command wrapper

## Advanced Usage

### Python API

You can use bish-please as a Python library:

```python
from bish import BishDB

# Initialize database
db = BishDB()

# Add bookmark
db.add_bjump('myalias', '/path/to/dir')

# Get bookmark
path = db.get_bjump('myalias')

# Record visit
db.record_visit('/path/to/dir')

# Search
results = db.search_directories('query', limit=10)

# Clean up
db.close()
```

### Custom Indexing

```bash
# Manually record visits for directories you want to prioritize
for dir in ~/projects/*; do
    python3 bish.py visit "$dir"
done
```

### Cleanup Strategies

```bash
# Remove entries not accessed in 30 days
bish cleanup -d 30

# Remove entries not accessed in 180 days
bish cleanup -d 180

# Regular maintenance (cron job)
0 0 * * 0 python3 ~/.local/bin/bish-please/bish.py cleanup -d 90
```

## Troubleshooting

### "bish: command not found"

Make sure you've sourced the shell integration:
```bash
source ~/.local/bin/bish-please/bish.sh
```

Or add it to your shell profile and restart your shell.

### Database Errors

If you encounter database errors:
```bash
# Backup old database
mv .bish.sqlite .bish.sqlite.bak

# Initialize fresh database
bish stats
```

### Python Not Found

Ensure Python 3 is installed and in your PATH:
```bash
python3 --version
```

### No Results in Search

The database starts empty. It learns as you navigate:
1. Navigate to directories normally
2. Wait for frecency to build up
3. Or manually add bookmarks with `bish add`

## Performance

- **Database**: SQLite with optimized indices
- **Tracking**: Async background recording (doesn't slow down shell)
- **Search**: Sub-millisecond for typical databases (<10,000 entries)
- **Memory**: Minimal footprint (~1-5 MB for database)

## Comparison with Other Tools

| Feature | bish-please | z/autojump | fasd | zoxide |
|---------|-------------|------------|------|--------|
| Frecency | ✅ | ✅ | ✅ | ✅ |
| Bookmarks | ✅ | ❌ | ❌ | ❌ |
| Visual Prompt | ✅ | ❌ | ❌ | ❌ |
| Python API | ✅ | ❌ | ❌ | ❌ |
| Fuzzy Search | ✅ | ✅ | ✅ | ✅ |
| Tab Completion | ✅ | ✅ | ✅ | ✅ |
| Metasploit Integration | ✅ | ❌ | ❌ | ❌ |

## Contributing

Contributions are welcome! Please:

1. Follow the Metasploit coding standards
2. Add tests for new features
3. Update documentation
4. Submit a pull request

## License

This tool is part of the Metasploit Framework and follows the same BSD-style license.

## Credits

Developed as part of the Metasploit Framework Python-native initiative.

Inspired by tools like:
- [z](https://github.com/rupa/z)
- [autojump](https://github.com/wting/autojump)
- [fasd](https://github.com/clvv/fasd)
- [zoxide](https://github.com/ajeetdsouza/zoxide)

## Support

- GitHub Issues: https://github.com/HyperionGray/metasploit-framework-pynative/issues
- Metasploit Slack: https://metasploit.com/slack
- Documentation: This README

---

**Made with ❤️ for the Metasploit community**
