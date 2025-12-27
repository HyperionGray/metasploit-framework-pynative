#!/bin/bash
# -*- coding: utf-8 -*-
# Bish-Please Shell Integration
# 
# Source this file to enable bish navigation in your shell
# It provides:
# - Visual prompt when typing 'bish'
# - Directory tracking for frecency
# - Convenient shell functions
#
# Usage:
#   source bish.sh
#   # or add to your ~/.bashrc or ~/.zshrc:
#   source /path/to/bish.sh

# Detect shell type
if [ -n "$BASH_VERSION" ]; then
    BISH_SHELL="bash"
elif [ -n "$ZSH_VERSION" ]; then
    BISH_SHELL="zsh"
else
    echo "Warning: Unsupported shell. bish-please works best with bash or zsh."
    BISH_SHELL="unknown"
fi

# Get the directory where bish.py is located
BISH_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export BISH_ROOT

# Ensure Python script is executable
if [ -f "$BISH_ROOT/bish.py" ]; then
    chmod +x "$BISH_ROOT/bish.py" 2>/dev/null
fi

# Main bish command wrapper
bish() {
    local bish_cmd="$1"
    shift
    
    case "$bish_cmd" in
        "")
            # Show visual prompt and help
            echo "╔════════════════════════════════════════════════════════════╗"
            echo "║           🚀 BISH-PLEASE: Smart Navigation Tool           ║"
            echo "╚════════════════════════════════════════════════════════════╝"
            echo ""
            echo "Quick Commands:"
            echo "  bish j <alias>        Jump to bookmarked directory"
            echo "  bish add <alias> .    Bookmark current directory"
            echo "  bish ls               List all bookmarks"
            echo "  bish search <query>   Search directories"
            echo "  bish stats            Show usage statistics"
            echo ""
            echo "Full help: bish help"
            ;;
        
        j|jump)
            # Quick jump command
            local target="$1"
            if [ -z "$target" ]; then
                python3 "$BISH_ROOT/bish.py" bjump --list
                return $?
            fi
            
            local result
            result=$(python3 "$BISH_ROOT/bish.py" bjump "$target" 2>/dev/null)
            if [ $? -eq 0 ] && [ -d "$result" ]; then
                cd "$result" || return 1
                echo "📍 Jumped to: $result"
                # Record visit
                python3 "$BISH_ROOT/bish.py" visit "$result" &>/dev/null
                return 0
            else
                echo "❌ Could not jump to: $target" >&2
                return 1
            fi
            ;;
        
        add|bookmark)
            # Add bookmark
            local alias="$1"
            local path="${2:-.}"
            
            if [ -z "$alias" ]; then
                echo "Usage: bish add <alias> [path]" >&2
                return 1
            fi
            
            python3 "$BISH_ROOT/bish.py" add "$alias" "$path"
            ;;
        
        remove|rm)
            # Remove bookmark
            python3 "$BISH_ROOT/bish.py" remove "$@"
            ;;
        
        ls|list)
            # List bookmarks
            python3 "$BISH_ROOT/bish.py" bjump --list
            ;;
        
        search|find)
            # Search directories
            python3 "$BISH_ROOT/bish.py" search "$@"
            ;;
        
        stats)
            # Show statistics
            python3 "$BISH_ROOT/bish.py" stats
            ;;
        
        cleanup)
            # Clean up old entries
            python3 "$BISH_ROOT/bish.py" cleanup "$@"
            ;;
        
        help|--help|-h)
            # Show help
            echo "╔════════════════════════════════════════════════════════════╗"
            echo "║           🚀 BISH-PLEASE: Smart Navigation Tool           ║"
            echo "╚════════════════════════════════════════════════════════════╝"
            echo ""
            echo "USAGE:"
            echo "  bish                    Show this prompt with quick help"
            echo "  bish j <alias>          Jump to bookmarked directory"
            echo "  bish add <alias> [dir]  Add bookmark (defaults to current dir)"
            echo "  bish remove <alias>     Remove bookmark"
            echo "  bish ls                 List all bookmarks"
            echo "  bish search <query>     Search directories by name"
            echo "  bish stats              Show usage statistics"
            echo "  bish cleanup            Clean up old entries"
            echo "  bish help               Show this help"
            echo ""
            echo "EXAMPLES:"
            echo "  bish add msf /opt/metasploit-framework"
            echo "  bish j msf"
            echo "  bish add home ~"
            echo "  bish search exploit"
            echo ""
            echo "FEATURES:"
            echo "  • Frecency-based smart navigation (frequency + recency)"
            echo "  • Quick bookmarks for frequently used directories"
            echo "  • Fuzzy search across filesystem"
            echo "  • Automatic visit tracking"
            echo "  • Visual prompt activation"
            echo ""
            ;;
        
        *)
            # Unknown command, pass to Python backend
            python3 "$BISH_ROOT/bish.py" "$bish_cmd" "$@"
            ;;
    esac
}

# Directory tracking hook for frecency
_bish_track_pwd() {
    # Record visit in background to avoid slowing down shell
    if [ -n "$PWD" ]; then
        python3 "$BISH_ROOT/bish.py" visit "$PWD" &>/dev/null &
    fi
}

# Install directory tracking hook based on shell
if [ "$BISH_SHELL" = "bash" ]; then
    # Bash: use PROMPT_COMMAND
    if [[ ! "$PROMPT_COMMAND" =~ (^|[[:space:]])_bish_track_pwd($|[[:space:]]) ]]; then
        PROMPT_COMMAND="_bish_track_pwd${PROMPT_COMMAND:+; $PROMPT_COMMAND}"
    fi
elif [ "$BISH_SHELL" = "zsh" ]; then
    # Zsh: use chpwd hook
    if [[ ! " ${chpwd_functions[*]} " =~ " _bish_track_pwd " ]]; then
        chpwd_functions+=(_bish_track_pwd)
    fi
fi

# Bash completion for bish command
if [ "$BISH_SHELL" = "bash" ]; then
    _bish_completion() {
        local cur prev opts
        COMPREPLY=()
        cur="${COMP_WORDS[COMP_CWORD]}"
        prev="${COMP_WORDS[COMP_CWORD-1]}"
        
        # Top-level commands
        if [ $COMP_CWORD -eq 1 ]; then
            opts="j jump add bookmark remove rm ls list search find stats cleanup help"
            COMPREPLY=( $(compgen -W "${opts}" -- ${cur}) )
            return 0
        fi
        
        # Completions for specific commands
        case "${COMP_WORDS[1]}" in
            j|jump)
                # Complete with bookmark aliases
                local aliases=$(python3 "$BISH_ROOT/bish.py" bjump --list 2>/dev/null | grep -E '^\s*✓' | awk '{print $2}')
                COMPREPLY=( $(compgen -W "${aliases}" -- ${cur}) )
                ;;
            remove|rm)
                # Complete with bookmark aliases
                local aliases=$(python3 "$BISH_ROOT/bish.py" bjump --list 2>/dev/null | grep -E '^\s*[✓✗]' | awk '{print $2}')
                COMPREPLY=( $(compgen -W "${aliases}" -- ${cur}) )
                ;;
            add|bookmark)
                # Complete with directory names
                COMPREPLY=( $(compgen -d -- ${cur}) )
                ;;
        esac
    }
    
    complete -F _bish_completion bish
fi

# Zsh completion for bish command
if [ "$BISH_SHELL" = "zsh" ]; then
    _bish_zsh_completion() {
        local -a subcmds
        subcmds=(
            'j:Jump to bookmarked directory'
            'jump:Jump to bookmarked directory'
            'add:Add bookmark for directory'
            'bookmark:Add bookmark for directory'
            'remove:Remove bookmark'
            'rm:Remove bookmark'
            'ls:List all bookmarks'
            'list:List all bookmarks'
            'search:Search directories'
            'find:Search directories'
            'stats:Show usage statistics'
            'cleanup:Clean up old entries'
            'help:Show help message'
        )
        
        if (( CURRENT == 2 )); then
            _describe 'command' subcmds
        else
            case "${words[2]}" in
                j|jump)
                    local -a aliases
                    aliases=(${(f)"$(python3 "$BISH_ROOT/bish.py" bjump --list 2>/dev/null | grep -E '^\s*✓' | awk '{print $2}')"})
                    _describe 'bookmark' aliases
                    ;;
                remove|rm)
                    local -a aliases
                    aliases=(${(f)"$(python3 "$BISH_ROOT/bish.py" bjump --list 2>/dev/null | grep -E '^\s*[✓✗]' | awk '{print $2}')"})
                    _describe 'bookmark' aliases
                    ;;
                add|bookmark)
                    _directories
                    ;;
            esac
        fi
    }
    
    compdef _bish_zsh_completion bish
fi

# Export function so it's available in subshells
export -f bish 2>/dev/null || true

# Show activation message
echo "🚀 bish-please activated! Type 'bish' to see the visual prompt."
