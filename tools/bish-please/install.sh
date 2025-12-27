#!/bin/bash
# -*- coding: utf-8 -*-
# Bish-Please Installer
# 
# Installs bish-please shell navigation tool
# - Copies files to installation directory
# - Sets up shell integration
# - Configures PATH and shell profiles

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Print colored output
print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Banner
print_banner() {
    echo ""
    echo "╔════════════════════════════════════════════════════════════╗"
    echo "║           🚀 BISH-PLEASE INSTALLER                        ║"
    echo "║           Smart Shell Navigation Tool                      ║"
    echo "╚════════════════════════════════════════════════════════════╝"
    echo ""
}

# Check prerequisites
check_prerequisites() {
    print_info "Checking prerequisites..."
    
    # Check for Python 3
    if ! command -v python3 &> /dev/null; then
        print_error "Python 3 is required but not installed."
        exit 1
    fi
    
    local python_version=$(python3 --version 2>&1 | awk '{print $2}')
    print_success "Python 3 found: $python_version"
    
    # Check for bash or zsh
    local shell_found=0
    if command -v bash &> /dev/null; then
        print_success "Bash found: $(bash --version | head -n1)"
        shell_found=1
    fi
    if command -v zsh &> /dev/null; then
        print_success "Zsh found: $(zsh --version)"
        shell_found=1
    fi
    
    if [ $shell_found -eq 0 ]; then
        print_warning "No supported shell (bash/zsh) found. Installation will continue but may not work."
    fi
}

# Determine installation directory
get_install_dir() {
    local default_dir="$HOME/.local/bin/bish-please"
    
    if [ -n "$MSF_ROOT" ] && [ -d "$MSF_ROOT" ]; then
        # If in Metasploit environment, install there
        echo "$MSF_ROOT/tools/bish-please"
    elif [ "$INSTALL_SYSTEM_WIDE" = "yes" ]; then
        # System-wide installation
        echo "/usr/local/share/bish-please"
    else
        # User installation
        echo "$default_dir"
    fi
}

# Install files
install_files() {
    local install_dir="$1"
    
    print_info "Installing to: $install_dir"
    
    # Get script directory
    local script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    
    # Check if installing to the same directory
    if [ "$script_dir" = "$install_dir" ]; then
        print_info "Already in installation directory, skipping file copy"
        return 0
    fi
    
    # Create installation directory
    mkdir -p "$install_dir"
    
    # Copy Python script
    if [ -f "$script_dir/bish.py" ]; then
        cp "$script_dir/bish.py" "$install_dir/bish.py"
        chmod +x "$install_dir/bish.py"
        print_success "Installed bish.py"
    else
        print_error "bish.py not found in $script_dir"
        exit 1
    fi
    
    # Copy shell integration
    if [ -f "$script_dir/bish.sh" ]; then
        cp "$script_dir/bish.sh" "$install_dir/bish.sh"
        chmod +x "$install_dir/bish.sh"
        print_success "Installed bish.sh"
    else
        print_error "bish.sh not found in $script_dir"
        exit 1
    fi
    
    # Copy README if exists
    if [ -f "$script_dir/README.md" ]; then
        cp "$script_dir/README.md" "$install_dir/README.md"
        print_success "Installed README.md"
    fi
}

# Setup shell profile integration
setup_shell_profile() {
    local install_dir="$1"
    local shell_rc=""
    
    # Determine which shell profile to use
    if [ -n "$BASH_VERSION" ] || [ "$SHELL" = "/bin/bash" ] || [ "$SHELL" = "/usr/bin/bash" ]; then
        if [ -f "$HOME/.bashrc" ]; then
            shell_rc="$HOME/.bashrc"
        elif [ -f "$HOME/.bash_profile" ]; then
            shell_rc="$HOME/.bash_profile"
        fi
    elif [ -n "$ZSH_VERSION" ] || [ "$SHELL" = "/bin/zsh" ] || [ "$SHELL" = "/usr/bin/zsh" ]; then
        if [ -f "$HOME/.zshrc" ]; then
            shell_rc="$HOME/.zshrc"
        fi
    fi
    
    if [ -z "$shell_rc" ]; then
        print_warning "Could not determine shell profile. Manual setup required."
        print_info "Add this to your shell profile:"
        echo ""
        echo "    source $install_dir/bish.sh"
        echo ""
        return
    fi
    
    # Check if already configured
    if grep -q "bish-please" "$shell_rc" 2>/dev/null; then
        print_info "Shell profile already configured: $shell_rc"
        return
    fi
    
    # Ask user if they want to modify shell profile
    print_info "Shell profile detected: $shell_rc"
    
    if [ "$AUTO_YES" = "true" ]; then
        local response="y"
    else
        read -p "Add bish-please to $shell_rc? (y/n): " response
    fi
    
    if [[ "$response" =~ ^[Yy]$ ]]; then
        # Add to shell profile
        echo "" >> "$shell_rc"
        echo "# bish-please: Smart shell navigation" >> "$shell_rc"
        echo "if [ -f \"$install_dir/bish.sh\" ]; then" >> "$shell_rc"
        echo "    source \"$install_dir/bish.sh\"" >> "$shell_rc"
        echo "fi" >> "$shell_rc"
        
        print_success "Added bish-please to $shell_rc"
        print_info "Restart your shell or run: source $shell_rc"
    else
        print_info "Skipped shell profile modification."
        print_info "To enable bish-please, add this to your shell profile:"
        echo ""
        echo "    source $install_dir/bish.sh"
        echo ""
    fi
}

# Create symlink for easy access
create_symlink() {
    local install_dir="$1"
    local bin_dir="$HOME/.local/bin"
    
    # Create bin directory if it doesn't exist
    mkdir -p "$bin_dir"
    
    # Check if bin_dir is in PATH
    if [[ ":$PATH:" != *":$bin_dir:"* ]]; then
        print_warning "$bin_dir is not in PATH. You may need to add it."
    fi
    
    # Create symlink
    if [ -f "$bin_dir/bish" ]; then
        print_info "Symlink already exists: $bin_dir/bish"
    else
        ln -s "$install_dir/bish.py" "$bin_dir/bish"
        print_success "Created symlink: $bin_dir/bish"
    fi
}

# Initialize database
init_database() {
    print_info "Initializing database..."
    
    # Run bish stats to initialize database
    local bish_py="$1/bish.py"
    python3 "$bish_py" stats &>/dev/null || true
    
    # Add some default bookmarks if in MSF environment
    if [ -n "$MSF_ROOT" ] && [ -d "$MSF_ROOT" ]; then
        python3 "$bish_py" add msf "$MSF_ROOT" &>/dev/null || true
        python3 "$bish_py" add modules "$MSF_ROOT/modules" &>/dev/null || true
        python3 "$bish_py" add exploits "$MSF_ROOT/modules/exploits" &>/dev/null || true
        print_success "Added default Metasploit bookmarks"
    fi
}

# Main installation
main() {
    print_banner
    
    # Parse arguments
    AUTO_YES="false"
    INSTALL_SYSTEM_WIDE="no"
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            -y|--yes)
                AUTO_YES="true"
                shift
                ;;
            --system)
                INSTALL_SYSTEM_WIDE="yes"
                shift
                ;;
            -h|--help)
                echo "Usage: $0 [OPTIONS]"
                echo ""
                echo "Options:"
                echo "  -y, --yes     Automatically answer yes to prompts"
                echo "  --system      Install system-wide (requires sudo)"
                echo "  -h, --help    Show this help message"
                echo ""
                exit 0
                ;;
            *)
                print_error "Unknown option: $1"
                exit 1
                ;;
        esac
    done
    
    # Check prerequisites
    check_prerequisites
    
    # Determine installation directory
    INSTALL_DIR=$(get_install_dir)
    
    # Check if we need sudo for system-wide install
    if [ "$INSTALL_SYSTEM_WIDE" = "yes" ] && [ "$(id -u)" -ne 0 ]; then
        print_error "System-wide installation requires sudo privileges"
        exit 1
    fi
    
    # Install files
    install_files "$INSTALL_DIR"
    
    # Create symlink
    if [ "$INSTALL_SYSTEM_WIDE" != "yes" ]; then
        create_symlink "$INSTALL_DIR"
    fi
    
    # Setup shell profile
    setup_shell_profile "$INSTALL_DIR"
    
    # Initialize database
    init_database "$INSTALL_DIR"
    
    # Success message
    echo ""
    print_success "Installation complete! 🎉"
    echo ""
    echo "Next steps:"
    echo "  1. Restart your shell or run: source $INSTALL_DIR/bish.sh"
    echo "  2. Type 'bish' to see the visual prompt and quick help"
    echo "  3. Try: bish add mydir /path/to/directory"
    echo "  4. Then: bish j mydir"
    echo ""
    echo "Documentation: $INSTALL_DIR/README.md"
    echo ""
}

# Run main function
main "$@"
