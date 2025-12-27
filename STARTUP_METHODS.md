# Metasploit Framework Startup Methods - Visual Guide

This document provides a visual representation of the different ways to start and use the Metasploit Framework in this Python-native fork.

## 🎯 Recommended Method: `source msfrc`

```
┌─────────────────────────────────────────────────────────────────┐
│                    USER'S REGULAR SHELL                         │
└─────────────────────────────────────────────────────────────────┘
                              │
                              │ $ source msfrc
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│              MSF ENVIRONMENT ACTIVATED (msf)                    │
│                                                                 │
│  Environment Variables Set:                                     │
│  • MSF_ROOT                                                     │
│  • MSF_PYTHON_MODE=1                                            │
│  • MSF_DATABASE_CONFIG                                          │
│  • MSF_MODULE_PATHS                                             │
│  • PYTHONPATH includes MSF lib                                  │
│                                                                 │
│  Available Commands:                                            │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │ msf_console   → Python-enhanced console                │   │
│  │ msf_venom     → Payload generator                      │   │
│  │ msf_exploit   → Quick exploit launcher                 │   │
│  │ msf_search    → Search modules                         │   │
│  │ msf_info      → Environment information                │   │
│  │ msf_db        → Database management                    │   │
│  │ msf_rpc       → RPC server                             │   │
│  └─────────────────────────────────────────────────────────┘   │
│                                                                 │
│  Direct Python Execution:                                       │
│  $ python3 modules/exploits/linux/http/example.py --help       │
│                                                                 │
│  Traditional Commands (with guidance):                          │
│  $ msfconsole  → Shows guidance to use msf_console instead     │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
                              │
                              │ $ msf_deactivate
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│              ORIGINAL SHELL ENVIRONMENT RESTORED                │
└─────────────────────────────────────────────────────────────────┘
```

## ⚠️ Legacy Method: Direct `msfconsole` (Not Recommended)

```
┌─────────────────────────────────────────────────────────────────┐
│                    USER'S REGULAR SHELL                         │
└─────────────────────────────────────────────────────────────────┘
                              │
                              │ $ ./msfconsole
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                     ⚠️  GUIDANCE MESSAGE                        │
│                                                                 │
│  ╔════════════════════════════════════════════════════════╗    │
│  ║  RECOMMENDED: Use the MSF environment activation       ║    │
│  ║                                                        ║    │
│  ║  For the best experience, activate first:             ║    │
│  ║    $ source msfrc                                      ║    │
│  ║                                                        ║    │
│  ║  This gives you a virtualenv-like experience with:    ║    │
│  ║    ✅ All MSF commands in your shell                   ║    │
│  ║    ✅ Python-native module execution                   ║    │
│  ║    ✅ Easy access to transpiler tools                  ║    │
│  ║    ✅ Proper environment configuration                 ║    │
│  ╚════════════════════════════════════════════════════════╝    │
│                                                                 │
│  Traditional msfconsole is being phased out.                   │
│  Use 'source msfrc' for the modern Python-native experience!   │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
                              │
                              │ Process exits
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│              USER RETURNS TO REGULAR SHELL                      │
│         (Encouraged to try 'source msfrc' instead)              │
└─────────────────────────────────────────────────────────────────┘
```

## 📊 Comparison: Why `source msfrc` is Better

| Feature | `source msfrc` | Direct `msfconsole` |
|---------|----------------|---------------------|
| **Workflow** | Modern, virtualenv-like | Legacy, traditional |
| **Shell Integration** | ✅ All commands in shell | ❌ Must enter console |
| **Python Support** | ✅ Full native support | ⚠️ Limited |
| **Environment Setup** | ✅ Automatic | ⚠️ Manual |
| **Tool Access** | ✅ Direct access | ❌ Must use console |
| **Transpilers** | ✅ Easy access | ❌ Not available |
| **Flexibility** | ✅ High (run modules directly) | ⚠️ Limited |
| **Deactivation** | ✅ Clean (`msf_deactivate`) | N/A |

## 🔄 Typical Workflow with `source msfrc`

```
1. Activate Environment
   ┌────────────────────────────────┐
   │ $ cd metasploit-framework-pynative
   │ $ source msfrc                 │
   │                                │
   │ 🐍 MSF Environment Activated!  │
   └────────────────────────────────┘
                ↓
2. Explore Available Commands
   ┌────────────────────────────────┐
   │ (msf) $ msf_info               │
   │                                │
   │ Shows all available commands   │
   │ and environment details        │
   └────────────────────────────────┘
                ↓
3. Search for Modules
   ┌────────────────────────────────┐
   │ (msf) $ msf_search apache      │
   │                                │
   │ Lists apache-related modules   │
   └────────────────────────────────┘
                ↓
4. Run Python Module Directly
   ┌────────────────────────────────┐
   │ (msf) $ python3 modules/       │
   │   exploits/linux/http/         │
   │   example.py --help            │
   │                                │
   │ Execute module with full       │
   │ environment support            │
   └────────────────────────────────┘
                ↓
5. Use Transpiler Tools
   ┌────────────────────────────────┐
   │ (msf) $ python3 ruby2py/       │
   │   convert.py old_module.rb     │
   │                                │
   │ Convert Ruby to Python         │
   └────────────────────────────────┘
                ↓
6. Clean Exit
   ┌────────────────────────────────┐
   │ (msf) $ msf_deactivate         │
   │                                │
   │ MSF environment deactivated    │
   │ Shell restored to original     │
   └────────────────────────────────┘
```

## 💡 Key Benefits

### For Users

- **Familiar Workflow**: Works like Python's virtualenv
- **No Context Switching**: Stay in your regular shell
- **Direct Execution**: Run Python modules without entering console
- **Clean Environment**: Easy activation and deactivation

### For Developers

- **Better Testing**: Run modules directly with `python3`
- **Tool Integration**: Direct access to transpilers and utilities
- **Debugging**: Standard Python debugging tools work normally
- **Flexible**: Mix MSF commands with regular shell commands

## 🚀 Getting Started

```bash
# One-time setup
git clone https://github.com/HyperionGray/metasploit-framework-pynative.git
cd metasploit-framework-pynative
pip3 install -r requirements.txt

# Every session
source msfrc          # Activate
msf_info              # Get oriented
# ... do your work ...
msf_deactivate        # Clean exit
```

For complete details, see [QUICKSTART.md](QUICKSTART.md).
