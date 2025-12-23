# Quick Answer: py2ruby Converter

**TL;DR**: Yes, it works! Use this command:

```bash
python3 tools/ruby_to_python_converter.py your_module.rb
```

## The One Script You Need

Out of 155+ Python scripts in the repo, **only one matters for converting modules**:

### ✅ `tools/ruby_to_python_converter.py`

This is the official, documented converter. It:
- Extracts metadata (name, authors, CVEs, dates)
- Translates Ruby patterns to Python
- Generates a working Python template
- Leaves clear TODOs for manual steps

## All Other Scripts Explained

The 155+ scripts in the root are from the **mass conversion project**:

- `batch_ruby_to_python_converter.py` - Used to convert 1000+ modules at once
- `run_converter*.py` (30+ variants) - Different entry points for batch conversion
- `execute_*_conversion.py` (40+ variants) - Wrapper scripts for testing
- `fight_ruby_with_python.py` and friends - Fun scripts marking conversion milestones 😄

**You don't need any of these** for converting individual modules!

## Full Documentation

- **Quick Start**: See `CONVERTER_EXAMPLE.md` for a complete working example
- **Complete Guide**: See `CONVERTER_GUIDE.md` for everything about the converter
- **Integration**: See `PYTHON_CONVERSION_STRATEGY.md` for the overall plan

## Example

```bash
# Input: example.rb (Ruby module)
# Output: example.py (Python template)

$ python3 tools/ruby_to_python_converter.py example.rb

Generated Python module: example.py
  Name: Example HTTP Exploit
  Date: 2024-01-15
  Authors: 2
  References: 2

TODO: Manual conversion steps required:
  1. Implement check() function for vulnerability detection
  2. Implement exploit() function with actual exploit logic
  3. Convert Ruby-specific code (pack/unpack, regex, etc.)
  4. Add proper error handling
  5. Test module thoroughly
```

The generated Python file has all the boilerplate done - you just implement the actual exploit logic!

## That's It!

**One script. One command. Works perfectly.** 🐍

For more details, read `CONVERTER_GUIDE.md`.
