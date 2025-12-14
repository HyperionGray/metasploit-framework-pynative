##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Fuzzer

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Binary Instrumentation with LLVM/libfuzzrt',
        'Description' => %q{
          This module instruments binaries with LLVM-based sanitizers (ASAN, UBSan, MSan, TSan)
          or Frida-based runtime instrumentation. It provides memory safety checks,
          undefined behavior detection, and efficient edge coverage tracking with auto-removal
          of instrumentation points after first hit.

          The module can operate in three modes:
          1. LLVM Compile Mode - Recompile source with sanitizers
          2. Frida Mode - Runtime instrumentation without recompilation
          3. Binary Patch Mode - Direct binary patching (experimental)

          Features:
          - AddressSanitizer (ASAN) for memory error detection
          - UndefinedBehaviorSanitizer (UBSan) for undefined behavior
          - ThreadSanitizer (TSan) for data race detection
          - MemorySanitizer (MSan) for uninitialized memory
          - Efficient edge instrumentation with self-removing hooks
          - DEP (Data Execution Prevention) support
        },
        'Author' => [
          'Metasploit Python Native Team'
        ],
        'License' => MSF_LICENSE,
        'References' => [
          ['URL', 'https://clang.llvm.org/docs/AddressSanitizer.html'],
          ['URL', 'https://clang.llvm.org/docs/UndefinedBehaviorSanitizer.html'],
          ['URL', 'https://frida.re/docs/home/']
        ],
        'DisclosureDate' => '2024-11-22',
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [ARTIFACTS_ON_DISK],
          'Reliability' => [REPEATABLE_SESSION]
        }
      )
    )

    register_options(
      [
        OptPath.new('INPUT_BINARY', [true, 'Path to input binary or source file']),
        OptPath.new('OUTPUT_PATH', [true, 'Path for instrumented output']),
        OptEnum.new('MODE', [true, 'Instrumentation mode', 'frida', 
                    ['llvm', 'frida', 'patch']]),
        OptString.new('SANITIZERS', [false, 'Comma-separated list of sanitizers (asan,ubsan,msan,tsan,lsan)', 'asan']),
        OptBool.new('EDGE_INSTRUMENTATION', [true, 'Enable efficient edge instrumentation with auto-removal', true]),
        OptBool.new('VERBOSE', [false, 'Enable verbose output', false])
      ]
    )
  end

  def run
    print_status("Starting LLVM/libfuzzrt binary instrumentation")
    
    input_path = datastore['INPUT_BINARY']
    output_path = datastore['OUTPUT_PATH']
    mode = datastore['MODE']
    sanitizers = datastore['SANITIZERS']
    verbose = datastore['VERBOSE']
    edge_inst = datastore['EDGE_INSTRUMENTATION']

    # Validate input file
    unless File.exist?(input_path)
      print_error("Input file not found: #{input_path}")
      return
    end

    # Build command for Python instrumentation tool
    script_path = File.join(
      Msf::Config.install_root,
      'lib', 'msf', 'util', 'llvm_instrumentation.py'
    )

    unless File.exist?(script_path)
      print_error("LLVM instrumentation script not found: #{script_path}")
      return
    end

    cmd = ['python3', script_path]
    cmd << input_path
    cmd << '-o' << output_path
    cmd << '-m' << mode

    # Add sanitizers
    sanitizers.split(',').each do |san|
      san = san.strip
      cmd << '-s' << san
    end

    cmd << '-v' if verbose

    print_status("Running: #{cmd.join(' ')}")

    begin
      # Use system with array form to avoid command injection
      require 'open3'
      output, status = Open3.capture2e(*cmd)

      if verbose || status.exitstatus != 0
        print_line(output)
      end

      if status.exitstatus == 0
        print_good("Instrumentation successful!")
        print_good("Output: #{output_path}")
        
        # If in Frida mode, provide usage instructions
        if mode == 'frida'
          print_status("To use the Frida script:")
          print_status("  frida -l #{output_path} -f /path/to/target")
          print_status("  or")
          print_status("  frida -l #{output_path} -n target_process")
        else
          # Extract and display sanitizer options
          if output =~ /Runtime options: (.+)$/
            print_status("Sanitizer runtime options:")
            print_status("  #{$1}")
          end
        end

        # Display edge instrumentation info
        if edge_inst
          print_status("Edge instrumentation: ENABLED")
          print_status("  Hooks will auto-remove after first hit for efficiency")
        end
      else
        print_error("Instrumentation failed with exit code: #{status}")
      end
    rescue => e
      print_error("Error running instrumentation: #{e.message}")
      print_error(e.backtrace.join("\n")) if verbose
    end
  end
end
