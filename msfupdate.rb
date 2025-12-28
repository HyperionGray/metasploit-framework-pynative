#!/usr/bin/env ruby
# -*- coding: binary -*-
#
# $Id$
#
# This keeps the framework up-to-date
#
# $Revision$
#

# Show informational message about Python alternatives (unless quiet mode)
unless ENV['MSF_QUIET'] || ARGV.include?('-q')
  $stderr.puts "\n" + "="*70
  $stderr.puts "  MsfUpdate - Framework Updater (Legacy Ruby Version)"
  $stderr.puts "="*70
  $stderr.puts "  NOTE: This is the legacy Ruby version."
  $stderr.puts "  For the primary Python-native experience, use:"
  $stderr.puts "    python3 msfupdate.py"
  $stderr.puts "="*70 + "\n"
end

msfbase = __FILE__
while File.symlink?(msfbase)
  msfbase = File.expand_path(File.readlink(msfbase), File.dirname(msfbase))
end

class Msfupdate
  attr_reader :stdin
  attr_reader :stdout
  attr_reader :stderr

  def initialize(msfbase_dir, stdin = $stdin, stdout = $stdout, stderr = $stderr)
    @msfbase_dir = msfbase_dir
    @stdin = stdin
    @stdout = stdout
    @stderr = stderr
    @git_branch = nil
    @git_remote = nil
    @offline_file = nil
    @actually_wait = nil
  end

  def parse_args(args)
    args = args.dup
    
    while args.length > 0
      arg = args.shift
      
      case arg
      when '--help', '-h'
        usage
        exit(0)
      when /^--git-branch=(.*)$/
        @git_branch = $1
      when '--git-branch'
        @git_branch = args.shift
      when /^--git-remote=(.*)$/
        @git_remote = $1
      when '--git-remote'
        @git_remote = args.shift
      when /^--offline-file=(.*)$/
        @offline_file = File.expand_path($1)
      when '--offline-file'
        @offline_file = File.expand_path(args.shift)
      when 'wait'
        @actually_wait = true
      when 'nowait'
        @actually_wait = false
      end
    end
  end

  def usage
    @stdout.puts "Usage: #{$0} [options] [wait|nowait]"
    @stdout.puts ""
    @stdout.puts "Options:"
    @stdout.puts "  --git-branch <branch>   Update to a specific git branch"
    @stdout.puts "  --git-remote <remote>   Update from a specific git remote"
    @stdout.puts "  --offline-file <file>   Update from an offline file"
    @stdout.puts "  --help, -h              Show this help message"
    @stdout.puts ""
    @stdout.puts "Arguments:"
    @stdout.puts "  wait                    Wait for user input before exiting"
    @stdout.puts "  nowait                  Don't wait for user input before exiting"
  end

  def validate_args
    if apt?
      # APT installations don't support git or offline options
      return false if @git_branch || @git_remote || @offline_file
    elsif binary_install?
      # Binary installations support offline files but not git options
      return false if @git_branch || @git_remote
    elsif git?
      # Git installations support git options but not offline files
      return false if @offline_file
    end
    
    true
  end

  def run!
    return maybe_wait_and_exit unless validate_args
    
    if binary_install?
      update_binary_install!
    elsif git?
      update_git!
    end
  end

  def apt?
    File.exist?(File.join(@msfbase_dir, '.apt'))
  end

  def binary_install?
    engine_dir = File.join(@msfbase_dir, '..', 'engine')
    File.exist?(File.join(engine_dir, 'update.rb'))
  end

  def git?
    File.exist?(File.join(@msfbase_dir, '.git'))
  end

  def update_binary_install!
    @stdout.puts "Updating binary installation..."
    # Implementation would go here for binary updates
  end

  def update_git!
    @stdout.puts "Updating git installation..."
    # Implementation would go here for git updates
  end

  def maybe_wait_and_exit
    if @actually_wait
      @stdout.print "Press any key to exit..."
      @stdin.gets
    end
    exit(1)
  end
end

if __FILE__ == $0
  updater = Msfupdate.new(File.dirname(msfbase))
  updater.parse_args(ARGV)
  updater.run!
end