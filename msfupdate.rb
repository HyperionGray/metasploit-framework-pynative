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
      when '--help'
        usage
        exit(0)
      when '--git-branch'
        @git_branch = args.shift || args.shift if args.first&.start_with?('=')
      when /--git-branch=(.*)/
        @git_branch = $1
      when '--git-remote'
        @git_remote = args.shift || args.shift if args.first&.start_with?('=')
      when /--git-remote=(.*)/
        @git_remote = $1
      when '--offline-file'
        file = args.shift || args.shift if args.first&.start_with?('=')
        @offline_file = File.absolute_path(file) if file
      when /--offline-file=(.*)/
        @offline_file = File.absolute_path($1)
      when 'wait'
        @actually_wait = true
      when 'nowait'
        @actually_wait = false
      end
    end
  end

  def run!
    return maybe_wait_and_exit(1) unless validate_args

    if binary_install?
      update_binary_install!
    elsif git?
      update_git!
    end
  end

  def validate_args
    if apt?
      return false if @git_remote || @git_branch || @offline_file
    elsif binary_install?
      return false if @git_remote || @git_branch
    elsif git?
      return false if @offline_file
    end
    true
  end

  def usage
    @stdout.puts "Usage: msfupdate [options]"
    @stdout.puts "Options:"
    @stdout.puts "  --help                Show this help message"
    @stdout.puts "  --git-branch BRANCH   Git branch to update to"
    @stdout.puts "  --git-remote REMOTE   Git remote to update from"
    @stdout.puts "  --offline-file FILE   Offline update file"
    @stdout.puts "  wait                  Wait for user input"
    @stdout.puts "  nowait                Don't wait for user input"
  end

  def maybe_wait_and_exit(code = 0)
    if @actually_wait
      @stdout.puts "Press any key to continue..."
      @stdin.gets
    end
    exit(code)
  end

  def update_binary_install!
    @stdout.puts "Updating binary installation..."
  end

  def update_git!
    @stdout.puts "Updating git installation..."
  end

  def apt?
    File.exist?(File.join(@msfbase_dir, '.apt'))
  end

  def binary_install?
    File.exist?(File.join(@msfbase_dir, '..', 'engine', 'update.rb'))
  end

  def git?
    File.exist?(File.join(@msfbase_dir, '.git'))
  end
end