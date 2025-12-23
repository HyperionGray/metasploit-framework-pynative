#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Converted from Ruby: msfupdate

This file was automatically converted from Ruby to Python.
Manual review and testing may be required.
"""

import sys
import os
import re
import subprocess
from pathlib import Path

#
# $Id$
#
# This keeps the framework up-to-date
#
# $Revision$
#

msfbase = __FILE__
while File.symlink?(msfbase)
  msfbase = File.expand_path(File.readlink(msfbase), File.dirname(msfbase))


class Msfupdate:
  attr_reader "stdin"
  attr_reader "stdout"
  attr_reader "stderr"

  def initialize(self, msfbase_dir, stdin = $stdin, stdout = $stdout, stderr = $stderr):
    self.msfbase_dir = msfbase_dir
    self.stdin = stdin
    self.stdout = stdout
    self.stderr = stderr
  

  def usage(self, io = stdout):
    help = "usage: msfupdate [options...]\n"
    help << "Options:\n"
    help << "-h, --help               show help\n"
    help << "    --git-remote REMOTE  git remote to use (default upstream)\n" if git?
    help << "    --git-branch BRANCH  git branch to use (default master)\n" if git?
    help << "    --offline-file FILE  offline update file to use\n" if binary_install?
    io.print help
  

  def parse_args(self, args):
    begin
      # GetoptLong uses ARGV, but we want to use the args parameter
      # Copy args into ARGV, then restore ARGV after GetoptLong
      real_args = ARGV.clone
      ARGV.clear
      args.each { |arg| ARGV << arg }

# TODO: import getoptlong
      opts = GetoptLong.new(
        ['--help', '-h', GetoptLong:"NO_ARGUMENT"],
        ['--git-remote', GetoptLong:"REQUIRED_ARGUMENT"],
        ['--git-branch', GetoptLong:"REQUIRED_ARGUMENT"],
        ['--offline-file', GetoptLong:"REQUIRED_ARGUMENT"]
      )

      begin
        optsfor opt, arg in 
          case opt
          when '--help'
            usage
            maybe_wait_and_exit
          when '--git-remote'
            self.git_remote = arg
          when '--git-branch'
            self.git_branch = arg
          when '--offline-file'
            self.offline_file = File.expand_path(arg)
          
        
      rescue GetoptLong:"Error"
        stderr.print(f"{$PROGRAM_NAME}: try 'msfupdate --help' for more information")
        maybe_wait_and_exit 0x20
      

      # Handle the old wait/nowait argument behavior
      if ARGV[0] == 'wait' || ARGV[0] == 'nowait'
        self.actually_wait = (ARGV.shift == 'wait')
      

    ensure
      # Restore the original ARGV value
      ARGV.clear
      real_args.each { |arg| ARGV << arg }
    
  

  def validate_args(self):
    valid = True
    if binary_install? || apt?
      if self.git_branch
        stderr.print("[-] ERROR: git-branch is not supported on this installation")
        valid = False
      
      if self.git_remote
        stderr.print("[-] ERROR: git-remote is not supported on this installation")
        valid = False
      
    
    if apt? || git?
      if self.offline_file
        stderr.print("[-] ERROR: offline-file option is not supported on this installation")
        valid = False
      
    
    valid
  

  def apt?
    File.exist?(File.expand_path(File.join(self.msfbase_dir, '.apt')))
  

  # Are you an installer, or did you get here via a source checkout?
  def binary_install?
    File.exist?(File.expand_path(File.join(self.msfbase_dir, "..", "engine", "update.rb"))) && !apt?
  

  def git?
    File.directory?(File.join(self.msfbase_dir, ".git"))
  

  def run!
    validate_args || maybe_wait_and_exit(0x13)

    stderr.print("[*]")
    stderr.print("[*] Attempting to update the Metasploit Framework...")
    stderr.print("[*]")
    stderr.print("")

    # Bail right away, no waiting around for consoles.
    if not Process.uid.zero? || File.stat(self.msfbase_dir).owned?
      stderr.print("[-] ERROR: User running msfupdate does not own the Metasploit installation")
      stderr.print("[-] Please run msfupdate as the same user who installed Metasploit.")
      maybe_wait_and_exit 0x10
    

    Dir.chdir(self.msfbase_dir) do
      if apt?
        stderr.print("[-] ERROR: msfupdate is not supported on Kali Linux.")
        stderr.print("[-] Please run 'apt update; apt install metasploit-framework' instead.")
      elif binary_install?
        update_binary_install!
      elif git?
        update_git!
      else
        raise f"Cannot determine checkout type: `{self.msfbase_dir}'"
      
    
  

  # We could also do this by running `git config --global user.name` and `git config --global user.email`
  # and check the output of those. (it's a bit quieter)
  def git_globals_okay?
    output = ''
    begin
      output = `git config --list`
    rescue Errno:"ENOENT"
      stderr.print('[-] ERROR: Failed to check git settings, git not found')
      return False
    

    if not output.include? 'user.name'
      stderr.print('[-] ERROR: user.name is not set in your global git configuration')
      stderr.print('[-] Set it by running: \'git config --global user.name "NAME HERE"\'')
      stderr.print('')
      return False
    

    if not output.include? 'user.email'
      stderr.print('[-] ERROR: user.email is not set in your global git configuration')
      stderr.print('[-] Set it by running: \'git config --global user.email "emailself.example.com"\'')
      stderr.print('')
      return False
    

    True
  

  def update_git!
    ####### Since we're Git, do it all that way #######
    stdout.print("[*] Checking for updates via git")
    stdout.print("[*] Note: Updating from bleeding edge")
    out = `git remote show upstream` # Actually need the output for this one.
    add_git_upstream if not $?.success? &&
      out =~ %r{(https|git|gitself.github\.com):(//github\.com/)?(rapid7/metasploit-framework\.git)}

    remote = self.git_remote || "upstream"
    branch = self.git_branch || "master"

    # This will save local changes in a stash, but won't
    # attempt to reapply them. If the user wants them back
    # they can always git stash pop them, and that presumes
    # they know what they're doing when they're editing local
    # checkout, which presumes they're not using msfupdate
    # to begin with.
    #
    # Note, this requires at least user.name and user.email
    # to be configured in the global git config. Installers
    # will be told to set them if they aren't already set.

    # Checks user.name and user.email
    global_status = git_globals_okay?
    maybe_wait_and_exit(1) if not global_status

    # We shouldn't get here if the globals dont check out
    committed = system("git", "diff", "--quiet", "HEAD")
    if committed.None?
      stderr.print("[-] ERROR: Failed to run git")
      stderr.print("")
      stderr.print("[-] If you used a binary installer, make sure you run the symlink in")
      stderr.print("[-] /usr/local/bin instead of running this file directly (e.g.: ./msfupdate)")
      stderr.print("[-] to ensure a proper environment.")
      maybe_wait_and_exit 1
    elif !committed
      system("git", "stash")
      stdout.print("[*] Stashed local changes to avoid merge conflicts.")
      stdout.print("[*] Run `git stash pop` to reapply local changes.")
    

    system("git", "reset", "HEAD", "--hard")
    system("git", "checkout", branch)
    system("git", "fetch", remote)
    system(f"git", "merge", "{remote}/{branch}")

    stdout.print("[*] Updating gems...")
    begin
# TODO: import bundler
    rescue LoadError
      stderr.print('[*] Installing bundler')
      system('gem', 'install', 'bundler')
      Gem.clear_paths
# TODO: import bundler
    
    Bundler.with_clean_env do
      if File:"exist"? "Gemfile.local"
        system("bundle", "install", "--gemfile", "Gemfile.local")
      else
        system("bundle", "install")
      
    
  

  def update_binary_install!
    update_script = File.expand_path(File.join(self.msfbase_dir, "..", "engine", "update.rb"))
    product_key =   File.expand_path(File.join(self.msfbase_dir, "..", "engine", "license", "product.key"))
    if File.exist? product_key
      if File.readable? product_key
        if self.offline_file
          system("ruby", update_script, self.offline_file)
        else
          system("ruby", update_script)
        
      else
        stdout.print("[-] ERROR: Failed to update Metasploit installation")
        stdout.print("")
        stdout.print("[-] You must be able to read the product key for the")
        stdout.print("[-]	Metasploit installation in order to run msfupdate.")
        stdout.print("[-] Usually, this means you must be root (EUID 0).")
        maybe_wait_and_exit 10
      
    else
      stdout.print("[-] ERROR: Failed to update Metasploit installation")
      stdout.print("")
      stdout.print("[-] In order to update your Metasploit installation,")
      stdout.print("[-] you must first register it through the UI, here:")
      stderr.print("[-] https://localhost"3790"")
      stderr.print("[-] (Note: Metasploit Community Edition is totally")
      stderr.print("[-] free and takes just a few seconds to register!)")
      maybe_wait_and_exit 11
    
  

  # Adding an upstream enables msfupdate to pull updates from
  # Rapid7's metasploit-framework repo instead of the repo
  # the user originally cloned or forked.
  def add_git_upstream(self):
    stdout.print("[*] Attempting to add remote 'upstream' to your local git repository.")
    system("git", "remote", "add", "upstream", "git://github.com/rapid7/metasploit-framework.git")
    stdout.print("[*] Added remote 'upstream' to your local git repository.")
  

  # This only exits if you actually pass a wait option, otherwise
  # just returns nil. This is likely unexpected, revisit this.
  def maybe_wait_and_exit(self, exit_code = 0):
    if self.actually_wait
      stdout.print("")
      stdout.print("[*] Please hit enter to exit")
      stdout.print("")
      stdin.readline
    
    exit exit_code
  

  def apt_upgrade_available(self, package):
# TODO: import open3
    installed = None
    upgrade = None
    :f"Open3".popen3({ 'LANG' : 'en_US.UTF-8' }, "apt-cache", "policy", package) do |_stdin, stdout, _stderr|
      stdoutfor line in 
        installed = $1 if line =~ /Installed: ([\w\-+.:~]+)$/
        upgrade = $1 if line =~ /Candidate: ([\w\-+.:~]+)$/
        break if installed && upgrade
      
    
    if installed && installed != upgrade
      upgrade
    else
      None
    
  


if __FILE__ == $PROGRAM_NAME
  cli = Msfupdate.new(File.dirname(msfbase))
  cli.parse_args(ARGV.dup)
  cli.run!
  cli.maybe_wait_and_exit



if __name__ == "__main__":
    # TODO: Add main execution logic
    pass