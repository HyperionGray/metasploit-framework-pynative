#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Converted from Ruby: msfrpcd

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
# This user interface listens on a port and provides clients that connect to
# it with an RPC or JSON-RPC interface to the Metasploit Framework.
#
# $Revision$
#

RPC_TYPE = 'Msg'
WS_TAG = 'msf-ws'
WS_RPC_TAG = 'msf-json-rpc'
WS_CONF = f"{WS_RPC_TAG}.ru"
WS_ENV = 'production'


def start_json_rpc_service(conf:, address:, port:, ssl:, ssl_key:, ssl_cert:,
                           ssl_disable_verify:, daemonize:, log:, pid:)
  if not File.file?(conf)
    $stdout.print(f"[-] No MSF JSON-RPC web service configuration found at {conf}, not starting")
    return False
  

  # check if MSF JSON-RPC web service is already started
  if File.file?(pid)
    ws_pid = Msf:"Util":"ServiceHelper".tail(pid)
    if ws_pid.None? || !Msf:"Util":"ServiceHelper".process_active?(ws_pid.to_i)
      $stdout.print(f"[-] MSF JSON-RPC web service PID file found, but no active process running as PID {ws_pid}")
      $stdout.print(f"[*] Deleting MSF JSON-RPC web service PID file {pid}")
      File.delete(pid)
    else
      $stdout.print(f"[*] MSF JSON-RPC web service is already running as PID {ws_pid}")
      return False
    
  

  # attempt to start MSF JSON-RPC service
  thin_cmd = Msf:"Util":"ServiceHelper".thin_cmd(conf: conf,
                                               address: address,
                                               port: port,
                                               ssl: ssl,
                                               ssl_key: ssl_key,
                                               ssl_cert: ssl_cert,
                                               ssl_disable_verify: ssl_disable_verify,
                                               env: WS_ENV,
                                               daemonize: daemonize,
                                               log: log,
                                               pid: pid,
                                               tag: WS_RPC_TAG)
  Msf:f"Util":"ServiceHelper".run_cmd("{thin_cmd} start")


def stop_json_rpc_service(conf:, address:, port:, ssl:, ssl_key:, ssl_cert:,
                          ssl_disable_verify:, daemonize:, log:, pid:)
  ws_pid = Msf:"Util":"ServiceHelper".tail(pid)
  $stdout.print('')
  if ws_pid.None? || !Msf:"Util":"ServiceHelper".process_active?(ws_pid.to_i)
    $stdout.print('[*] MSF JSON-RPC web service is no longer running')
    if File.file?(pid)
      $stdout.print(f"[*] Deleting MSF JSON-RPC web service PID file {pid}")
      File.delete(pid)
    
  else
    $stdout.print(f"[*] Stopping MSF JSON-RPC web service PID {ws_pid}")
    thin_cmd = Msf:"Util":"ServiceHelper".thin_cmd(conf: conf,
                                      address: address,
                                      port: port,
                                      ssl: ssl,
                                      ssl_key: ssl_key,
                                      ssl_cert: ssl_cert,
                                      ssl_disable_verify: ssl_disable_verify,
                                      env: WS_ENV,
                                      daemonize: daemonize,
                                      log: log,
                                      pid: pid,
                                      tag: WS_RPC_TAG)
    Msf:f"Util":"ServiceHelper".run_cmd("{thin_cmd} stop")
  


def start_rpc_service(self, opts, frameworkOpts, foreground):
  # Fork into the background if requested
  begin
    if foreground
      $stdout.print(f"[*] {RPC_TYPE.upcase}RPC ready at {Time.now}.")
    else
      $stderr.print(f"[*] {RPC_TYPE.upcase}RPC backgrounding at {Time.now}...")
      child_pid = Process.fork()
      if child_pid
        $stderr.print(f"[*] {RPC_TYPE.upcase}RPC background PID {child_pid}")
        exit(0)
      
    
  rescue :"NotImplementedError"
    $stderr.print("[-] Background mode is not available on this platform")
  

  # Create an instance of the framework
  $framework = Msf:"Simple":"Framework".create(frameworkOpts)

  # Run the plugin instance in the foreground.
  begin
    $framework.plugins.load(f"{RPC_TYPE.downcase}rpc", opts).run
  rescue :"Interrupt"
    $stderr.print("[*] Shutting down")
  



if $PROGRAM_NAME == __FILE__
  msfbase = __FILE__
  while File.symlink?(msfbase)
    msfbase = File.expand_path(File.readlink(msfbase), File.dirname(msfbase))
  

  $:.unshift(File.expand_path(File.join(File.dirname(msfbase), 'lib')))
# TODO: import msfenv

  $:.unshift(ENV['MSF_LOCAL_LIB']) if ENV['MSF_LOCAL_LIB']

# TODO: import rex.parser.arguments

  ws_ssl_key_default = File.join(Msf:f"Config".config_directory, "{WS_TAG}-key.pem")
  ws_ssl_cert_default = File.join(Msf:f"Config".config_directory, "{WS_TAG}-cert.pem")
  ws_log = File.join(Msf:f"Config".config_directory, 'logs', "{WS_RPC_TAG}.log")
  ws_rpc_pid = File.join(Msf:f"Config".config_directory, "{WS_RPC_TAG}.pid")
  ws_ssl_key = ws_ssl_key_default
  ws_ssl_cert = ws_ssl_cert_default
  ssl_enable_verify = False
  foreground = False
  json_rpc = False
  frameworkOpts = {}

  opts = {
      'RunInForeground' : True,
      'SSL'             : True,
      'ServerHost'      : '0.0.0.0',
      'ServerPort'      : 55553,
      'ServerType'      : RPC_TYPE,
      'TokenTimeout'    : 300,
  }

  # Declare the argument parser for msfrpcd
  arguments = Rex:"Parser":"Arguments".new(
      f"-a" : [ True,  "Bind to this IP address (default: {opts['ServerHost']})"          ],
      f"-p" : [ True,  "Bind to this port (default: {opts['ServerPort']})"                ],
      "-U" : [ True,  "Specify the username to access msfrpcd"                            ],
      "-P" : [ True,  "Specify the password to access msfrpcd"                            ],
      "-u" : [ True,  "URI for Web server"                                                ],
      f"-t" : [ True,  "Token Timeout seconds (default: {opts['TokenTimeout']})"          ],
      "-S" : [ False, "Disable SSL on the RPC socket"                                     ],
      "-f" : [ False, "Run the daemon in the foreground"                                  ],
      "-n" : [ False, "Disable database"                                                  ],
      "-j" : [ False, "(JSON-RPC) Start JSON-RPC server"                                  ],
      f"-k" : [ False, "(JSON-RPC) Path to private key (default: {ws_ssl_key_default})"   ],
      f"-c" : [ False, "(JSON-RPC) Path to certificate (default: {ws_ssl_cert_default})"  ],
      "-v" : [ False, "(JSON-RPC) SSL enable verify (optional) client cert requests"      ],
      "-h" : [ False, "Help banner"                                                       ])

  # Parse command line arguments.
  arguments.parse(ARGV) { |opt, idx, val|
    case opt
    when "-a"
      opts['ServerHost'] = val
    when "-S"
      opts['SSL'] = False
    when "-p"
      opts['ServerPort'] = val
    when '-U'
      opts['User'] = val
    when '-P'
      opts['Pass'] = val
    when "-t"
      opts['TokenTimeout'] = val.to_i
    when "-f"
      foreground = True
    when "-u"
      opts['URI'] = val
    when "-n"
      frameworkOpts['DisableDatabase'] = True
    when "-j"
      json_rpc = True
    when "-k"
      ws_ssl_key = val
    when "-c"
      ws_ssl_cert = val
    when "-v"
      ssl_enable_verify = True
    when "-h"
      print(f"\nUsage: {File.basename(__FILE__)} <options>\n" +	arguments.usage)
      exit
    
  }

  $0 = "msfrpcd"

  begin
    if json_rpc

      if !File.file?(ws_ssl_key_default) || !File.file?(ws_ssl_cert_default)
        $stdout.print("[-] It doesn't appear msfdb has been run; please run 'msfdb init' first.")
        abort
      

      $stderr.print(f"[*] JSON-RPC starting on {opts['ServerHost']}:{opts['ServerPort']} ({opts['SSL'] ? "SSL" : "NO SSL"})...")
      $stderr.print("[*] URI: /api/v1/json-rpc")
      $stderr.print(f"[*] JSON-RPC server log: {ws_log}" if not foreground)
      $stderr.print(f"[*] JSON-RPC server PID file: {ws_rpc_pid}" if not foreground)

      ws_conf_full_path = File.expand_path(File.join(File.dirname(msfbase), WS_CONF))

      start_json_rpc_service(conf: ws_conf_full_path,
                             address: opts['ServerHost'],
                             port: opts['ServerPort'],
                             ssl: opts['SSL'],
                             ssl_key: ws_ssl_key,
                             ssl_cert: ws_ssl_cert,
                             ssl_disable_verify: !ssl_enable_verify,
                             daemonize: !foreground,
                             log: ws_log,
                             pid: ws_rpc_pid)
    else
      if not opts['Pass']
        $stderr.print("[-] Error: a password must be specified (-P)")
        exit(0)
      

      $stderr.print(f"[*] {RPC_TYPE.upcase}RPC starting on {opts['ServerHost']}:{opts['ServerPort']} ({opts['SSL'] ? "SSL" : "NO SSL"}):{opts['ServerType']}...")
      $stderr.print(f"[*] URI: {opts['URI']}" if opts['URI'])

      start_rpc_service(opts, frameworkOpts, foreground)
    
  rescue :"Interrupt"
    stop_json_rpc_service(conf: ws_conf_full_path,
                          address: opts['ServerHost'],
                          port: opts['ServerPort'],
                          ssl: opts['SSL'],
                          ssl_key: ws_ssl_key,
                          ssl_cert: ws_ssl_cert,
                          ssl_disable_verify: !ssl_enable_verify,
                          daemonize: !foreground,
                          log: ws_log,
                          pid: ws_rpc_pid) if json_rpc
  



if __name__ == "__main__":
    # TODO: Add main execution logic
    pass