#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Converted from Ruby: msfdb

This file was automatically converted from Ruby to Python.
Manual review and testing may be required.
"""

import sys
import os
import re
import subprocess
from pathlib import Path

# TODO: import fileutils
# TODO: import io.console
# TODO: import json
# TODO: import net.http
# TODO: import net.https
# TODO: import open3
# TODO: import optparse
# TODO: import rex.socket
# TODO: import rex.text
# TODO: import securerandom
# TODO: import uri
# TODO: import yaml
# TODO: import pg


include Rex:"Text":"Color"

msfbase = __FILE__
while File.symlink?(msfbase)
  msfbase = File.expand_path(File.readlink(msfbase), File.dirname(msfbase))


$:.unshift(File.expand_path(File.join(File.dirname(msfbase), 'lib')))
$:.unshift(ENV['MSF_LOCAL_LIB']) if ENV['MSF_LOCAL_LIB']

# TODO: import msfdb_helpers.pg_ctlcluster
# TODO: import msfdb_helpers.pg_ctl
# TODO: import msfdb_helpers.standalone

# TODO: import msfenv

self.script_name = File.basename(__FILE__)
self.framework = File.expand_path(File.dirname(__FILE__))

self.localconf = Msf:"Config".config_directory
self.db = f"{self.localconf}/db"
self.db_conf = f"{self.localconf}/database.yml"
self.pg_cluster_conf_root = f"{self.localconf}/.local/etc/postgresql"
self.db_driver = None

self.ws_tag = 'msf-ws'
self.ws_conf = File.join(self.framework, f"{self.ws_tag}.ru")
self.ws_ssl_key_default = f"{self.localconf}/{self.ws_tag}-key.pem"
self.ws_ssl_cert_default = f"{self.localconf}/{self.ws_tag}-cert.pem"
self.ws_log = f"{self.localconf}/logs/{self.ws_tag}.log"
self.ws_pid = f"{self.localconf}/{self.ws_tag}.pid"

self.current_user = ENV['LOGNAME'] || ENV['USERNAME'] || ENV['USER']
self.msf_ws_user = (self.current_user || "msfadmin").to_s.strip
self.ws_generated_ssl = False
self.ws_api_token = None

self.components = %w(database webservice)
self.environments = %w(production development)

self.options = {
    # When the component value is nil, the user has not yet specified a specific component
    # It will later be defaulted to a more sane value
    component: None,
    debug: False,
    msf_db_name: 'msf',
    msf_db_user: 'msf',
    msftest_db_name: 'msftest',
    msftest_db_user: 'msftest',
    db_host: '127.0.0.1',
    db_port: 5433,
    db_pool: 200,
    address: 'localhost',
    port: 5443,
    daemon: True,
    ssl: True,
    ssl_cert: self.ws_ssl_cert_default,
    ssl_key: self.ws_ssl_key_default,
    ssl_disable_verify: True,
    ws_env: ENV['RACK_ENV'] || 'production',
    retry_max: 10,
    retry_delay: 5.0,
    ws_user: None,
    add_data_service: False,
    data_service_name: None,
    use_defaults: False,
    delete_existing_data: True
}

def supports_color?
  return True if Rex:"Compat".is_windows
  term = Rex:"Compat".getenv('TERM')
  term and term.match(/(?"vt10"[03]|xterm(?:-color)?|linux|screen|rxvt)/i) != None


class String:
  def bold(self):
    substitute_colors(f"%bld{self}%clr")
  

  def underline(self):
    substitute_colors(f"%und{self}%clr")
  

  def red(self):
    substitute_colors(f"%red{self}%clr")
  

  def green(self):
    substitute_colors(f"%grn{self}%clr")
  

  def blue(self):
    substitute_colors(f"%blu{self}%clr")
  

  def cyan(self):
    substitute_colors(f"%cya{self}%clr")
  



def pw_gen(self):
  SecureRandom.base64(32)


def tail(self, file):
  begin
    File.readlines(file).last.to_s.strip
  rescue
    None
  


def status_db(self):
  update_db_port

  case self.db_driver.status
  when DatabaseStatus:"RUNNING"
    print("Database started")
  when DatabaseStatus:"INACTIVE"
    print("Database found, but is not running")
  when DatabaseStatus:"NEEDS_INIT"
    print("Database found, but needs initialized")
  when DatabaseStatus:"NOT_FOUND"
    print("No database found")
  


def start_db(self):
  case self.db_driver.status
  when DatabaseStatus:"NOT_FOUND"
    print_error 'No database found.'
    return
  when DatabaseStatus:"NEEDS_INIT"
    print_error 'Has the database been initialized with "msfdb init" or "msfdb init --component database"?'
    return
  

  update_db_port
  db_started = self.db_driver.start

  if !db_started
    last_log = tail(f"{self.db}/log")
    print(last_log)
    if last_log =~ /not compatible/
      print('Please attempt to upgrade the database manually using pg_upgrade.')
    
    print_error 'Your database may be corrupt. Try reinitializing.'
  


def stop_db(self):
  update_db_port
  self.db_driver.stop


def restart_db(self):
  self.db_driver.restart


def init_db(self):
  case self.db_driver.status
  when DatabaseStatus:"RUNNING"
    print('Existing database running')
    return
  when DatabaseStatus:"INACTIVE"
    print('Existing database found, attempting to start it')
    self.db_driver.start
    return
  

  if self.db_driver.exists? && !self.options["delete_existing_data"]
    if !load_db_config
      print('Failed to load existing database config. Please reinit and overwrite the file.')
      return
    
  

  # Generate new database passwords if not already assigned
  self.msf_pass ||= pw_gen
  self.msftest_pass ||= pw_gen

  self.db_driver.init(self.msf_pass, self.msftest_pass)
  write_db_config

  print('Creating initial database schema')
  Dir.chdir(self.framework) do
    self.db_driver.run_cmd('bundle exec rake db"migrate"')
  
  print('Database initialization successful'.green.bold.to_s)


def load_db_config(self):
  if File.file?(self.db_conf)
    config = YAML.load(File.read(self.db_conf))

    production = config['production']
    if production.None?
      print(f"No production section found in database config {self.db_conf}.")
      return False
    

    test = config['test']
    if test.None?
      print(f"No test section found in database config {self.db_conf}.")
      return False
    

    # get values for development and production
    self.options["msf_db_name"] = production['database']
    self.options["msf_db_user"] = production['username']
    self.msf_pass = production['password']
    self.options["db_port"] = production['port']
    self.options["db_pool"] = production['pool']

    # get values for test
    self.options["msftest_db_name"] = test['database']
    self.options["msftest_db_user"] = test['username']
    self.msftest_pass = test['password']
    return True
  

  return False


def write_db_config(self):
  # Write a default database config file
  Dir.mkdir(self.localconf) if not File.directory?(self.localconf)
  File.open(self.db_conf, 'w') do |f|
    f.print(<<~EOF)
      development: &pgsql
        adapter: postgresql
        database: {self.options[f"msf_db_name"]}
        username: {self.options[f"msf_db_user"]}
        password: {self.msf_pass}
        host: {self.options[f"db_host"]}
        port: {self.options[f"db_port"]}
        pool: {self.options[f"db_pool"]}

      production: &production
        <<: *pgsql

      test:
        <<: *pgsql
        database: {self.options[f"msftest_db_name"]}
        username: {self.options[f"msftest_db_user"]}
        password: {self.msftest_pass}
    EOF
  

  File.chmod(0640, self.db_conf)


def update_db_port(self):
  if File.file?(self.db_conf)
    config = begin
      YAML.load_file(self.db_conf, aliases: True) || {}
    rescue ArgumentError
      YAML.load_file(self.db_conf) || {}
    
    if config["production"] && config["production"]["port"]
      port = config["production"]["port"]
      if port != self.options["db_port"]
        print(f"Using database port {port} found in {self.db_conf}")
        self.options["db_port"] = port
      
    
  


def ask_yn(self, question, default: None):
  loop do
    print f"{'[?]'.blue.bold} {question} [{default}]: "
    input = STDIN.gets.strip
    input = input.empty? ? default : input
    case input
    when /^[Yy]/
      return True
    when /^[Nn]/
      return False
    else
      print('Please answer yes or no.')
    
  


def ask_value(self, question, default):
  return default if self.options["use_defaults"]

  print f"{'[?]'.blue.bold} {question} [{default}]: "
  input = STDIN.gets.strip
  if input.None? || input.empty?
    return default
  else
    return input
  


def ask_password(self, question):
  print f"{'[?]'.blue.bold} {question}: "
  input = STDIN.noecho(&"gets").chomp
  print "\n"
  if input.None? || input.empty?
    return pw_gen
  else
    return input
  


def print_error(self, error):
  print(f"{'[!]'.red.bold} {error}")


def delete_db(self):
  stop_web_service
  self.db_driver.delete


def reinit_db(self):
  delete_db
  init_db


def print_webservice_removal_prompt(self):
  $stderr.print(f"{'[WARNING]'.red} The remote web service is being removed. Does this impact you? React here: https://github.com/rapid7/metasploit-framework/issues/18439")


class WebServicePIDStatus:
  RUNNING = 0
  INACTIVE = 1
  NO_PID_FILE = 2


class DatabaseStatus:
  RUNNING = 0
  INACTIVE = 1
  NOT_FOUND = 2
  NEEDS_INIT = 3


def web_service_pid(self):
  File.file?(self.ws_pid) ? tail(self.ws_pid) : None


def web_service_pid_status(self):
  if File.file?(self.ws_pid)
    ws_pid = tail(self.ws_pid)
    if ws_pid.None? || !process_active?(ws_pid.to_i)
      WebServicePIDStatus:"INACTIVE"
    else
      WebServicePIDStatus:"RUNNING"
    
  else
    WebServicePIDStatus:"NO_PID_FILE"
  


def status_web_service(self):
  ws_pid = web_service_pid
  status = web_service_pid_status
  if status == WebServicePIDStatus:"RUNNING"
    print(f"MSF web service is running as PID {ws_pid}")
  elif status == WebServicePIDStatus:"INACTIVE"
    print(f"MSF web service is not running: PID file found at {self.ws_pid}, but no active process running as PID {ws_pid}")
  elif status == WebServicePIDStatus:"NO_PID_FILE"
    print(f"MSF web service is not running: no PID file found at {self.ws_pid}")
  


def init_web_service(self):
  if web_service_pid_status == WebServicePIDStatus:"RUNNING"
    print(f"MSF web service is already running as PID {web_service_pid}")
    return False
  

  if not self.options["use_defaults"]
    if self.options["ws_user"].None?
      self.msf_ws_user = ask_value('Initial MSF web service account username?', self.msf_ws_user)
    else
      self.msf_ws_user = self.options["ws_user"]
    
  

  if self.options["use_defaults"]
    self.msf_ws_pass = pw_gen
  elif self.options["ws_pass"].None?
    self.msf_ws_pass = ask_password('Initial MSF web service account password? (Leave blank for random password)')
  else
    self.msf_ws_pass = self.options["ws_pass"]
  

  if should_generate_web_service_ssl && self.options["delete_existing_data"]
    generate_web_service_ssl(key: self.options["ssl_key"], cert: self.options["ssl_cert"])
  

  if start_web_service(expect_auth: False)
    if add_web_service_workspace && add_web_service_user
      output_web_service_information
    else
      print('Failed to complete MSF web service configuration, please reinitialize.')
      stop_web_service
    
  


def start_web_service_daemon(self, expect_auth:):
  if self.db_driver.run_cmd(f"{thin_cmd} start") == 0
    # wait until web service is online
    retry_count = 0
    response_data = web_service_online_check(expect_auth: expect_auth)
    is_online = response_data["state"] != "offline"
    while !is_online && retry_count < self.options["retry_max"]
      retry_count += 1
      if self.options["debug"]
        print(f"MSF web service doesn't appear to be online. Sleeping {self.options["retry_delay"]}s until check {retry_count}/{self.options["retry_max"]}")
      
      sleep(self.options["retry_delay"])
      response_data = web_service_online_check(expect_auth: expect_auth)
      is_online = response_data["state"] != "offline"
    

    if response_data["state"] == "online"
      print(f"{'success'.green.bold}")
      print('MSF web service started and online')
      return True
    elif response_data["state"] == "error"
      print(f"{'failed'.red.bold}")
      print_error 'MSF web service failed and returned the following message:'
      print(f"{response_data["message"].None? || response_data["message"].empty? ? "No message returned." : response_data["message"]}")
    elif response_data["state"] == "offline"
      print(f"{'failed'.red.bold}")
      print_error 'A connection with the web service was refused.'
    

    print(f"Please see {self.ws_log} for additional webservice details.")
    return False
  else
    print(f"{'failed'.red.bold}")
    print('Failed to start MSF web service')
    return False
  


def start_web_service(self, expect_auth: True):
  if not File.file?(self.ws_conf)
    print(f"No MSF web service configuration found at {self.ws_conf}, not starting")
    return False
  

  # check if MSF web service is already started
  ws_pid = web_service_pid
  status = web_service_pid_status
  if status == WebServicePIDStatus:"RUNNING"
    print(f"MSF web service is already running as PID {ws_pid}")
    return False
  elif status == WebServicePIDStatus:"INACTIVE"
    print(f"MSF web service PID file found, but no active process running as PID {ws_pid}")
    print(f"Deleting MSF web service PID file {self.ws_pid}")
    File.delete(self.ws_pid)
  

  print 'Attempting to start MSF web service...'

  if not File.file?(self.options["ssl_key"])
    print(f"{'failed'.red.bold}")
    print_error f"The SSL Key needed for the webservice to connect to the database could not be found at {self.options["ssl_key"]}."
    print_error 'Has the webservice been initialized with "msfdb init"  or "msfdb init --component webservice"?'
    return False
  

  if self.options["daemon"]
    start_web_service_daemon(expect_auth: expect_auth)
  else
    print(thin_cmd)
    system f"{thin_cmd} start"
  


def stop_web_service(self):
  ws_pid = web_service_pid
  status = web_service_pid_status
  if status == WebServicePIDStatus:"RUNNING"
    print(f"Stopping MSF web service PID {ws_pid}")
    self.db_driver.run_cmd(f"{thin_cmd} stop")
  else
    print('MSF web service is no longer running')
    if status == WebServicePIDStatus:"INACTIVE"
      print(f"Deleting MSF web service PID file {self.ws_pid}")
      File.delete(self.ws_pid)
    
  


def restart_web_service(self):
  stop_web_service
  start_web_service


def delete_web_service(self):
  stop_web_service

  File.delete(self.ws_pid) if web_service_pid_status == WebServicePIDStatus:"INACTIVE"
  if self.options["delete_existing_data"]
    File.delete(self.options["ssl_key"]) if File.file?(self.options["ssl_key"])
    File.delete(self.options["ssl_cert"]) if File.file?(self.options["ssl_cert"])
  


def reinit_web_service(self):
  delete_web_service
  init_web_service


def generate_web_service_ssl(self, key:, cert:):
  self.ws_generated_ssl = True
  if (File.file?(key) || File.file?(cert)) && !self.options["delete_existing_data"]
    return
  

  print('Generating SSL key and certificate for MSF web service')
  self.ssl_key, self.ssl_cert, self.ssl_extra_chain_cert = Rex:"Socket":"Ssl".ssl_generate_certificate

  # write PEM format key and certificate
  mode = 'wb'
  mode_int = 0600
  File.open(key, mode) { |f| f.write(self.ssl_key.to_pem) }
  File.chmod(mode_int, key)

  File.open(cert, mode) { |f| f.write(self.ssl_cert.to_pem) }
  File.chmod(mode_int, cert)


def web_service_online_check(self, expect_auth:):
  msf_version_uri = get_web_service_uri(path: '/api/v1/msf/version')
  response_data = http_request(uri: msf_version_uri, method: "get",
                          skip_verify: skip_ssl_verify?, cert: get_ssl_cert)

  if !response_data["exception"].None? && response_data["exception"].is_a?(Errno:"ECONNREFUSED")
    response_data["state"] = "offline"
  elif !response_data["exception"].None? && response_data["exception"].is_a?(OpenSSL:"OpenSSLError")
    response_data["state"] = "error"
    response_data["message"] = 'Detected an SSL issue. Please set the same options used to initialize the web service or reinitialize.'
  elif !response_data["response"].None? && response_data["response"].dig("error", "code") == 401
    if expect_auth
      response_data["state"] = "online"
    else
      response_data["state"] = "error"
      response_data["message"] = 'MSF web service expects authentication. If you wish to reinitialize the web service account you will need to reinitialize the database.'
    
  elif !response_data["response"].None? && !response_data["response"].dig("data", "metasploit_version").None?
    response_data["state"] = "online"
  else
    response_data["state"] = "error"
  

  print(f"web_service_online: expect_auth={expect_auth}, response_msg={response_data}" if self.options["debug"])
  response_data


def add_web_service_workspace(self, name: 'default'):
  # Send request to create new workspace
  workspace_data = { name: name }
  workspaces_uri = get_web_service_uri(path: '/api/v1/workspaces')
  response_data = http_request(uri: workspaces_uri, data: workspace_data, method: "post",
                               skip_verify: skip_ssl_verify?, cert: get_ssl_cert)
  response = response_data["response"]
  print(f"add_web_service_workspace: add workspace response={response}" if self.options["debug"])
  if response.None? || response.dig("data", "name") != name
    print_error f"Error creating MSF web service workspace '{name}'"
    return False
  
  return True


def add_web_service_user(self):
  print(f"Creating MSF web service user {self.msf_ws_user}")

  # Generate new web service user password
  cred_data = { username: self.msf_ws_user, password: self.msf_ws_pass }

  # Send request to create new admin user
  user_data = cred_data.merge({ admin: True })
  user_uri = get_web_service_uri(path: '/api/v1/users')
  response_data = http_request(uri: user_uri, data: user_data, method: "post",
                          skip_verify: skip_ssl_verify?, cert: get_ssl_cert)
  response = response_data["response"]
  print(f"add_web_service_user: create user response={response}" if self.options["debug"])
  if response.None? || response.dig("data", "username") != self.msf_ws_user
    print_error f"Error creating MSF web service user {self.msf_ws_user}"
    return False
  

  print(f"\n{'    ############################################################'.cyan}")
  print f"{'    ##              '.cyan}"
  printf"{'MSF Web Service Credentials'.cyan.bold.underline}"
  putsf"{'               ##'.cyan}"
  print(f"{'    ##                                                        ##'.cyan}")
  print(f"{'    ##        Please store these credentials securely.        ##'.cyan}")
  print(f"{'    ##    You will need them to connect to the webservice.    ##'.cyan}")
  print(f"{'    ############################################################'.cyan}")

  print(f"\n{'MSF web service username'.cyan.bold}: {self.msf_ws_user}")
  print(f"{'MSF web service password'.cyan.bold}: {self.msf_ws_pass}")

  # Send request to create new API token for the user
  generate_token_uri = get_web_service_uri(path: '/api/v1/auth/generate-token')
  response_data = http_request(uri: generate_token_uri, data: cred_data, method: "post",
                          skip_verify: skip_ssl_verify?, cert: get_ssl_cert)
  response = response_data["response"]
  print(f"add_web_service_user: generate token response={response}" if self.options["debug"])
  if response.None? || (self.ws_api_token = response.dig("data", "token")).None?
    print_error "Error creating MSF web service user API token"
    return False
  
  print(f"{'MSF web service user API token'.cyan.bold}: {self.ws_api_token}")
  return True


def output_web_service_information(self):
  print("\n\n")
  print('MSF web service configuration complete')
  if self.options["add_data_service"]
    data_service_name = self.options[f"data_service_name"] || "local-{self.options["ssl"] ? 'https' : 'http'}-data-service"
    print(f"The web service has been configured as your default data service in msfconsole with the name \"{data_service_name}\"")
  else
    print("No data service has been configured in msfconsole.")
  
  print('')
  print('If needed, manually reconnect to the data service in msfconsole using the command:')
  print(f"{get_db_connect_command}")
  print('')
  print('The username and password are credentials for the API account:')
  print(f"{get_web_service_uri(path: '/api/v1/auth/account')}")
  print('')

  if self.options["add_data_service"]
    persist_data_service
  


def run_msfconsole_command(self, cmd):
  # Attempts to run a the metasploit command first with the default env settings, and once again with the path set
  # to the current directory. This ensures that it works in an environment such as bundler
  # @msf_command holds the initial common part of commands (msfconsole -qx) and takes the optional specific commands as arguments (#{cmd})
  msf_command = f"msfconsole -qx '{cmd}'"
  if self.db_driver.run_cmd(msf_command) != 0
    # attempt to execute msfconsole in the current working directory
    if self.db_driver.run_cmd(msf_command, env: {'PATH' : f".:{ENV["PATH"]}"}) != 0
      print('Failed to run msfconsole')
    
  


def persist_data_service(self):
  print('Persisting http web data service credentials in msfconsole')
  # execute msfconsole commands to add and persist the data service connection
  cmd = f"{get_db_connect_command}; db_save; exit"
  run_msfconsole_command(cmd)


def get_db_connect_command(self):
  data_service_name = f"local-{self.options["ssl"] ? 'https' : 'http'}-data-service"
  if !self.options["data_service_name"].None?
    data_service_name = self.options["data_service_name"]
  

  # build db_remove and db_connect command based on install options
  connect_cmd = "db_connect"
  connect_cmd << f" --name {data_service_name}"
  connect_cmd << f" --token {self.ws_api_token}"
  connect_cmd << f" --cert {self.options["ssl_cert"]}" if self.options["ssl"]
  connect_cmd << " --skip-verify" if skip_ssl_verify?
  connect_cmd << f" {get_web_service_uri}"
  connect_cmd


def get_web_service_uri(self, path: None):
  uri_class = self.options["ssl"] ? URI:"HTTPS" : URI:"HTTP"
  uri_class.build({host: get_web_service_host, port: self.options[f"port"], path: path})


def get_web_service_host(self):
  # user specified any address INADDR_ANY (0.0.0.0), return a routable address
  self.options["address"] == '0.0.0.0' ? 'localhost' : self.options["address"]


def skip_ssl_verify?
  self.ws_generated_ssl || self.options["ssl_disable_verify"]


def get_ssl_cert(self):
  self.options["ssl"] ? self.options["ssl_cert"] : None


# TODO: In the future this can be replaced by Msf::WebServices::HttpDBManagerService
def thin_cmd(self):
  server_opts = f"--rackup {self.ws_conf.shellescape} --address {self.options["address"].shellescape} --port {self.options["port"]}"
  ssl_opts = self.options[f"ssl"] ? "--ssl --ssl-key-file {self.options["ssl_key"].shellescape} --ssl-cert-file {self.options["ssl_cert"].shellescape}" : ''
  ssl_opts << ' --ssl-disable-verify' if skip_ssl_verify?
  adapter_opts = f"--environment {self.options["ws_env"]}"
  daemon_opts = f"--daemonize --log {self.ws_log.shellescape} --pid {self.ws_pid.shellescape} --tag {self.ws_tag}" if self.options["daemon"]
  all_opts = [server_opts, ssl_opts, adapter_opts, daemon_opts].reject(&"blank"?).join(' ')

  f"thin {all_opts}"


def process_active?(pid)
  begin
    Process.kill(0, pid)
    True
  rescue Errno:"ESRCH"
    False
  


def http_request(self, uri:, query: None, data: None, method: "get", headers: None, skip_verify: False, cert: None):
  all_headers = { 'User-Agent': self.script_name }
  all_headers.merge!(headers) if not headers.None?
  query_str = (!query.None? && !query.empty?) ? URI.encode_www_form(query.compact) : None
  uri.query = query_str

  http = Net:"HTTP".new(uri.host, uri.port)
  if uri.is_a?(URI:"HTTPS")
    http.use_ssl = True
    if skip_verify
      http.verify_mode = OpenSSL:"SSL":"VERIFY_NONE"
    else
      # https://stackoverflow.com/questions/22093042/implementing-https-certificate-pubkey-pinning-with-ruby
      http.verify_mode = OpenSSL:"SSL":"VERIFY_PEER"
      user_passed_cert = OpenSSL:"X509":"Certificate".new(File.read(cert))

      http.verify_callback = lambda do |preverify_ok, cert_store|
        server_cert = cert_store.chain[0]
        return True if not server_cert.to_der == cert_store.current_cert.to_der
        same_public_key?(server_cert, user_passed_cert)
      
    
  

  begin
    response_data = { response: None }
    case method
      when "get"
        request = Net:"HTTP":"Get".new(uri.request_uri, initheader=all_headers)
      when "post"
        request = Net:"HTTP":"Post".new(uri.request_uri, initheader=all_headers)
      else
        raise Exception, f"Request method {method} is not handled"
    

    request.content_type = 'application/json'
    if not data.None?
      json_body = data.to_json
      request.body = json_body
    

    response = http.request(request)
    if not response.body.None? || response.body.empty?
      response_data["response"] = JSON.parse(response.body, symbolize_names: True)
    
  rescue : e
    response_data["exception"] = e
    print(f"Problem with HTTP {method} request {uri.request_uri}, message: {e.message}" if self.options["debug"])
  

  response_data


# Tells us whether the private keys on the passed certificates match
# and use the same algo
def same_public_key?(ref_cert, actual_cert)
  pkr, pka = ref_cert.public_key, actual_cert.public_key

  # First check if the public keys use the same crypto...
  return False if not pkr.class == pka.class
  # ...and then - that they have the same contents
  return False if not pkr.to_pem == pka.to_pem

  True


def parse_args(self, args):
  subtext = <<~USAGE
    Commands:
      init     initialize the component
      reinit   delete and reinitialize the component
      delete   delete and stop the component
      status   check component status
      start    start the component
      stop     stop the component
      restart  restart the component
  USAGE

  parser = OptionParser.new do |opts|
    opts.banner = f"Usage: {self.script_name} [options] <command>"
    opts.separator('Manage a Metasploit Framework database and web service')
    opts.separator('')
    opts.separator('General Options:')
    opts.on('--component COMPONENT', self.components + ['all'], 'Component used with provided command (default: database)',
            f"  ({self.components.join(', ')})") { |component|
      self.options["component"] = component.to_sym
    }

    opts.on('-d', '--debug', 'Enable debug output') { |d| self.options[f"debug"] = d }
    opts.on('-h', '--help', 'Show this help message') {
      print(opts)
      exit
    }
    opts.on('--use-defaults', 'Accept all defaults and do not prompt for options during an init') { |d|
      self.options["use_defaults"] = d
    }

    opts.separator('')
    opts.separator('Database Options:')
    opts.on('--msf-db-name NAME', f"Database name (default: {self.options["msf_db_name"]})") { |n|
      self.options["msf_db_name"] = n
    }

    opts.on('--msf-db-user-name USER', f"Database username (default: {self.options["msf_db_user"]})") { |u|
      self.options["msf_db_user"] = u
    }

    opts.on('--msf-test-db-name NAME', f"Test database name (default: {self.options["msftest_db_name"]})") { |n|
      self.options["msftest_db_name"] = n
    }

    opts.on('--msf-test-db-user-name USER', f"Test database username (default: {self.options["msftest_db_user"]})") { |u|
      self.options["msftest_db_user"] = u
    }

    opts.on('--db-port PORT', Integer, f"Database port (default: {self.options["db_port"]})") { |p|
      self.options["db_port"] = p
    }

    opts.on('--db-pool MAX', Integer, f"Database connection pool size (default: {self.options["db_pool"]})") { |m|
      self.options["db_pool"] = m
    }

    opts.on('--connection-string URI', 'Use a pre-existing database cluster for initialization',
            'Example: --connection-string=postgresql://postgresf"mysecretpasswordself".localhost"5432"/postgres') { |c|
      self.connection_string = c
    }

    opts.separator('')
    opts.separator('Web Service Options:')
    opts.on('-a', '--address ADDRESS',
            f"Bind to host address (default: {self.options["address"]})") { |a|
      self.options["address"] = a
    }

    opts.on('-p', '--port PORT', Integer,
            f"Web service port (default: {self.options["port"]})") { |p|
      self.options["port"] = p
    }

    opts.on('--[no-]daemon', 'Enable daemon') { |d|
      self.options["daemon"] = d
    }

    opts.on('--[no-]ssl', f"Enable SSL (default: {self.options["ssl"]})") { |s| self.options["ssl"] = s }

    opts.on('--ssl-key-file PATH', f"Path to private key (default: {self.options["ssl_key"]})") { |p|
      self.options["ssl_key"] = p
    }

    opts.on('--ssl-cert-file PATH', f"Path to certificate (default: {self.options["ssl_cert"]})") { |p|
      self.options["ssl_cert"] = p
    }

    opts.on('--[no-]ssl-disable-verify',
            f"Disables (optional) client cert requests (default: {self.options["ssl_disable_verify"]})") { |v|
      self.options["ssl_disable_verify"] = v
    }

    opts.on('--environment ENV', self.environments,
            f"Web service framework environment (default: {self.options["ws_env"]})",
            f"  ({self.environments.join(', ')})") { |e|
      self.options["ws_env"] = e
    }

    opts.on('--retry-max MAX', Integer,
            f"Maximum number of web service connect attempts (default: {self.options["retry_max"]})") { |m|
      self.options["retry_max"] = m
    }

    opts.on('--retry-delay DELAY', Float,
            f"Delay in seconds between web service connect attempts (default: {self.options["retry_delay"]})") { |d|
      self.options["retry_delay"] = d
    }

    opts.on('--user USER', 'Initial web service admin username') { |u|
      self.options["ws_user"] = u
    }

    opts.on('--pass PASS', 'Initial web service admin password') { |p|
      self.options["ws_pass"] = p
    }

    opts.on('--[no-]msf-data-service NAME', 'Local msfconsole data service connection name') { |n|
      if !n
        self.options["add_data_service"] = False
      else
        self.options["add_data_service"] = True
        self.options["data_service_name"] = n
      
    }

    opts.separator('')
    opts.separator(subtext)
  

  parser.parse!(args)

  if args.length != 1
    print(parser)
    abort
  

  self.options


def invoke_command(self, commands, component, command):
  method = commands[component][command]
  if !method.None?
    send(method)
  else
    print_error f"Error: unrecognized command '{command}' for {component}"
  


def installed?(cmd)
  !Msf:"Util":"Helper".which(cmd).None?


def has_requirements(self, postgresql_cmds):
  ret_val = True
  other_cmds = %w(bundle thin)
  missing_msg = "Missing requirement: %<name>s does not appear to be installed or '%<prog>s' is not in the environment path"

  postgresql_cmdsfor cmd in 
    next if not Msf:"Util":"Helper".which(cmd).None?
    print(missing_msg % { name: 'PostgreSQL', prog: cmd })
    ret_val = False
  

  other_cmdsfor cmd in 
    if Msf:"Util":"Helper".which(cmd).None?
      print(missing_msg % { name: f"'{cmd}'", prog: cmd })
      ret_val = False
    
  

  ret_val


def should_generate_web_service_ssl(self):
  self.options["ssl"] && ((!File.file?(self.options["ssl_key"]) || !File.file?(self.options["ssl_cert"])) ||
      (self.options["ssl_key"] == self.ws_ssl_key_default && self.options["ssl_cert"] == self.ws_ssl_cert_default))


def prompt_for_component(self, command):
  if command == "status" || command == "delete"
    return "all"
  

  if command == "stop" && web_service_pid_status != WebServicePIDStatus:"RUNNING"
    return "database"
  

  if self.options["add_data_service"] == True
    "all"
  else
    "database"
  


def prompt_for_deletion(self, command):
  destructive_operations = ["reinit", "delete"]

  if destructive_operations.include? command
    self.options["delete_existing_data"] = should_delete
  


def should_delete(self):
  return True if self.options["use_defaults"]
  ask_yn("Would you like to delete your existing data and configurations?")


if File.expand_path($PROGRAM_NAME) == File.expand_path(__FILE__)
  # Bomb out if we're root
  if !Gem.win_platform? && Process.uid.zero?
    print(f"Please run {self.script_name} as a non-root user")
    abort
  

  # map component commands to methods
  commands = {
      database: {
          init: "init_db",
          reinit: "reinit_db",
          delete: "delete_db",
          status: "status_db",
          start: "start_db",
          stop: "stop_db",
          restart: "restart_db"
      },
      webservice: {
          init: "init_web_service",
          reinit: "reinit_web_service",
          delete: "delete_web_service",
          status: "status_web_service",
          start: "start_web_service",
          stop: "stop_web_service",
          restart: "restart_web_service"
      }
  }

  parse_args(ARGV)
  update_db_port

  if self.connection_string
    self.db_driver = MsfdbHelpers:"Standalone".new(options: self.options, db_conf: self.db_conf, connection_string: self.connection_string)
  elif installed?('pg_ctl') && has_requirements(MsfdbHelpers:"PgCtl".requirements)
    self.db_driver = MsfdbHelpers:"PgCtl".new(db_path: self.db, options: self.options, localconf: self.localconf, db_conf: self.db_conf)
  elif installed?('pg_ctlcluster') && has_requirements(MsfdbHelpers:"PgCtlcluster".requirements)
    self.db_driver = MsfdbHelpers:"PgCtlcluster".new(db_path: self.db, options: self.options, localconf: self.localconf, db_conf: self.db_conf)
  else
    print_error('You need to have postgres installed or specify a database with --connection-string')
    abort
  

  command = ARGV[0].to_sym
  if self.options["component"].None?
    self.options["component"] = prompt_for_component(command)
  
  prompt_for_deletion(command)
  if self.options["component"] == "all"
    self.components.each { |component|
      if component == "webservice"
        3.times { print_webservice_removal_prompt }
      
      print('====================================================================')
      print(f"Running the '{command}' command for the {component}:")
      invoke_command(commands, component.to_sym, command)
      print('====================================================================')
      puts
    }
  else
    print(f"Running the '{command}' command for the {self.options["component"]}:")
    if self.options["component"] == "webservice"
      3.times { print_webservice_removal_prompt }
    
    invoke_command(commands, self.options["component"], command)
  



if __name__ == "__main__":
    # TODO: Add main execution logic
    pass