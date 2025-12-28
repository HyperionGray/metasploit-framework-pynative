# -*- coding: binary -*-

require 'msf/core/opt_condition'
require 'optparse'

module Msf
module Ui
module Console
module CommandDispatcher

#
# Base module for core command functionality
# This provides common functionality shared across command groups
#
module CoreCommandBase
  include Msf::Ui::Console::CommandDispatcher
  include Msf::Ui::Console::CommandDispatcher::Common
  include Msf::Ui::Console::ModuleOptionTabCompletion

  # Common constants used across command groups
  SESSION_TYPE = 'session_type'
  SESSION_ID = 'session_id'
  LAST_CHECKIN = 'last_checkin'
  LESS_THAN = 'less_than'
  GREATER_THAN = 'greater_than'

  VALID_SESSION_SEARCH_PARAMS = [
    LAST_CHECKIN,
    SESSION_ID,
    SESSION_TYPE
  ]
  
  VALID_OPERATORS = [
    LESS_THAN,
    GREATER_THAN
  ]

  private_constant :VALID_SESSION_SEARCH_PARAMS
  private_constant :VALID_OPERATORS
  private_constant :SESSION_TYPE
  private_constant :SESSION_ID
  private_constant :LAST_CHECKIN
  private_constant :GREATER_THAN
  private_constant :LESS_THAN
end

end; end; end; end