# -*- coding: binary -*-
require 'rex/post/meterpreter/extensions/stdapi/railgun/const_manager'

module Rex
module Post
module Meterpreter
module Extensions
module Stdapi
module Railgun
module Def

#
# Base class for Windows API Constants that supports modular loading
#
class DefApiConstants_windows < ApiConstants

  # Registry of constant definition classes
  @constant_classes = []

  class << self
    attr_accessor :constant_classes
  end

  #
  # Register a constant definition class
  #
  def self.register_constants(const_class)
    @constant_classes ||= []
    @constant_classes << const_class unless @constant_classes.include?(const_class)
  end

  #
  # Load constants from all registered classes
  #
  def self.add_constants(win_const_mgr)
    @constant_classes ||= []
    @constant_classes.each do |const_class|
      const_class.add_constants(win_const_mgr) if const_class.respond_to?(:add_constants)
    end
  end

end

end; end; end; end; end; end; end