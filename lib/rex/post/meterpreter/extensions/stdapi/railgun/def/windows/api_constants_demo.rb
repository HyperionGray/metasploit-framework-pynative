# -*- coding: binary -*-
require 'rex/post/meterpreter/extensions/stdapi/railgun/const_manager'

require 'rex/post/meterpreter/extensions/stdapi/railgun/def/windows/constants/access_control_constants'
require 'rex/post/meterpreter/extensions/stdapi/railgun/def/windows/constants/crypto_certificates_constants'
require 'rex/post/meterpreter/extensions/stdapi/railgun/def/windows/constants/database_constants'
require 'rex/post/meterpreter/extensions/stdapi/railgun/def/windows/constants/device_io_constants'
require 'rex/post/meterpreter/extensions/stdapi/railgun/def/windows/constants/error_codes_constants'
require 'rex/post/meterpreter/extensions/stdapi/railgun/def/windows/constants/events_logging_constants'
require 'rex/post/meterpreter/extensions/stdapi/railgun/def/windows/constants/file_security_constants'
require 'rex/post/meterpreter/extensions/stdapi/railgun/def/windows/constants/input_devices_constants'
require 'rex/post/meterpreter/extensions/stdapi/railgun/def/windows/constants/internet_http_constants'
require 'rex/post/meterpreter/extensions/stdapi/railgun/def/windows/constants/locale_language_constants'
require 'rex/post/meterpreter/extensions/stdapi/railgun/def/windows/constants/miscellaneous_constants'
require 'rex/post/meterpreter/extensions/stdapi/railgun/def/windows/constants/multimedia_constants'
require 'rex/post/meterpreter/extensions/stdapi/railgun/def/windows/constants/network_dns_constants'
require 'rex/post/meterpreter/extensions/stdapi/railgun/def/windows/constants/pe_image_constants'
require 'rex/post/meterpreter/extensions/stdapi/railgun/def/windows/constants/printing_constants'
require 'rex/post/meterpreter/extensions/stdapi/railgun/def/windows/constants/process_security_constants'
require 'rex/post/meterpreter/extensions/stdapi/railgun/def/windows/constants/registry_config_constants'
require 'rex/post/meterpreter/extensions/stdapi/railgun/def/windows/constants/services_constants'
require 'rex/post/meterpreter/extensions/stdapi/railgun/def/windows/constants/system_hardware_constants'
require 'rex/post/meterpreter/extensions/stdapi/railgun/def/windows/constants/ui_resources_constants'
require 'rex/post/meterpreter/extensions/stdapi/railgun/def/windows/constants/window_management_constants'

module Rex
module Post
module Meterpreter
module Extensions
module Stdapi
module Railgun
module Def

#
# A container holding useful Windows API Constants.
# This file loads constants from categorized files for better maintainability.
# Original monolithic file had 38,000+ lines and has been split into 21 category files.
#
class DefApiConstants_windows < ApiConstants

  #
  # Load constants from all category files
  #
  def self.add_constants(win_const_mgr)
    AccessControlConstants.add_constants(win_const_mgr)
    CryptoCertificatesConstants.add_constants(win_const_mgr)
    DatabaseConstants.add_constants(win_const_mgr)
    DeviceIoConstants.add_constants(win_const_mgr)
    ErrorCodesConstants.add_constants(win_const_mgr)
    EventsLoggingConstants.add_constants(win_const_mgr)
    FileSecurityConstants.add_constants(win_const_mgr)
    InputDevicesConstants.add_constants(win_const_mgr)
    InternetHttpConstants.add_constants(win_const_mgr)
    LocaleLanguageConstants.add_constants(win_const_mgr)
    MiscellaneousConstants.add_constants(win_const_mgr)
    MultimediaConstants.add_constants(win_const_mgr)
    NetworkDnsConstants.add_constants(win_const_mgr)
    PeImageConstants.add_constants(win_const_mgr)
    PrintingConstants.add_constants(win_const_mgr)
    ProcessSecurityConstants.add_constants(win_const_mgr)
    RegistryConfigConstants.add_constants(win_const_mgr)
    ServicesConstants.add_constants(win_const_mgr)
    SystemHardwareConstants.add_constants(win_const_mgr)
    UiResourcesConstants.add_constants(win_const_mgr)
    WindowManagementConstants.add_constants(win_const_mgr)
  end

end

end; end; end; end; end; end; end