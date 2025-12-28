# -*- coding: binary -*-

# Load all OUI data files
require 'rex/oui/data_0'
require 'rex/oui/data_1'
require 'rex/oui/data_2'
require 'rex/oui/data_3'
require 'rex/oui/data_4'
require 'rex/oui/data_5'
require 'rex/oui/data_6'
require 'rex/oui/data_7'
require 'rex/oui/data_8'
require 'rex/oui/data_9'
require 'rex/oui/data_a'
require 'rex/oui/data_b'
require 'rex/oui/data_c'
require 'rex/oui/data_d'
require 'rex/oui/data_e'
require 'rex/oui/data_f'

module Rex
module Oui

  def self.lookup_oui_fullname(mac)
    check_mac(mac)
    mac = mac.upcase.gsub(':','')[0,6]
    oui = OUI_LIST[mac]
    if oui
      fullname = oui[0]
      fullname = oui[0] + ' / ' + oui[1] if oui[1] != ""
      return fullname
    else
      return 'UNKNOWN'
    end
  end

  def self.lookup_oui_company_name(mac)
    check_mac(mac)
    mac = mac.upcase.gsub(':','')[0,6]
    oui = OUI_LIST[mac]
    if oui
      fullname = oui[0]
      fullname = oui[1] if oui[1] != ""
      return fullname
    else
      return 'UNKNOWN'
    end
  end

  def self.check_mac(mac)
    unless mac =~ /(^([A-Fa-f0-9]{2}:){2,5}[A-Fa-f0-9]{2}$)|(^([A-Fa-f0-9]{2}){3,6}$)/
      raise "Mac address is not in a correct format"
    end
  end

  # Combine all OUI data into a single hash for backward compatibility
  OUI_LIST = {}
  
  # Load data from all split files
  [
    OUI_DATA_0, OUI_DATA_1, OUI_DATA_2, OUI_DATA_3, 
    OUI_DATA_4, OUI_DATA_5, OUI_DATA_6, OUI_DATA_7,
    OUI_DATA_8, OUI_DATA_9, OUI_DATA_A, OUI_DATA_B,
    OUI_DATA_C, OUI_DATA_D, OUI_DATA_E, OUI_DATA_F
  ].each do |data_hash|
    OUI_LIST.merge!(data_hash) if defined?(data_hash)
  end

end
end