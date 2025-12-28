# -*- coding: binary -*-

module Rex
module Oui

  def self.lookup_oui_fullname(mac)
    check_mac(mac)
    mac = mac.upcase.gsub(':','')[0,6]
    oui = get_oui_data(mac)
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
    oui = get_oui_data(mac)
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

  private

  # Lazy-loaded OUI data
  def self.get_oui_data(mac)
    @oui_data ||= load_oui_data
    @oui_data[mac]
  end

  # Load OUI data from split files
  def self.load_oui_data
    oui_data = {}
    
    # Load data from split files
    oui_data.merge!(load_oui_range_00_0f)
    oui_data.merge!(load_oui_range_10_1f)
    oui_data.merge!(load_oui_range_20_2f)
    oui_data.merge!(load_oui_range_30_3f)
    oui_data.merge!(load_oui_range_40_4f)
    oui_data.merge!(load_oui_range_50_5f)
    oui_data.merge!(load_oui_range_60_6f)
    oui_data.merge!(load_oui_range_70_7f)
    oui_data.merge!(load_oui_range_80_8f)
    oui_data.merge!(load_oui_range_90_9f)
    oui_data.merge!(load_oui_range_a0_af)
    oui_data.merge!(load_oui_range_b0_bf)
    oui_data.merge!(load_oui_range_c0_cf)
    oui_data.merge!(load_oui_range_d0_df)
    oui_data.merge!(load_oui_range_e0_ef)
    oui_data.merge!(load_oui_range_f0_ff)
    
    oui_data
  end

  # Load OUI data for range 00-0F
  def self.load_oui_range_00_0f
    {
      "000000" => ["Xerox", "XEROX CORPORATION"],
      "000001" => ["Xerox", "XEROX CORPORATION"],
      "000002" => ["Xerox", "XEROX CORPORATION"],
      "000003" => ["Xerox", "XEROX CORPORATION"],
      "000004" => ["Xerox", "XEROX CORPORATION"],
      "000005" => ["Xerox", "XEROX CORPORATION"],
      "000006" => ["Xerox", "XEROX CORPORATION"],
      "000007" => ["Xerox", "XEROX CORPORATION"],
      "000008" => ["Xerox", "XEROX CORPORATION"],
      "000009" => ["Xerox", "XEROX CORPORATION"],
      "00000A" => ["OmronTat", "OMRON TATEISI ELECTRONICS CO."],
      "00000B" => ["Matrix", "MATRIX CORPORATION"],
      "00000C" => ["Cisco", "CISCO SYSTEMS, INC."],
      "00000D" => ["Fibronics", "FIBRONICS LTD."],
      "00000E" => ["Fujitsu", "FUJITSU LIMITED"],
      "00000F" => ["NeXT", "NeXT, INC."]
    }
  end

  # Load OUI data for range 10-1F  
  def self.load_oui_range_10_1f
    {
      "000010" => ["Sytek", "SYTEK INC."],
      "000011" => ["Normerel", "NORMEREL SYSTEMES"],
      "000012" => ["InformationTechnology", "INFORMATION TECHNOLOGY LIMITED"],
      "000013" => ["Camex", "CAMEX"],
      "000014" => ["Netronix", "NETRONIX"],
      "000015" => ["Datapoint", "DATAPOINT CORPORATION"]
    }
  end

  # Placeholder methods for other ranges - these would be implemented with actual data
  def self.load_oui_range_20_2f; {}; end
  def self.load_oui_range_30_3f; {}; end
  def self.load_oui_range_40_4f; {}; end
  def self.load_oui_range_50_5f; {}; end
  def self.load_oui_range_60_6f; {}; end
  def self.load_oui_range_70_7f; {}; end
  def self.load_oui_range_80_8f; {}; end
  def self.load_oui_range_90_9f; {}; end
  def self.load_oui_range_a0_af; {}; end
  def self.load_oui_range_b0_bf; {}; end
  def self.load_oui_range_c0_cf; {}; end
  def self.load_oui_range_d0_df; {}; end
  def self.load_oui_range_e0_ef; {}; end
  def self.load_oui_range_f0_ff; {}; end

end
end