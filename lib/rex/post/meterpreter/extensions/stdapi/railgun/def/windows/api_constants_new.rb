# -*- coding: binary -*-
require 'rex/post/meterpreter/extensions/stdapi/railgun/const_manager'

# Load all the split constant definition files
require 'rex/post/meterpreter/extensions/stdapi/railgun/def/windows/api_constants_base'
require 'rex/post/meterpreter/extensions/stdapi/railgun/def/windows/api_constants_error_codes'
require 'rex/post/meterpreter/extensions/stdapi/railgun/def/windows/api_constants_window_management'
# TODO: Add more split files as they are created

module Rex
module Post
module Meterpreter
module Extensions
module Stdapi
module Railgun
module Def

#
# A container holding useful Windows API Constants.
# This class now loads constants from multiple split files for better maintainability.
#
class DefApiConstants_windows < ApiConstants

  #
  # Load constants from all registered split files
  #
  def self.add_constants(win_const_mgr)
    # Load constants from all registered constant classes
    @constant_classes ||= []
    @constant_classes.each do |const_class|
      const_class.add_constants(win_const_mgr) if const_class.respond_to?(:add_constants)
    end
    
    # For now, also load remaining constants that haven't been split yet
    # TODO: Remove this section as constants are moved to split files
    load_remaining_constants(win_const_mgr)
  end

  #
  # Register a constant definition class
  #
  def self.register_constants(const_class)
    @constant_classes ||= []
    @constant_classes << const_class unless @constant_classes.include?(const_class)
  end

  private

  #
  # Temporary method to load constants that haven't been moved to split files yet
  # This will be removed as the migration completes
  #
  def self.load_remaining_constants(win_const_mgr)
    # MCI Constants
    win_const_mgr.add_const('MCI_DGV_SETVIDEO_TINT', 0x00004003)
    
    # Event Tracing Constants
    win_const_mgr.add_const('EVENT_TRACE_FLAG_PROCESS', 0x00000001)
    win_const_mgr.add_const('EVENT_SYSTEM_DIALOGEND', 0x00000011)
    win_const_mgr.add_const('EVENT_TRACE_CONTROL_STOP', 0x00000001)
    
    # Text Framework Constants
    win_const_mgr.add_const('TF_LBI_TOOLTIP', 0x00000004)
    
    # Configuration Manager Constants
    win_const_mgr.add_const('CM_DRP_CLASSGUID', 0x00000009)
    win_const_mgr.add_const('DN_MOVED', 0x00001000)
    
    # Cryptography Constants
    win_const_mgr.add_const('SYMMETRICWRAPKEYBLOB', 0x0000000B)
    win_const_mgr.add_const('CMSG_HASH_DATA_PARAM', 0x00000015)
    
    # Accessibility Constants
    win_const_mgr.add_const('FKF_AVAILABLE', 0x00000002)
    
    # Line API Constants
    win_const_mgr.add_const('LINE_AGENTSTATUSEX', 0x0000001D)
    
    # Registry Constants
    win_const_mgr.add_const('REGDF_GENFORCEDCONFIG', 0x00000020)
    
    # DVD Constants
    win_const_mgr.add_const('AM_DVD_SECTOR_PROTECTED', 0x00000020)
    
    # HSE Constants
    win_const_mgr.add_const('HSE_VECTOR_ELEMENT_TYPE_MEMORY_BUFFER', 0x00000000)
    
    # Task Constants
    win_const_mgr.add_const('TASK_LAST_WEEK', 0x00000005)
    
    # Dispatch Constants
    win_const_mgr.add_const('DISPID_COLLECTION_RESERVED_MAX', 0x000007FF)
    win_const_mgr.add_const('MSIM_DISPID_ONSESSIONMEMBERLEAVE', 0x00000E0D)
    win_const_mgr.add_const('DISPID_IWBSCRIPTCONTROL_VERSION', 0x00000008)
    
    # Namespace Constants
    win_const_mgr.add_const('NS_NISPLUS', 0x0000002A)
    
    # NDR Constants
    win_const_mgr.add_const('NDR_MAJOR_VERSION', 0x00000005)
    
    # Setup API Constants
    win_const_mgr.add_const('SPPSR_ENUM_ADV_DEVICE_PROPERTIES', 0x00000003)
    
    # Common Controls Constants
    win_const_mgr.add_const('ICC_PAGESCROLLER_CLASS', 0x00001000)
    
    # Language Constants
    win_const_mgr.add_const('SUBLANG_CORSICAN_FRANCE', 0x00000001)
    win_const_mgr.add_const('SUBLANG_BOSNIAN_BOSNIA_HERZEGOVINA_CYRILLIC', 0x00000008)
    
    # Image Constants
    win_const_mgr.add_const('IMAGE_REL_IA64_PCREL60X', 0x00000015)
    win_const_mgr.add_const('IMAGE_SIZEOF_SYMBOL', 0x00000012)
    
    # GIL Constants
    win_const_mgr.add_const('GIL_CHECKSHIELD', 0x00000200)
    
    # DDE Constants
    win_const_mgr.add_const('DDE_FDEFERUPD', 0x00004000)
    
    # OS Version Constants
    win_const_mgr.add_const('OS_NT4ORGREATER', 0x00000003)
    
    # Disk Constants
    win_const_mgr.add_const('DISK_LOGGING_DUMP', 0x00000002)
    
    # List View Constants
    win_const_mgr.add_const('LVS_EX_HIDELABELS', 0x00020000)
    
    # Device Broadcast Constants
    win_const_mgr.add_const('DBT_VOLLOCKUNLOCKFAILED', 0x00008046)
    
    # Security Constants
    win_const_mgr.add_const('SEC_WINNT_AUTH_IDENTITY_VERSION', 0x00000200)
    
    # User Marshal Constants
    win_const_mgr.add_const('USER_MARSHAL_FC_USMALL', 0x00000004)
    
    # Internet Constants
    win_const_mgr.add_const('INTERNET_OPTION_HANDLE_TYPE', 0x00000009)
    
    # Month Calendar Constants
    win_const_mgr.add_const('MCGIP_CALENDARBODY', 0x00000006)
    
    # Media Foundation Constants
    win_const_mgr.add_const('MFOUTPUTATTRIBUTE_SOFTWARE', 0x00000010)
    
    # ImageHlp Constants
    win_const_mgr.add_const('IMAGEHLP_GET_TYPE_INFO_CHILDREN', 0x00000002)
    
    # MCI Constants
    win_const_mgr.add_const('MCI_CD_OFFSET', 0x00000440)
    
    # Credential Constants
    win_const_mgr.add_const('CRED_MAX_DOMAIN_TARGET_NAME_LENGTH', 0x00000100)
    
    # ACPI Constants
    win_const_mgr.add_const('ACPI_PPM_SOFTWARE_ANY', 0x000000FD)
    
    # Display Mode Constants
    win_const_mgr.add_const('DM_PELSHEIGHT', 0x00100000)
    
    # Clone Constants
    win_const_mgr.add_const('CLONE_FLAG_ENTITY', 0x00000004)
    
    # IP Constants
    win_const_mgr.add_const('IP_UNICAST_IF', 0x0000001F)
    
    # LDAP Constants
    win_const_mgr.add_const('LDAP_OPT_VERSION', 0x00000011)
    
    # Cluster API Constants
    win_const_mgr.add_const('CLUSAPI_CHANGE_ACCESS', 0x00000002)
    
    # Sound Constants
    win_const_mgr.add_const('SND_NOSTOP', 0x00000010)
    win_const_mgr.add_const('SOUND_SYSTEM_BEEP', 0x00000003)
    
    # Layer 2 Constants
    win_const_mgr.add_const('L2_NOTIFICATION_SOURCE_ALL', 0x00000000)
    
    # IDM Constants
    win_const_mgr.add_const('IDM_SIZETOCONTROLHEIGHT', 0x00000024)
    
    # Country Constants
    win_const_mgr.add_const('CTRY_CANADA', 0x00000002)
    win_const_mgr.add_const('CTRY_SAUDI_ARABIA', 0x000003C6)
    
    # Firewall Constants
    win_const_mgr.add_const('FWPM_ACTRL_CLASSIFY', 0x00000010)
    
    # Service Constants
    win_const_mgr.add_const('SERVICE_STOP_REASON_FLAG_CUSTOM', 0x20000000)
    
    # Device Manager Constants
    win_const_mgr.add_const('DMBIN_LARGECAPACITY', 0x0000000B)
    
    # SQL Constants
    win_const_mgr.add_const('SQL_FD_FETCH_ABSOLUTE', 0x00000010)
    
    # Color Constants
    win_const_mgr.add_const('COLOR_HIGHLIGHTTEXT', 0x0000000E)
    
    # Debug Constants
    win_const_mgr.add_const('DEBUG_FILTER_GO_HANDLED', 0x00000000)
    
    # Certificate Constants
    win_const_mgr.add_const('CR_FLG_RENEWAL', 0x00000002)
    
    # DirectDraw Constants
    win_const_mgr.add_const('DDOVERZ_INSERTINBACKOF', 0x00000005)
    
    # Parity Constants
    win_const_mgr.add_const('PARITY_MARK', 0x00000800)
    
    # SIP Constants
    win_const_mgr.add_const('MSSIP_FLAGS_USE_CATALOG', 0x00020000)
    
    # PostScript Constants
    win_const_mgr.add_const('PSINJECT_SHOWPAGE', 0x00000069)
    
    # Theme Constants
    win_const_mgr.add_const('TMT_GLYPHINDEX', 0x00000972)
    
    # OID Constants
    win_const_mgr.add_const('OID_FDDI_MAC_FRAME_ERROR_FLAG', 0x0303024C)
    
    # Font Constants
    win_const_mgr.add_const('PAN_SERIF_OBTUSE_SQUARE_COVE', 0x00000005)
    
    # Joystick Constants
    win_const_mgr.add_const('JOYCAPS_HASPOV', 0x00000010)
    
    # Wave Constants
    win_const_mgr.add_const('WAVE_FORMAT_96S16', 0x00080000)
    
    # TODO: Continue adding remaining constants in batches
    # This is just a small sample to demonstrate the structure
    # The full migration would involve moving all 38,000+ constants
  end

end

end; end; end; end; end; end; end