# -*- coding: binary -*-

module Rex
module Post
module Meterpreter
module Extensions
module Stdapi
module Railgun
module Def

# Windows API Constants - Miscellaneous (Sample)
class MiscellaneousConstants
  def self.add_constants(win_const_mgr)
    win_const_mgr.add_const('TF_LBI_TOOLTIP',0x00000004)
    win_const_mgr.add_const('SYMMETRICWRAPKEYBLOB',0x0000000B)
    win_const_mgr.add_const('FKF_AVAILABLE',0x00000002)
    win_const_mgr.add_const('LINE_AGENTSTATUSEX',0x0000001D)
    win_const_mgr.add_const('REGDF_GENFORCEDCONFIG',0x00000020)
    win_const_mgr.add_const('AM_DVD_SECTOR_PROTECTED',0x00000020)
    win_const_mgr.add_const('BTH_ERROR_PAIRING_NOT_ALLOWED',0x00000018)
    win_const_mgr.add_const('HSE_VECTOR_ELEMENT_TYPE_MEMORY_BUFFER',0x00000000)
    win_const_mgr.add_const('TASK_LAST_WEEK',0x00000005)
    win_const_mgr.add_const('DISPID_COLLECTION_RESERVED_MAX',0x000007FF)
    win_const_mgr.add_const('MSIM_DISPID_ONSESSIONMEMBERLEAVE',0x00000E0D)
    win_const_mgr.add_const('WPWIZ_ERROR_PROV_QI',0xC0042002)
    win_const_mgr.add_const('FLICK_WM_HANDLED_MASK',0x00000001)
    win_const_mgr.add_const('NDR_MAJOR_VERSION',0x00000005)
    win_const_mgr.add_const('SPPSR_ENUM_ADV_DEVICE_PROPERTIES',0x00000003)
    win_const_mgr.add_const('ICC_PAGESCROLLER_CLASS',0x00001000)
    win_const_mgr.add_const('GIL_CHECKSHIELD',0x00000200)
    win_const_mgr.add_const('DDE_FDEFERUPD',0x00004000)
  end
end

end; end; end; end; end; end; end