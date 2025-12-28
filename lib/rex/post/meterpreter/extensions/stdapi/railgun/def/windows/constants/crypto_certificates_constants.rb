# -*- coding: binary -*-

module Rex
module Post
module Meterpreter
module Extensions
module Stdapi
module Railgun
module Def

# Windows API Constants - Cryptography and Certificates
class CryptoCertificatesConstants
  def self.add_constants(win_const_mgr)
    win_const_mgr.add_const('CMSG_HASH_DATA_PARAM',0x00000015)
    win_const_mgr.add_const('CMSG_KEY_TRANS_RECIPIENT',0x00000001)
    win_const_mgr.add_const('CRYPT_OCSP_ONLY_RETRIEVAL',0x01000000)
    win_const_mgr.add_const('CRYPTNET_URL_CACHE_DEFAULT_FLUSH',0x00000000)
    win_const_mgr.add_const('CRYPTDLG_REVOCATION_ONLINE',0x80000000)
    win_const_mgr.add_const('CERT_STORE_PROV_CONTROL_FUNC',0x0000000D)
    win_const_mgr.add_const('CERT_DECIPHER_ONLY_KEY_USAGE',0x00000080)
    win_const_mgr.add_const('CERT_CLOSE_STORE_FORCE_FLAG',0x00000001)
    win_const_mgr.add_const('CRYPTDLG_POLICY_MASK',0x0000FFFF)
    # Add more crypto/certificate constants here...
  end
end

end; end; end; end; end; end; end