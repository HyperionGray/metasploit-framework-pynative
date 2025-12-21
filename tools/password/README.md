Python password utilities
=========================

This directory now uses Python-only tooling. The previous Ruby utilities have been removed and replaced with Python equivalents:

- `halflm_second.py` (half-LM challenge brute-forcer)
- `hmac_sha1_crack.py` (HMAC-SHA1 cracker with binary salts)
- `lm2ntcrack.py` (LM/NTLM cracking helper)
- `md5_lookup.py` (MD5 lookup client)
- `vxmaster.py` (VxWorks master password generator)
- Shared helpers in `ntlm_utils.py`

Older Ruby scripts have been deleted as part of the Ruby → Python migration. Use the Python versions going forward.
