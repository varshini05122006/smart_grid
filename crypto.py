"""Crypto service. Uses the PyPI `ascon` package (Ascon v1.2 reference, variant Ascon-128a).
NOT NIST SP 800-232 Ascon-AEAD128: IVs differ, so outputs are not interoperable.
Swap only this module when a maintained SP 800-232 library exists."""
import ascon, hmac
ALG = "Ascon-128a (v1.2)"
def aead_encrypt(key, nonce, aad, pt): return ascon.encrypt(key, nonce, aad, pt, "Ascon-128a")
def aead_decrypt(key, nonce, aad, ct):  # returns None if tag check fails
    return ascon.decrypt(key, nonce, aad, ct, "Ascon-128a")
def mac(key, msg): return ascon.mac(key, msg)          # Ascon-Mac, 128-bit tag
def eq(a, b): return hmac.compare_digest(a, b)
