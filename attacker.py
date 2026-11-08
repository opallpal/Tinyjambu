"""
attacker.py
============
Menghasilkan paket termanipulasi (kondisi tampered) untuk menguji ketahanan
mekanisme verifikasi tag autentikasi TinyJambu-128, sesuai empat varian pada
skenario S4:
  1. bitflip_ciphertext - membalik satu bit pada bagian ciphertext
  2. random_tag         - mengganti authentication tag dengan nilai acak
  3. wrong_nonce        - mengubah nonce sehingga tidak sesuai saat enkripsi
  4. wrong_key          - mengenkripsi ulang memakai kunci rahasia yang berbeda
"""

import os

from crypto_utils import TinyJambuContext, generate_key, NONCE_SIZE, TAG_SIZE

ATTACK_VARIANTS = ["bitflip_ciphertext", "random_tag", "wrong_nonce", "wrong_key"]


def make_packet(plaintext: bytes, associated_data: bytes, key: bytes,
                 condition: str, variant: str = None):
    """
    condition: 'normal' atau 'tampered'
    variant  : salah satu dari ATTACK_VARIANTS (wajib diisi bila condition='tampered')
    Mengembalikan (nonce, ciphertext, tag).
    """
    ctx = TinyJambuContext(key)

    if condition == "normal":
        return ctx.encrypt(plaintext, associated_data=associated_data)

    if condition != "tampered":
        raise ValueError("condition harus 'normal' atau 'tampered'")
    if variant not in ATTACK_VARIANTS:
        raise ValueError(f"variant tidak dikenal: {variant}")

    if variant == "wrong_key":
        wrong_key = generate_key()
        wrong_ctx = TinyJambuContext(wrong_key)
        return wrong_ctx.encrypt(plaintext, associated_data=associated_data)

    # Untuk 3 varian lain: enkripsi dahulu secara sah, lalu rusak salah satu komponen paket
    nonce, ct, tag = ctx.encrypt(plaintext, associated_data=associated_data)

    if variant == "bitflip_ciphertext":
        ct = bytearray(ct)
        idx = 0 if len(ct) > 0 else None
        if idx is not None:
            ct[idx] ^= 0x01
        return nonce, bytes(ct), tag

    if variant == "random_tag":
        return nonce, ct, os.urandom(TAG_SIZE)

    if variant == "wrong_nonce":
        bad_nonce = bytearray(nonce)
        bad_nonce[0] ^= 0x01
        return bytes(bad_nonce), ct, tag

    raise AssertionError("unreachable")
