"""
crypto_utils.py
================
Wrapper enkripsi/dekripsi TinyJambu-128 AEAD beserta pengelolaan kunci dan nonce.

CATATAN AKADEMIK / TRANSPARANSI
--------------------------------
Modul ini mengimplementasikan struktur inti TinyJambu (NLFSR 128-bit berbasis
word 32-bit, kunci 128-bit, nonce 96-bit, tag 64-bit) sesuai deskripsi publik
algoritma TinyJambu v2 (finalis NIST Lightweight Cryptography, Wu & Huang).
Fungsi permutasi/state-update, tahapan inisialisasi (P1024), pemrosesan
associated data & plaintext (P384 per blok), serta finalisasi tag (P1024)
ditulis ulang dari spesifikasi publik untuk KEPERLUAN SIMULASI BENCHMARKING
PERFORMA (latensi, throughput, CPU/RAM) dan pengujian mekanisme autentikasi/tag,
BUKAN untuk digunakan sebagai implementasi kriptografi produksi.

Jika skripsi/tugas akhir memerlukan kesesuaian bit-exact terhadap test vector
resmi NIST LWC, validasikan implementasi ini terhadap reference implementation
resmi (paket "tinyjambu" pada repositori NIST LWC) sebelum dipakai sebagai
klaim kesesuaian standar. Untuk tujuan benchmarking (mengukur beban komputasi,
RTT, throughput, serta kemampuan mendeteksi manipulasi data), implementasi ini
sudah konsisten: enkripsi-dekripsi round-trip benar, dan tag ditolak jika
ciphertext/tag/nonce/kunci diubah.
"""

import os
import struct
import hmac as _hmac

MASK32 = 0xFFFFFFFF

# Frame bits untuk domain separation antar fase (mengikuti pola spesifikasi publik)
FRAME_NONCE = 0x10
FRAME_AD = 0x30
FRAME_PC = 0x50
FRAME_FINAL = 0x70

KEY_SIZE = 16     # 128 bit
NONCE_SIZE = 12   # 96 bit
TAG_SIZE = 8       # 64 bit


def _bytes_to_words_le(data: bytes):
    """Ubah bytes (kelipatan 4, sudah di-pad di luar fungsi ini) menjadi list word 32-bit little-endian."""
    n = len(data) // 4
    return list(struct.unpack("<%dI" % n, data))


def _word_to_bytes_le(w: int) -> bytes:
    return struct.pack("<I", w & MASK32)


def _state_update(s0, s1, s2, s3, key_words, steps):
    """Update state NLFSR 128-bit sebanyak `steps` bit, diproses 32 bit per iterasi (word-batched)."""
    assert steps % 32 == 0
    n = steps // 32
    for i in range(n):
        t1 = ((s1 >> 15) | (s2 << 17)) & MASK32
        t2 = ((s2 >> 6) | (s3 << 26)) & MASK32
        t3 = ((s2 >> 21) | (s3 << 11)) & MASK32
        t4 = ((s2 >> 27) | (s3 << 5)) & MASK32
        t4 ^= key_words[i % 4]
        feedback = (s0 ^ t1 ^ (~(t2 & t3) & MASK32) ^ t4) & MASK32
        s0, s1, s2, s3 = s1, s2, s3, feedback
    return s0, s1, s2, s3


def _pad_to_word(block: bytes) -> int:
    """Pad blok parsial (<4 byte) dengan nol lalu ubah ke word 32-bit little-endian."""
    padded = block + b"\x00" * (4 - len(block))
    return struct.unpack("<I", padded)[0]


class TinyJambuError(Exception):
    """Dilempar saat verifikasi tag gagal (data dianggap tampered / tidak sah)."""


class TinyJambuContext:
    """Konteks kunci TinyJambu-128. Satu instance dapat dipakai berulang untuk banyak pesan."""

    def __init__(self, key: bytes):
        if len(key) != KEY_SIZE:
            raise ValueError("Kunci TinyJambu-128 harus 16 byte (128 bit)")
        self.key_words = _bytes_to_words_le(key)

    # -- inti proses (dipakai bersama oleh encrypt & decrypt) --------------
    def _init_state(self, nonce: bytes):
        if len(nonce) != NONCE_SIZE:
            raise ValueError("Nonce TinyJambu-128 harus 12 byte (96 bit)")
        s0 = s1 = s2 = s3 = 0
        s0, s1, s2, s3 = _state_update(s0, s1, s2, s3, self.key_words, 1024)
        nonce_words = _bytes_to_words_le(nonce)
        for nw in nonce_words:
            s1 ^= FRAME_NONCE
            s0, s1, s2, s3 = _state_update(s0, s1, s2, s3, self.key_words, 384)
            s3 ^= nw
        return s0, s1, s2, s3

    def _absorb_ad(self, state, ad: bytes):
        s0, s1, s2, s3 = state
        if not ad:
            return s0, s1, s2, s3
        full = len(ad) // 4
        for i in range(full):
            word = struct.unpack_from("<I", ad, i * 4)[0]
            s1 ^= FRAME_AD
            s0, s1, s2, s3 = _state_update(s0, s1, s2, s3, self.key_words, 384)
            s3 ^= word
        rem = ad[full * 4:]
        if rem:
            word = _pad_to_word(rem)
            s1 ^= (FRAME_AD ^ 0x01)
            s0, s1, s2, s3 = _state_update(s0, s1, s2, s3, self.key_words, 384)
            s3 ^= word
        return s0, s1, s2, s3

    def _process_pt(self, state, pt: bytes):
        s0, s1, s2, s3 = state
        ct = bytearray()
        full = len(pt) // 4
        for i in range(full):
            word = struct.unpack_from("<I", pt, i * 4)[0]
            s1 ^= FRAME_PC
            s0, s1, s2, s3 = _state_update(s0, s1, s2, s3, self.key_words, 384)
            ks = s2
            ct_word = word ^ ks
            s3 ^= word  # absorb PLAINTEXT (bukan ciphertext) untuk autentikasi
            ct += _word_to_bytes_le(ct_word)
        rem = pt[full * 4:]
        if rem:
            word = _pad_to_word(rem)
            s1 ^= (FRAME_PC ^ 0x01)
            s0, s1, s2, s3 = _state_update(s0, s1, s2, s3, self.key_words, 384)
            ks = s2
            ct_word = (word ^ ks) & MASK32
            s3 ^= word
            ct += _word_to_bytes_le(ct_word)[: len(rem)]
        return (s0, s1, s2, s3), bytes(ct)

    def _process_ct(self, state, ct: bytes):
        """Kebalikan dari _process_pt: memulihkan plaintext dari ciphertext."""
        s0, s1, s2, s3 = state
        pt = bytearray()
        full = len(ct) // 4
        for i in range(full):
            word = struct.unpack_from("<I", ct, i * 4)[0]
            s1 ^= FRAME_PC
            s0, s1, s2, s3 = _state_update(s0, s1, s2, s3, self.key_words, 384)
            ks = s2
            pt_word = word ^ ks
            s3 ^= pt_word
            pt += _word_to_bytes_le(pt_word)
        rem = ct[full * 4:]
        if rem:
            s1 ^= (FRAME_PC ^ 0x01)
            s0, s1, s2, s3 = _state_update(s0, s1, s2, s3, self.key_words, 384)
            ks = s2
            rem_word = _pad_to_word(rem)
            ks_bytes = _word_to_bytes_le(ks)[: len(rem)]
            pt_partial = bytes(a ^ b for a, b in zip(rem, ks_bytes))
            pt_word_full = _pad_to_word(pt_partial)
            s3 ^= pt_word_full
            pt += pt_partial
        return (s0, s1, s2, s3), bytes(pt)

    def _finalize_tag(self, state):
        s0, s1, s2, s3 = state
        s1 ^= FRAME_FINAL
        s0, s1, s2, s3 = _state_update(s0, s1, s2, s3, self.key_words, 1024)
        tag0 = s2
        s1 ^= FRAME_FINAL
        s0, s1, s2, s3 = _state_update(s0, s1, s2, s3, self.key_words, 384)
        tag1 = s2
        tag = _word_to_bytes_le(tag0) + _word_to_bytes_le(tag1)
        return tag

    # -- API publik ----------------------------------------------------------
    def encrypt(self, plaintext: bytes, associated_data: bytes = b"", nonce: bytes = None):
        """Enkripsi + hasilkan tag. Mengembalikan (nonce, ciphertext, tag)."""
        if nonce is None:
            nonce = os.urandom(NONCE_SIZE)
        state = self._init_state(nonce)
        state = self._absorb_ad(state, associated_data)
        state, ct = self._process_pt(state, plaintext)
        tag = self._finalize_tag(state)
        return nonce, ct, tag

    def decrypt(self, nonce: bytes, ciphertext: bytes, tag: bytes, associated_data: bytes = b""):
        """Verifikasi tag lalu dekripsi. Melempar TinyJambuError bila tag tidak cocok (tampered)."""
        state = self._init_state(nonce)
        state = self._absorb_ad(state, associated_data)
        state, pt = self._process_ct(state, ciphertext)
        expected_tag = self._finalize_tag(state)
        if not _hmac.compare_digest(expected_tag, tag):
            raise TinyJambuError("Verifikasi tag gagal: paket dianggap tampered / tidak sah")
        return pt


def generate_key() -> bytes:
    return os.urandom(KEY_SIZE)


if __name__ == "__main__":
    # Uji cepat: round-trip normal dan deteksi tampering
    key = generate_key()
    ctx = TinyJambuContext(key)
    pt = b'{"suhu":29.4,"kelembaban":63,"cahaya":812}'
    nonce, ct, tag = ctx.encrypt(pt, associated_data=b"device-01")
    recovered = ctx.decrypt(nonce, ct, tag, associated_data=b"device-01")
    assert recovered == pt, "round-trip gagal!"
    print("[OK] round-trip normal berhasil:", recovered)

    # tamper 1 bit pada ciphertext
    bad_ct = bytearray(ct)
    bad_ct[0] ^= 0x01
    try:
        ctx.decrypt(nonce, bytes(bad_ct), tag, associated_data=b"device-01")
        print("[GAGAL] tampering tidak terdeteksi!")
    except TinyJambuError:
        print("[OK] tampering ciphertext berhasil dideteksi dan ditolak")
