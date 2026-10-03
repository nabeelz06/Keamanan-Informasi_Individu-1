"""
AES-128 implementasi manual (tanpa library kripto) + mode CBC + padding PKCS#7.

Tugas Keamanan Informasi - Muhammad Nabil Fauzan (5025241024)

Semua komponen dibangun sendiri:
- Aritmetika GF(2^8)
- S-Box dan Inverse S-Box (dihitung, bukan tabel hasil copy)
- KeyExpansion, SubBytes, ShiftRows, MixColumns, AddRoundKey
- Mode CBC dan padding PKCS#7
"""

import os

BLOCK = 16
NR = 10  # jumlah ronde untuk AES-128


# ---------- Aritmetika GF(2^8), polinomial irreducible x^8+x^4+x^3+x+1 ----------
def xtime(a):
    a <<= 1
    if a & 0x100:
        a ^= 0x11B
    return a & 0xFF


def gmul(a, b):
    r = 0
    while b:
        if b & 1:
            r ^= a
        a = xtime(a)
        b >>= 1
    return r


def _rotl8(x, n):
    return ((x << n) | (x >> (8 - n))) & 0xFF


def _build_sbox():
    sbox = [0] * 256
    for a in range(256):
        # invers perkalian di GF(2^8); 0 dipetakan ke 0
        inv = 0
        if a:
            for x in range(1, 256):
                if gmul(a, x) == 1:
                    inv = x
                    break
        # transformasi affine
        s = inv ^ _rotl8(inv, 1) ^ _rotl8(inv, 2) ^ _rotl8(inv, 3) ^ _rotl8(inv, 4) ^ 0x63
        sbox[a] = s
    inv_sbox = [0] * 256
    for i, v in enumerate(sbox):
        inv_sbox[v] = i
    return sbox, inv_sbox


SBOX, INV_SBOX = _build_sbox()


# ---------- Key expansion ----------
def expand_key(key):
    if len(key) != 16:
        raise ValueError("Key AES-128 harus tepat 16 byte")
    w = [list(key[4 * i:4 * i + 4]) for i in range(4)]
    rcon = 1
    for i in range(4, 4 * (NR + 1)):
        t = w[i - 1][:]
        if i % 4 == 0:
            t = t[1:] + t[:1]               # RotWord
            t = [SBOX[b] for b in t]        # SubWord
            t[0] ^= rcon
            rcon = xtime(rcon)
        w.append([w[i - 4][j] ^ t[j] for j in range(4)])
    # gabungkan jadi round key 16 byte per ronde
    return [sum(w[4 * r:4 * r + 4], []) for r in range(NR + 1)]


# ---------- Transformasi ronde (state = 16 byte, urutan kolom-mayor) ----------
def add_round_key(s, rk):
    return [s[i] ^ rk[i] for i in range(16)]


def sub_bytes(s):
    return [SBOX[b] for b in s]


def inv_sub_bytes(s):
    return [INV_SBOX[b] for b in s]


def shift_rows(s):
    out = [0] * 16
    for r in range(4):
        for c in range(4):
            out[r + 4 * c] = s[r + 4 * ((c + r) % 4)]
    return out


def inv_shift_rows(s):
    out = [0] * 16
    for r in range(4):
        for c in range(4):
            out[r + 4 * c] = s[r + 4 * ((c - r) % 4)]
    return out


def mix_columns(s):
    out = [0] * 16
    for c in range(4):
        a = s[4 * c:4 * c + 4]
        out[4 * c + 0] = gmul(a[0], 2) ^ gmul(a[1], 3) ^ a[2] ^ a[3]
        out[4 * c + 1] = a[0] ^ gmul(a[1], 2) ^ gmul(a[2], 3) ^ a[3]
        out[4 * c + 2] = a[0] ^ a[1] ^ gmul(a[2], 2) ^ gmul(a[3], 3)
        out[4 * c + 3] = gmul(a[0], 3) ^ a[1] ^ a[2] ^ gmul(a[3], 2)
    return out


def inv_mix_columns(s):
    out = [0] * 16
    for c in range(4):
        a = s[4 * c:4 * c + 4]
        out[4 * c + 0] = gmul(a[0], 14) ^ gmul(a[1], 11) ^ gmul(a[2], 13) ^ gmul(a[3], 9)
        out[4 * c + 1] = gmul(a[0], 9) ^ gmul(a[1], 14) ^ gmul(a[2], 11) ^ gmul(a[3], 13)
        out[4 * c + 2] = gmul(a[0], 13) ^ gmul(a[1], 9) ^ gmul(a[2], 14) ^ gmul(a[3], 11)
        out[4 * c + 3] = gmul(a[0], 11) ^ gmul(a[1], 13) ^ gmul(a[2], 9) ^ gmul(a[3], 14)
    return out


# ---------- Enkripsi / dekripsi satu blok ----------
def encrypt_block(block, round_keys):
    if len(block) != BLOCK:
        raise ValueError("Blok AES harus tepat 16 byte")
    s = add_round_key(list(block), round_keys[0])
    for r in range(1, NR):
        s = sub_bytes(s)
        s = shift_rows(s)
        s = mix_columns(s)
        s = add_round_key(s, round_keys[r])
    s = sub_bytes(s)
    s = shift_rows(s)
    s = add_round_key(s, round_keys[NR])
    return bytes(s)


def decrypt_block(block, round_keys):
    if len(block) != BLOCK:
        raise ValueError("Blok AES harus tepat 16 byte")
    s = add_round_key(list(block), round_keys[NR])
    for r in range(NR - 1, 0, -1):
        s = inv_shift_rows(s)
        s = inv_sub_bytes(s)
        s = add_round_key(s, round_keys[r])
        s = inv_mix_columns(s)
    s = inv_shift_rows(s)
    s = inv_sub_bytes(s)
    s = add_round_key(s, round_keys[0])
    return bytes(s)


# ---------- Padding PKCS#7 ----------
def pad(data):
    n = BLOCK - (len(data) % BLOCK)
    return data + bytes([n]) * n


def unpad(data):
    if not data or len(data) % BLOCK:
        raise ValueError("Panjang data tidak valid")
    n = data[-1]
    if n < 1 or n > BLOCK or data[-n:] != bytes([n]) * n:
        raise ValueError("Padding tidak valid (key salah atau data rusak)")
    return data[:-n]


# ---------- Mode CBC ----------
def _xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def encrypt_cbc(plaintext, key, iv=None):
    """Mengembalikan IV (16 byte) + ciphertext. IV acak per pesan, tidak rahasia."""
    if iv is None:
        iv = os.urandom(BLOCK)
    elif len(iv) != BLOCK:
        raise ValueError("IV harus tepat 16 byte")
    rks = expand_key(key)
    data = pad(plaintext)
    prev = iv
    out = []
    for i in range(0, len(data), BLOCK):
        blk = _xor(data[i:i + BLOCK], prev)
        prev = encrypt_block(blk, rks)
        out.append(prev)
    return iv + b"".join(out)


def decrypt_cbc(payload, key):
    """Input: IV (16 byte) + ciphertext."""
    if len(payload) < 2 * BLOCK or len(payload) % BLOCK:
        raise ValueError("Payload ciphertext tidak valid")
    rks = expand_key(key)
    iv, ct = payload[:BLOCK], payload[BLOCK:]
    prev = iv
    out = []
    for i in range(0, len(ct), BLOCK):
        blk = ct[i:i + BLOCK]
        out.append(_xor(decrypt_block(blk, rks), prev))
        prev = blk
    return unpad(b"".join(out))
