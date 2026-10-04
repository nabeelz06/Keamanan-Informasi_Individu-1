"""
DES (Data Encryption Standard) implementasi manual (tanpa library kripto) + mode CBC + padding PKCS#7.

Tugas Keamanan Informasi - Muhammad Nabil Fauzan (5025241024)

Mengacu pada FIPS 46-3. Semua komponen ditulis sendiri:
- Permutasi awal dan akhir (IP, FP), ekspansi E, permutasi P
- 8 S-box (6 bit masuk, 4 bit keluar)
- Key schedule: PC-1, rotasi kiri, PC-2 (16 subkey, masing-masing 48 bit)
- Jaringan Feistel 16 ronde
- Mode CBC dan padding PKCS#7 (blok 8 byte)

Key DES berukuran 8 byte (64 bit), tetapi 8 bit paritas dibuang oleh PC-1 sehingga yang efektif
hanya 56 bit. Antarmuka sengaja dibuat sama dengan aes.py agar peer.py bisa memilih algoritma
lewat --cipher.
"""

import os

BLOCK = 8      # ukuran blok DES: 64 bit
KEY_SIZE = 8   # ukuran key: 64 bit (termasuk 8 bit paritas)

# Semua tabel di bawah memakai penomoran bit FIPS 46-3: bit nomor 1 adalah bit paling kiri (MSB).

# Permutasi awal (Initial Permutation)
IP = [
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7,
]

# Permutasi akhir (Final Permutation = kebalikan IP)
FP = [
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9, 49, 17, 57, 25,
]

# Ekspansi E: 32 bit menjadi 48 bit
E = [
    32, 1, 2, 3, 4, 5,
    4, 5, 6, 7, 8, 9,
    8, 9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32, 1,
]

# Permutasi P setelah S-box (32 bit)
P = [
    16, 7, 20, 21, 29, 12, 28, 17,
    1, 15, 23, 26, 5, 18, 31, 10,
    2, 8, 24, 14, 32, 27, 3, 9,
    19, 13, 30, 6, 22, 11, 4, 25,
]

# Permuted Choice 1: 64 bit key menjadi 56 bit (membuang 8 bit paritas)
PC1 = [
    57, 49, 41, 33, 25, 17, 9,
    1, 58, 50, 42, 34, 26, 18,
    10, 2, 59, 51, 43, 35, 27,
    19, 11, 3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
    7, 62, 54, 46, 38, 30, 22,
    14, 6, 61, 53, 45, 37, 29,
    21, 13, 5, 28, 20, 12, 4,
]

# Permuted Choice 2: 56 bit menjadi subkey 48 bit
PC2 = [
    14, 17, 11, 24, 1, 5,
    3, 28, 15, 6, 21, 10,
    23, 19, 12, 4, 26, 8,
    16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32,
]

# Jumlah rotasi kiri per ronde pada key schedule
SHIFTS = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

# 8 S-box. Tiap S-box 4 baris x 16 kolom, disimpan berurutan per baris (indeks = baris*16 + kolom).
SBOXES = [
    [  # S1
        14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
        0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
        4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
        15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13,
    ],
    [  # S2
        15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
        3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
        0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
        13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9,
    ],
    [  # S3
        10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
        13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
        13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
        1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12,
    ],
    [  # S4
        7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
        13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
        10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
        3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14,
    ],
    [  # S5
        2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
        14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
        4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
        11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3,
    ],
    [  # S6
        12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
        10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
        9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
        4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13,
    ],
    [  # S7
        4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
        13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
        1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
        6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12,
    ],
    [  # S8
        13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
        1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
        7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
        2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11,
    ],
]


def _permute(value, table, in_bits):
    """Susun ulang bit: bit ke-i hasil adalah bit nomor table[i] dari input (nomor 1 = bit paling kiri)."""
    out = 0
    for pos in table:
        out = (out << 1) | ((value >> (in_bits - pos)) & 1)
    return out


# ---------- Key schedule ----------
def expand_key(key):
    """Dari key 8 byte menjadi 16 subkey 48 bit (berupa integer)."""
    if len(key) != KEY_SIZE:
        raise ValueError("Key DES harus tepat 8 byte")
    k = _permute(int.from_bytes(key, "big"), PC1, 64)   # 56 bit
    c, d = k >> 28, k & 0xFFFFFFF                        # dua setengah 28 bit
    subkeys = []
    for s in SHIFTS:
        c = ((c << s) | (c >> (28 - s))) & 0xFFFFFFF     # rotasi kiri 28 bit
        d = ((d << s) | (d >> (28 - s))) & 0xFFFFFFF
        subkeys.append(_permute((c << 28) | d, PC2, 56))
    return subkeys


# ---------- Fungsi ronde Feistel ----------
def _feistel(r, subkey):
    """f(R, K): ekspansi E, XOR subkey, delapan S-box, lalu permutasi P."""
    x = _permute(r, E, 32) ^ subkey                      # 48 bit
    out = 0
    for i in range(8):
        enam = (x >> (42 - 6 * i)) & 0x3F                # 6 bit untuk S-box ke-i
        baris = ((enam & 0x20) >> 4) | (enam & 1)        # bit paling kiri dan paling kanan
        kolom = (enam >> 1) & 0xF                        # empat bit di tengah
        out = (out << 4) | SBOXES[i][baris * 16 + kolom]
    return _permute(out, P, 32)


def _crypt_block(block, subkeys):
    if len(block) != BLOCK:
        raise ValueError("Blok DES harus tepat 8 byte")
    v = _permute(int.from_bytes(block, "big"), IP, 64)
    l, r = v >> 32, v & 0xFFFFFFFF
    for k in subkeys:                                    # 16 ronde Feistel
        l, r = r, l ^ _feistel(r, k)
    v = (r << 32) | l                                    # tukar setengah terakhir sebelum FP
    return _permute(v, FP, 64).to_bytes(8, "big")


# ---------- Enkripsi / dekripsi satu blok ----------
def encrypt_block(block, subkeys):
    return _crypt_block(block, subkeys)


def decrypt_block(block, subkeys):
    # Struktur Feistel: dekripsi = proses yang sama dengan urutan subkey dibalik
    return _crypt_block(block, subkeys[::-1])


# ---------- Padding PKCS#7 (blok 8 byte) ----------
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
    """Mengembalikan IV (8 byte) + ciphertext. IV acak per pesan, tidak rahasia."""
    if iv is None:
        iv = os.urandom(BLOCK)
    elif len(iv) != BLOCK:
        raise ValueError("IV harus tepat 8 byte")
    subkeys = expand_key(key)
    data = pad(plaintext)
    prev = iv
    out = []
    for i in range(0, len(data), BLOCK):
        blk = _xor(data[i:i + BLOCK], prev)
        prev = encrypt_block(blk, subkeys)
        out.append(prev)
    return iv + b"".join(out)


def decrypt_cbc(payload, key):
    """Input: IV (8 byte) + ciphertext."""
    if len(payload) < 2 * BLOCK or len(payload) % BLOCK:
        raise ValueError("Payload ciphertext tidak valid")
    subkeys = expand_key(key)
    iv, ct = payload[:BLOCK], payload[BLOCK:]
    prev = iv
    out = []
    for i in range(0, len(ct), BLOCK):
        blk = ct[i:i + BLOCK]
        out.append(_xor(decrypt_block(blk, subkeys), prev))
        prev = blk
    return unpad(b"".join(out))
