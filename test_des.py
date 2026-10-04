"""
Verifikasi implementasi DES manual dengan vektor uji klasik dan vektor pesan lengkap.

Tugas Keamanan Informasi - Muhammad Nabil Fauzan (5025241024)

Tes ini TIDAK memakai library kripto apa pun: semua nilai harapan ditulis langsung dalam hex
(vektor klasik DES, subkey contoh terkenal, dan vektor pesan CBC+PKCS#7 yang dihitung dengan
`openssl enc -des-cbc` sebagai pembanding independen).

Jalankan:  python test_des.py        atau        python -m unittest -v test_des
"""
import random
import unittest

import des
from des import (
    BLOCK, E, FP, IP, P, PC1, PC2, SBOXES, SHIFTS, decrypt_block, decrypt_cbc, encrypt_block,
    encrypt_cbc, expand_key, pad, unpad,
)

H = bytes.fromhex

# Key & IV untuk vektor pesan lengkap (dihitung dengan `openssl enc -des-cbc -K .. -iv ..`)
KEY = b"kunci123"
IV = H("0001020304050607")


def random_bytes(rng, n):
    return bytes(rng.getrandbits(8) for _ in range(n))


class TestTables(unittest.TestCase):
    """Pemeriksaan struktur tabel: menangkap salah ketik pada tabel DES."""

    def test_ukuran_dan_isi_tabel(self):
        self.assertEqual((len(IP), len(FP), len(E), len(P), len(PC1), len(PC2)), (64, 64, 48, 32, 56, 48))
        self.assertEqual(sorted(IP), list(range(1, 65)))
        self.assertEqual(sorted(FP), list(range(1, 65)))
        self.assertEqual(sorted(P), list(range(1, 33)))
        self.assertEqual(sorted(set(E)), list(range(1, 33)))
        self.assertTrue(all(p % 8 != 0 for p in PC1), "PC-1 harus membuang bit paritas (8, 16, ..., 64)")
        self.assertEqual(len(set(PC1)), 56)
        self.assertEqual(len(set(PC2)), 48)
        self.assertEqual((len(SHIFTS), sum(SHIFTS)), (16, 28))

    def test_ip_dan_fp_saling_berkebalikan(self):
        rng = random.Random(1)
        for _ in range(50):
            x = rng.getrandbits(64)
            self.assertEqual(des._permute(des._permute(x, IP, 64), FP, 64), x)

    def test_setiap_baris_sbox_adalah_permutasi_0_sampai_15(self):
        self.assertEqual(len(SBOXES), 8)
        for sb in SBOXES:
            self.assertEqual(len(sb), 64)
            for baris in range(4):
                self.assertEqual(sorted(sb[baris * 16:(baris + 1) * 16]), list(range(16)))


class TestKeySchedule(unittest.TestCase):
    def test_subkey_contoh_terkenal(self):
        sk = expand_key(H("133457799BBCDFF1"))
        self.assertEqual(len(sk), 16)
        self.assertEqual(sk[0], 0x1B02EFFC7072)    # K1
        self.assertEqual(sk[15], 0xCB3D8B0E17F5)   # K16
        self.assertTrue(all(0 <= k < 2 ** 48 for k in sk))

    def test_panjang_key_harus_8_byte(self):
        for n in (0, 7, 9, 16, 24):
            with self.assertRaises(ValueError):
                expand_key(bytes(n))


class TestBlockCipher(unittest.TestCase):
    def test_vektor_klasik(self):
        kasus = [
            ("133457799BBCDFF1", "0123456789ABCDEF", "85E813540F0AB405"),
            ("0123456789ABCDEF", "4E6F772069732074", "3FA40E8A984D4815"),  # "Now is t"
            ("0E329232EA6D0D73", "8787878787878787", "0000000000000000"),
            ("0101010101010101", "8000000000000000", "95F8A5E5DD31D900"),
        ]
        for key, pt, ct in kasus:
            sk = expand_key(H(key))
            self.assertEqual(encrypt_block(H(pt), sk), H(ct), key)
            self.assertEqual(decrypt_block(H(ct), sk), H(pt), key)

    def test_round_trip_acak(self):
        rng = random.Random(46)
        for _ in range(100):
            sk = expand_key(random_bytes(rng, 8))
            blk = random_bytes(rng, 8)
            self.assertEqual(decrypt_block(encrypt_block(blk, sk), sk), blk)

    def test_bit_paritas_key_tidak_berpengaruh(self):
        # Bit paling kanan tiap byte key adalah bit paritas dan dibuang PC-1 (56 bit efektif)
        key, blk = H("133457799BBCDFF1"), H("0123456789ABCDEF")
        key_lain = bytes(b ^ 1 for b in key)
        self.assertEqual(encrypt_block(blk, expand_key(key)), encrypt_block(blk, expand_key(key_lain)))

    def test_sifat_komplemen(self):
        # Sifat terkenal DES: E_{~K}(~P) = ~E_K(P)
        rng = random.Random(7)
        for _ in range(20):
            key, blk = random_bytes(rng, 8), random_bytes(rng, 8)
            inv = lambda b: bytes(x ^ 0xFF for x in b)
            self.assertEqual(
                encrypt_block(inv(blk), expand_key(inv(key))),
                inv(encrypt_block(blk, expand_key(key))),
            )

    def test_panjang_blok_harus_8_byte(self):
        sk = expand_key(KEY)
        for n in (0, 7, 9, 16):
            with self.assertRaises(ValueError):
                encrypt_block(bytes(n), sk)
            with self.assertRaises(ValueError):
                decrypt_block(bytes(n), sk)


class TestPadding(unittest.TestCase):
    def test_pad_selalu_menambah_1_sampai_8_byte(self):
        for n in range(0, 30):
            padded = pad(bytes(n))
            self.assertEqual(len(padded) % BLOCK, 0)
            self.assertEqual(len(padded) - n, BLOCK - n % BLOCK)
            self.assertEqual(unpad(padded), bytes(n))

    def test_padding_tidak_valid_ditolak(self):
        buruk = [
            b"",                          # kosong
            b"A" * 7,                     # bukan kelipatan 8
            b"A" * 7 + b"\x00",           # byte padding 0
            b"A" * 7 + b"\x09",           # byte padding > 8
            b"A" * 6 + b"\x01\x02",       # byte padding tidak konsisten
        ]
        for data in buruk:
            with self.assertRaises(ValueError, msg=repr(data)):
                unpad(data)


class TestCBC(unittest.TestCase):
    def test_vektor_pesan_lengkap_dari_openssl(self):
        kasus = [
            (b"Halo Bob!", "1a65ab7b2a3088d6cfc5a9f562eaff57"),
            (b"", "356d485cc0fad171"),
            (b"A" * 8, "08266c389d6019fddfe0f93935e43580"),
            ("Keamanan Informasi — 安全 \U0001F510".encode("utf-8"),
             "123601178113bc9000c9576ef904dd14fcbb20cb920e83781628800a757c532f"
             "307c10efafaf62d9"),
        ]
        for plaintext, ct_hex in kasus:
            payload = encrypt_cbc(plaintext, KEY, iv=IV)
            self.assertEqual(payload, IV + H(ct_hex), repr(plaintext))
            self.assertEqual(decrypt_cbc(payload, KEY), plaintext)

    def test_round_trip_berbagai_panjang_dan_utf8(self):
        pesan = ["", "a", "Halo ITS!", "x" * 7, "x" * 8, "x" * 9, "x" * 1000,
                 "Keamanan Informasi — 安全 \U0001F510"]
        for m in pesan:
            self.assertEqual(decrypt_cbc(encrypt_cbc(m.encode("utf-8"), KEY), KEY).decode("utf-8"), m)

    def test_iv_acak_membuat_ciphertext_berbeda(self):
        a, b = encrypt_cbc(b"pesan yang sama", KEY), encrypt_cbc(b"pesan yang sama", KEY)
        self.assertNotEqual(a, b)
        self.assertNotEqual(a[:8], b[:8], "IV harus acak per pesan")
        self.assertEqual(decrypt_cbc(a, KEY), decrypt_cbc(b, KEY))

    def test_iv_sama_hasilnya_deterministik(self):
        self.assertEqual(encrypt_cbc(b"x", KEY, iv=IV), encrypt_cbc(b"x", KEY, iv=IV))

    def test_iv_harus_8_byte(self):
        with self.assertRaises(ValueError):
            encrypt_cbc(b"x", KEY, iv=bytes(16))

    def test_key_salah_tidak_membuka_pesan(self):
        payload = encrypt_cbc(b"rahasia", KEY)
        try:
            hasil = decrypt_cbc(payload, b"kuncisal")
        except ValueError:
            return  # kasus umum: padding tidak valid
        self.assertNotEqual(hasil, b"rahasia")

    def test_payload_tidak_valid_ditolak(self):
        for payload in (b"", bytes(8), bytes(15), bytes(17)):
            with self.assertRaises(ValueError):
                decrypt_cbc(payload, KEY)

    def test_cbc_tidak_menjamin_integritas(self):
        # Membalik 1 bit di IV membalik bit yang sama di plaintext blok pertama, dan dekripsi tetap berhasil.
        payload = bytearray(encrypt_cbc(b"transfer 100 ke Bob", KEY, iv=IV))
        payload[0] ^= 0x01
        hasil = decrypt_cbc(bytes(payload), KEY)
        self.assertEqual(hasil[0], ord("t") ^ 0x01)
        self.assertEqual(hasil[1:], b"ransfer 100 ke Bob")


if __name__ == "__main__":
    unittest.main(verbosity=2)
