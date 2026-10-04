"""
Verifikasi implementasi AES manual dengan test vector resmi FIPS-197 & NIST SP 800-38A.

Tugas Keamanan Informasi - Muhammad Nabil Fauzan (5025241024)

Tes ini TIDAK memakai library kripto apa pun: semua nilai harapan ditulis langsung
dalam hex (vektor resmi NIST, dan vektor pesan lengkap yang dihitung dengan `openssl enc`
sebagai pembanding independen).

Jalankan:  python test_aes.py        atau        python -m unittest -v test_aes
"""
import random
import unittest

from aes import (
    BLOCK, INV_SBOX, SBOX, decrypt_block, decrypt_cbc, encrypt_block, encrypt_cbc,
    expand_key, gmul, pad, unpad, xtime,
)

H = bytes.fromhex

# Key & IV yang dipakai vektor pesan lengkap (dihitung dengan `openssl enc -aes-128-cbc -K .. -iv ..`)
KEY = b"kuncirahasia1234"
IV = H("000102030405060708090a0b0c0d0e0f")

# NIST SP 800-38A, F.2.1 (CBC-AES128.Encrypt)
SP_KEY = H("2b7e151628aed2a6abf7158809cf4f3c")
SP_PLAINTEXT = H(
    "6bc1bee22e409f96e93d7e117393172a" "ae2d8a571e03ac9c9eb76fac45af8e51"
    "30c81c46a35ce411e5fbc1191a0a52ef" "f69f2445df4f9b17ad2b417be66c3710"
)
SP_CIPHERTEXT = H(
    "7649abac8119b246cee98e9b12e9197d" "5086cb9b507219ee95db113a917678b2"
    "73bed6b8e3c1743b7116e69e22229516" "3ff1caa1681fac09120eca307586e1a7"
)
# Blok ke-5 = hasil enkripsi blok padding PKCS#7 penuh (16 x 0x10), dihitung dengan openssl
SP_PADDING_BLOCK = H("8cb82807230e1321d3fae00d18cc2012")


def random_bytes(rng, n):
    return bytes(rng.getrandbits(8) for _ in range(n))


class TestGaloisFieldAndSBox(unittest.TestCase):
    def test_xtime_dan_perkalian_fips197_bagian_4_2(self):
        self.assertEqual([xtime(0x57), xtime(0xAE), xtime(0x47), xtime(0x8E)], [0xAE, 0x47, 0x8E, 0x07])
        self.assertEqual(gmul(0x57, 0x13), 0xFE)
        self.assertEqual(gmul(0x57, 0x83), 0xC1)

    def test_nilai_sbox_resmi(self):
        self.assertEqual([SBOX[x] for x in (0x00, 0x01, 0x10, 0x53, 0xFF)], [0x63, 0x7C, 0xCA, 0xED, 0x16])
        self.assertEqual(INV_SBOX[0x63], 0x00)

    def test_sifat_sbox(self):
        self.assertEqual(sorted(SBOX), list(range(256)), "S-box harus permutasi 0..255")
        self.assertTrue(all(INV_SBOX[SBOX[x]] == x for x in range(256)))
        self.assertTrue(all(SBOX[x] != x and SBOX[x] != x ^ 0xFF for x in range(256)), "tanpa fixed point")


class TestKeyExpansion(unittest.TestCase):
    def test_round_key_fips197_appendix_a1(self):
        rks = expand_key(SP_KEY)
        self.assertEqual(len(rks), 11)
        self.assertEqual(bytes(rks[0]), SP_KEY)
        self.assertEqual(bytes(rks[1]), H("a0fafe1788542cb123a339392a6c7605"))
        self.assertEqual(bytes(rks[10]), H("d014f9a8c9ee2589e13f0cc8b6630ca6"))

    def test_panjang_key_harus_16_byte(self):
        for n in (0, 8, 15, 17, 24, 32):
            with self.assertRaises(ValueError):
                expand_key(bytes(n))


class TestBlockCipher(unittest.TestCase):
    def test_fips197_appendix_b(self):
        pt, ct = H("3243f6a8885a308d313198a2e0370734"), H("3925841d02dc09fbdc118597196a0b32")
        rks = expand_key(SP_KEY)
        self.assertEqual(encrypt_block(pt, rks), ct)
        self.assertEqual(decrypt_block(ct, rks), pt)

    def test_fips197_appendix_c1(self):
        rks = expand_key(H("000102030405060708090a0b0c0d0e0f"))
        pt, ct = H("00112233445566778899aabbccddeeff"), H("69c4e0d86a7b0430d8cdb78070b4c55a")
        self.assertEqual(encrypt_block(pt, rks), ct)
        self.assertEqual(decrypt_block(ct, rks), pt)

    def test_round_trip_acak(self):
        rng = random.Random(2026)
        for _ in range(100):
            rks = expand_key(random_bytes(rng, 16))
            blk = random_bytes(rng, 16)
            self.assertEqual(decrypt_block(encrypt_block(blk, rks), rks), blk)

    def test_panjang_blok_harus_16_byte(self):
        rks = expand_key(KEY)
        for n in (0, 15, 17):
            with self.assertRaises(ValueError):
                encrypt_block(bytes(n), rks)
            with self.assertRaises(ValueError):
                decrypt_block(bytes(n), rks)


class TestPadding(unittest.TestCase):
    def test_pad_selalu_menambah_1_sampai_16_byte(self):
        for n in range(0, 40):
            padded = pad(bytes(n))
            self.assertEqual(len(padded) % BLOCK, 0)
            self.assertEqual(len(padded) - n, BLOCK - n % BLOCK)
            self.assertEqual(unpad(padded), bytes(n))

    def test_padding_tidak_valid_ditolak(self):
        buruk = [
            b"",                                  # kosong
            b"A" * 15,                            # bukan kelipatan 16
            b"A" * 15 + b"\x00",                  # byte padding 0
            b"A" * 15 + b"\x11",                  # byte padding > 16
            b"A" * 14 + b"\x01\x02",              # byte padding tidak konsisten
        ]
        for data in buruk:
            with self.assertRaises(ValueError, msg=repr(data)):
                unpad(data)


class TestCBC(unittest.TestCase):
    def test_nist_sp800_38a_f21_empat_blok(self):
        payload = encrypt_cbc(SP_PLAINTEXT, SP_KEY, iv=IV)
        self.assertEqual(payload[:16], IV)
        self.assertEqual(payload[16:80], SP_CIPHERTEXT)
        self.assertEqual(payload[80:], SP_PADDING_BLOCK)  # blok padding PKCS#7 penuh
        self.assertEqual(decrypt_cbc(payload, SP_KEY), SP_PLAINTEXT)

    def test_vektor_pesan_lengkap_dari_openssl(self):
        kasus = [
            (b"Halo Bob!", "50e5bffd73bc04bd3c63c35269e90044"),
            (b"", "4af911409d9bc8ad0272970b1c8d0281"),
            (b"A" * 16, "530ab722dc11d65771a4258bca5341bad0bf66aceb72f11820119118e3b084a7"),
            ("Keamanan Informasi — 安全 \U0001F510".encode("utf-8"),
             "b6dcaaeb653ccab27ac87a785b5c2932e94f432e4430d5116f6a24660ec21f12"
             "bd4f29d2fa9bb4f1d9498e050aa9637f"),
        ]
        for plaintext, ct_hex in kasus:
            payload = encrypt_cbc(plaintext, KEY, iv=IV)
            self.assertEqual(payload, IV + H(ct_hex), repr(plaintext))
            self.assertEqual(decrypt_cbc(payload, KEY), plaintext)

    def test_round_trip_berbagai_panjang_dan_utf8(self):
        pesan = ["", "a", "Halo ITS!", "x" * 15, "x" * 16, "x" * 17, "x" * 1000,
                 "Keamanan Informasi — 安全 \U0001F510"]
        for m in pesan:
            self.assertEqual(decrypt_cbc(encrypt_cbc(m.encode("utf-8"), KEY), KEY).decode("utf-8"), m)

    def test_iv_acak_membuat_ciphertext_berbeda(self):
        a, b = encrypt_cbc(b"pesan yang sama", KEY), encrypt_cbc(b"pesan yang sama", KEY)
        self.assertNotEqual(a, b)
        self.assertNotEqual(a[:16], b[:16], "IV harus acak per pesan")
        self.assertEqual(decrypt_cbc(a, KEY), decrypt_cbc(b, KEY))

    def test_iv_sama_hasilnya_deterministik(self):
        self.assertEqual(encrypt_cbc(b"x", KEY, iv=IV), encrypt_cbc(b"x", KEY, iv=IV))

    def test_iv_harus_16_byte(self):
        with self.assertRaises(ValueError):
            encrypt_cbc(b"x", KEY, iv=bytes(8))

    def test_key_salah_tidak_membuka_pesan(self):
        payload = encrypt_cbc(b"rahasia", KEY)
        try:
            hasil = decrypt_cbc(payload, b"kuncisalahbanget")
        except ValueError:
            return  # kasus umum: padding tidak valid
        self.assertNotEqual(hasil, b"rahasia")

    def test_payload_tidak_valid_ditolak(self):
        for payload in (b"", bytes(16), bytes(31), bytes(33)):
            with self.assertRaises(ValueError):
                decrypt_cbc(payload, KEY)

    def test_cbc_tidak_menjamin_integritas(self):
        # Batasan yang perlu dipahami: membalik 1 bit di IV membalik bit yang sama di plaintext blok 1,
        # dan dekripsi tetap "berhasil". Integritas butuh MAC (di luar cakupan tugas).
        payload = bytearray(encrypt_cbc(b"transfer 100 ke Bob", KEY, iv=IV))
        payload[0] ^= 0x01
        hasil = decrypt_cbc(bytes(payload), KEY)
        self.assertEqual(hasil[0], ord("t") ^ 0x01)
        self.assertEqual(hasil[1:], b"ransfer 100 ke Bob")


if __name__ == "__main__":
    unittest.main(verbosity=2)
