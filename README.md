# Tugas Individu Keamanan Informasi: Komunikasi Ciphertext Dua Arah

**Nama:** Muhammad Nabil Fauzan  **NRP:** 5025241024  
**Departemen:** Teknik Informatika, ITS

## Ringkasan

Simulasi transmisi ciphertext dua arah antara dua pihak (Sender dan Receiver) yang berjalan
sebagai **dua proses terpisah** dan berkomunikasi lewat **TCP socket**. Algoritma **AES-128 mode
CBC dengan padding PKCS#7 diimplementasikan manual**, tanpa library enkripsi/dekripsi.
Bahasa: Python 3 (diuji di Python 3.13, seharusnya jalan di 3.7 ke atas), tanpa `pip install`.

Library yang dipakai hanya bawaan Python: `socket`, `threading`, `struct`, `argparse`, `sys`,
`time`, dan `os` (`os.urandom` hanya untuk membangkitkan IV acak, bukan fungsi enkripsi).

## Pemenuhan ketentuan tugas

| # | Ketentuan | Pemenuhan |
|---|-----------|-----------|
| 1 | Komunikasi dua arah | Setiap peer punya thread terima dan loop kirim, jadi keduanya bisa menjadi sender sekaligus receiver. Key yang sama dipakai untuk kedua arah. |
| 2 | Key sudah diketahui kedua pihak, tidak dikirim | Key diberikan lewat `--key` di masing-masing sisi dan tidak pernah masuk ke paket. Tes `test_e2e.py` merekam byte di kabel dan memastikan key (teks maupun hex) tidak ada di sana. |
| 3 | Bukan satu skrip yang enkripsi dan dekripsi di satu tempat | Dua proses terpisah (dua terminal, VM, atau dua komputer). Data benar-benar lewat socket TCP. |
| 4 | Bahasa bebas | Python 3 |
| 5 | Tanpa library enkripsi siap pakai | `aes.py` ditulis sendiri: aritmetika GF(2^8), S-box yang dihitung dari definisinya, KeyExpansion, SubBytes, ShiftRows, MixColumns, AddRoundKey, mode CBC, padding PKCS#7. |
| 6 | Demo langsung | Lihat "Skenario demo" di bawah. Layar menampilkan plaintext, IV, ciphertext, dan hasil dekripsi di kedua sisi. |

## Struktur file

| File | Isi |
|------|-----|
| `aes.py` | AES-128, CBC, dan PKCS#7 buatan sendiri |
| `peer.py` | Program komunikasi. Satu instance adalah satu pihak (`--listen` atau `--connect`) |
| `sniffer.py` | Penyadap pasif opsional untuk memperlihatkan isi kabel saat demo |
| `test_aes.py` | 20 tes: vektor resmi FIPS-197 dan NIST SP 800-38A, vektor pesan lengkap dari OpenSSL, padding, IV |
| `test_e2e.py` | 6 tes dua proses: dua arah, kabel hanya ciphertext, key tidak terkirim, key salah, putus koneksi, sniffer |

## Cara menjalankan

Key harus 16 karakter (atau 32 digit hex) dan sama di kedua sisi. Di Windows pakai `python`
atau `py`; di Linux/macOS pakai `python3`.

### Satu komputer (logical, dua terminal)

```
# Terminal 1
python peer.py --name Alice --listen 5000 --key kuncirahasia1234

# Terminal 2
python peer.py --name Bob --connect 127.0.0.1:5000 --key kuncirahasia1234
```

Ketik pesan lalu Enter. `/quit` untuk keluar; sisi yang satunya ikut berhenti otomatis.
Jika port 5000 terpakai (di macOS biasanya dipakai AirPlay), ganti ke port lain, misalnya 5050.

### Dua komputer atau dua VM (physical)

1. Di komputer A: `python peer.py --name Alice --listen 5000 --key kuncirahasia1234`
2. Cari IP komputer A (`ipconfig` di Windows, `hostname -I` di Linux).
3. Di komputer B: `python peer.py --name Bob --connect <IP-komputer-A>:5000 --key kuncirahasia1234`

Key diketik sendiri di masing-masing komputer, tidak lewat jaringan. Jika koneksi gagal, cek
firewall di komputer A (izinkan Python atau port 5000, di Windows pilih jaringan Private).
Untuk VM, pakai Bridged Adapter atau jaringan Host-only/Internal agar kedua VM saling terlihat.

### Melihat isi kabel dengan sniffer (opsional)

```
# Terminal 1
python peer.py --name Alice --listen 5000 --key kuncirahasia1234
# Terminal 2 (sniffer di tengah)
python sniffer.py --listen 6000 --target 127.0.0.1:5000
# Terminal 3 (Bob mengira terhubung ke Alice, padahal lewat sniffer)
python peer.py --name Bob --connect 127.0.0.1:6000 --key kuncirahasia1234
```

### Menjalankan tes

```
python test_aes.py        # 20 tes AES/CBC/padding, di bawah 1 detik
python test_e2e.py        # 6 tes dua proses, sekitar 7 detik
```

## Contoh keluaran (hasil jalan sungguhan)

Terminal Bob (mengirim pesan, lalu menerima balasan):

```
[Bob] Key dimuat: AES-128, KCV=70494e (key TIDAK dikirim lewat jaringan; KCV sama di kedua sisi berarti key sama)
[Bob] Terhubung ke 127.0.0.1:5000
[Bob] >> plaintext        : Halo Alice, ini pesan rahasia dari Bob
[Bob] >> IV (acak)        : 4b0420c51c2d6c96ea1dfd9c83606900
[Bob] >> KIRIM ciphertext : 4f29b7402294c87c61a7d8b894c79a4a229246711c77f558a5397a4fba9d6759716dfaa40937e605283b15c8de43505f
[Bob] >> ukuran paket     : 68 byte = 4 (panjang) + 16 (IV) + 48 (ciphertext)

[Bob] << DITERIMA paket    : 52 byte = 4 (panjang) + 16 (IV) + 32 (ciphertext)
[Bob] << IV                : f6bfc8a2bd866fe3338bb15e5cf4336b
[Bob] << ciphertext (hex)  : b30ef15203f6049f8609010456aa6730eb448eb5cbd3adb2258508822ccac2a8
[Bob] << DEKRIPSI -> plaintext: Halo Bob, pesan diterima!
```

Terminal Alice (menerima, lalu membalas). IV dan ciphertext sama persis dengan yang dikirim Bob:

```
[Alice] << DITERIMA paket    : 68 byte = 4 (panjang) + 16 (IV) + 48 (ciphertext)
[Alice] << IV                : 4b0420c51c2d6c96ea1dfd9c83606900
[Alice] << ciphertext (hex)  : 4f29b7402294c87c61a7d8b894c79a4a229246711c77f558a5397a4fba9d6759716dfaa40937e605283b15c8de43505f
[Alice] << DEKRIPSI -> plaintext: Halo Alice, ini pesan rahasia dari Bob
[Alice] >> plaintext        : Halo Bob, pesan diterima!
...
```

Terminal sniffer. Hanya byte acak yang terlihat, empat byte pertama (`00 00 00 40`) adalah
panjang paket (64), lalu IV, lalu ciphertext:

```
[SNIFFER] klien -> server: 68 byte lewat
    0000  00 00 00 40 3f ca ad 92 50 44 35 28 5e 8a 74 34  |...@?...PD5(^.t4|
    0010  fe 46 64 ad 76 e8 89 78 63 e9 d3 f5 3e 08 d1 96  |.Fd.v..xc...>...|
    ...
```

Jika key berbeda (misalnya Bob memakai `--key kuncisalahbanget`), Alice menampilkan:

```
[Alice] << Gagal dekripsi: Padding tidak valid (key salah atau data rusak)
```

## Format paket di jaringan

```
[ 4 byte panjang (big-endian) ][ 16 byte IV acak ][ ciphertext (kelipatan 16 byte) ]
```

Panjang di 4 byte pertama dipakai penerima untuk memotong aliran TCP menjadi pesan utuh.
IV dibuat acak untuk setiap pesan dan boleh dikirim terbuka karena bukan rahasia. Key tidak dikirim.

## Cara kerja singkat (bahan penjelasan saat demo)

**Alur kirim:** teks diubah ke byte UTF-8, diberi padding PKCS#7 sampai kelipatan 16 byte,
dienkripsi blok demi blok dengan CBC, lalu dikirim sebagai paket di atas. **Alur terima:** baca
4 byte panjang, baca isi paket, pisahkan IV dan ciphertext, dekripsi CBC, buang padding, ubah
ke teks.

**AES-128:** blok 16 byte disusun sebagai matriks state 4x4 dan diproses 10 ronde.

- *SubBytes*: setiap byte diganti lewat S-box. S-box tidak ditulis sebagai tabel hasil salin,
  tetapi dihitung dari definisinya: invers perkalian di GF(2^8), lalu transformasi affine.
- *ShiftRows*: baris ke-r digeser ke kiri sebanyak r posisi.
- *MixColumns*: setiap kolom dikalikan matriks tetap di GF(2^8). Ronde terakhir tidak memakainya.
- *AddRoundKey*: state di-XOR dengan round key.
- *KeyExpansion*: key 16 byte diperluas menjadi 11 round key (RotWord, SubWord, Rcon).
- Dekripsi memakai kebalikan setiap langkah dengan urutan terbalik.

**CBC:** `C0 = IV`, `Ci = E(Pi XOR C(i-1))`, dan saat dekripsi `Pi = D(Ci) XOR C(i-1)`.
**PKCS#7:** tambahkan n byte bernilai n (n antara 1 dan 16), bahkan jika panjang data sudah
kelipatan 16, sehingga padding selalu bisa dibuang dengan tepat.

**KCV (Key Check Value):** 3 byte pertama dari hasil enkripsi blok nol dengan key tersebut.
Dipakai untuk menunjukkan bahwa kedua sisi memegang key yang sama tanpa menampilkan key-nya.

## Skenario demo (sekitar 5 menit)

1. Jalankan `python test_aes.py`: 20 tes lulus, termasuk cocok dengan vektor resmi FIPS-197 dan NIST SP 800-38A.
2. Buka dua terminal (Alice dan Bob) seperti di atas. Tunjukkan KCV sama di kedua sisi.
3. Bob mengirim pesan. Tunjukkan IV dan ciphertext di layar Bob sama persis dengan di layar Alice, lalu plaintext hasil dekripsi.
4. Alice membalas (arah sebaliknya), dan tunjukkan hal yang sama.
5. Kirim pesan yang sama dua kali. Ciphertext berbeda karena IV acak per pesan.
6. Opsional: jalankan lewat `sniffer.py` dan tunjukkan bahwa di kabel hanya ada byte acak.
7. Opsional: jalankan satu sisi dengan key berbeda dan tunjukkan "Gagal dekripsi".
8. Ketik `/quit` di satu sisi. Sisi lain berhenti sendiri.

## Pertanyaan yang mungkin muncul

**Mengapa IV ikut dikirim padahal key tidak?** IV bukan rahasia. Ia hanya perlu acak dan
berbeda untuk setiap pesan, supaya plaintext yang sama menghasilkan ciphertext berbeda. Penerima
membutuhkannya untuk mendekripsi blok pertama. Yang rahasia adalah key, dan key tidak pernah dikirim.

**Mengapa CBC, bukan ECB?** Pada ECB, blok plaintext yang sama menghasilkan ciphertext yang
sama sehingga pola data bocor. CBC merantai blok dan memakai IV acak.

**Dari mana S-box?** Dihitung di `aes.py` dari definisi FIPS-197, lalu dicek di `test_aes.py`
terhadap nilai resmi dan sifat-sifatnya (permutasi, tanpa fixed point).

**Bagaimana membuktikan implementasinya benar?** Cocok dengan vektor resmi FIPS-197 dan NIST
SP 800-38A. Selain itu hasilnya sudah saya bandingkan dengan OpenSSL (di luar program ini)
pada ratusan kasus acak, dalam dua arah: ciphertext buatan program ini bisa dibuka OpenSSL,
dan sebaliknya.

**Bagaimana kalau key berbeda?** Dekripsi menghasilkan data acak. Hampir selalu padding tidak
valid sehingga muncul "Gagal dekripsi". Sesekali padding kebetulan lolos (peluang sekitar 1
dari 256), tetapi hasilnya tetap bukan teks asli.

**Library apa yang dipakai?** Hanya library standar Python untuk jaringan dan thread. Tidak ada
library enkripsi, hash, maupun TLS. `os.urandom` hanya membuat IV acak.

## Catatan keamanan dan batasan

- CBC hanya menjamin kerahasiaan, bukan integritas atau keaslian pengirim (tidak ada MAC).
  `test_aes.py` memuat tes yang memperlihatkan bahwa membalik satu bit di IV mengubah plaintext
  tanpa terdeteksi. Pengamanan lebih lanjut butuh MAC atau mode AEAD seperti GCM.
- Key dibagikan manual sebelumnya sesuai ketentuan tugas. Pertukaran key otomatis (misalnya
  RSA atau Diffie-Hellman) tidak termasuk di tugas ini.
- `--key` di command line bisa terlihat di riwayat shell dan daftar proses. Cukup untuk demo.
- AES ditulis dengan Python murni (sekitar 9 ms per 1 KB), jadi cukup untuk chat tetapi bukan
  untuk data besar. Ukuran satu pesan dibatasi sekitar 1 MB.
- Implementasi ini untuk pembelajaran, bukan untuk produksi.

## Referensi

- NIST FIPS 197, *Advanced Encryption Standard (AES)*
- NIST SP 800-38A, *Recommendation for Block Cipher Modes of Operation: Methods and Techniques*
