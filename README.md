# Tugas Individu Keamanan Informasi: Komunikasi Ciphertext Dua Arah

**Nama:** Muhammad Nabil Fauzan  **NRP:** 5025241024  
**Departemen:** Teknik Informatika, ITS

## Ringkasan

Simulasi transmisi ciphertext dua arah antara dua pihak (Sender dan Receiver) yang berjalan
sebagai **dua proses terpisah** (dua terminal, dua VM, atau dua komputer) dan berkomunikasi lewat
**TCP socket**. Enkripsi dan dekripsi **diimplementasikan manual**, tanpa library enkripsi/dekripsi:
**DES** (bawaan) dan **AES-128**, keduanya dengan mode **CBC** dan padding **PKCS#7**. Algoritma
dipilih dengan `--cipher des` atau `--cipher aes`.

Bahasa: Python 3 (diuji di Python 3.13, seharusnya jalan di 3.7 ke atas), tanpa `pip install`.
Library yang dipakai hanya bawaan Python: `socket`, `threading`, `struct`, `argparse`, `sys`,
`time`, dan `os` (`os.urandom` hanya untuk membangkitkan IV acak, bukan fungsi enkripsi).

## Pemenuhan ketentuan tugas

| # | Ketentuan | Pemenuhan |
|---|-----------|-----------|
| 1 | Komunikasi dua arah | Setiap peer punya thread terima dan loop kirim, jadi keduanya bisa menjadi sender sekaligus receiver. Key yang sama dipakai untuk kedua arah. |
| 2 | Key sudah diketahui kedua pihak, tidak dikirim | Key diberikan lewat `--key` di masing-masing sisi dan tidak pernah masuk ke paket. Tes `test_e2e.py` merekam byte di kabel dan memastikan key (teks maupun hex) tidak ada di sana. |
| 3 | Bukan satu skrip yang enkripsi dan dekripsi di satu tempat | Dua proses terpisah (dua terminal, VM, atau komputer). Data benar-benar lewat socket TCP. |
| 4 | Bahasa bebas | Python 3 |
| 5 | Tanpa library enkripsi siap pakai | `des.py` dan `aes.py` ditulis sendiri. DES: IP, FP, ekspansi E, 8 S-box, permutasi P, key schedule (PC-1, rotasi, PC-2), 16 ronde Feistel. AES: GF(2^8), S-box yang dihitung, KeyExpansion, SubBytes, ShiftRows, MixColumns, AddRoundKey. Keduanya dengan CBC dan PKCS#7 buatan sendiri. |
| 6 | Demo langsung | Lihat "Skenario demo" di bawah. Layar menampilkan plaintext, IV, ciphertext, dan hasil dekripsi di kedua sisi. |

## Struktur file

| File | Isi |
|------|-----|
| `des.py` | DES, CBC, dan PKCS#7 (blok 8 byte) buatan sendiri |
| `aes.py` | AES-128, CBC, dan PKCS#7 (blok 16 byte) buatan sendiri |
| `peer.py` | Program komunikasi. Satu instance adalah satu pihak (`--listen` atau `--connect`) |
| `sniffer.py` | Penyadap pasif opsional untuk memperlihatkan isi kabel saat demo |
| `test_des.py` | 20 tes DES: vektor klasik, subkey contoh terkenal, struktur tabel, vektor pesan dari OpenSSL |
| `test_aes.py` | 20 tes AES: vektor FIPS-197 dan NIST SP 800-38A, vektor pesan dari OpenSSL |
| `test_e2e.py` | 14 tes dua proses (7 skenario, masing-masing untuk DES dan AES) |

## Pilihan algoritma dan key

| `--cipher` | Algoritma | Blok dan IV | `--key` |
|------------|-----------|-------------|---------|
| `des` (bawaan) | DES-CBC | 8 byte | 8 karakter, atau 16 digit hex |
| `aes` | AES-128-CBC | 16 byte | 16 karakter, atau 32 digit hex |

Kedua sisi harus memakai `--cipher` dan `--key` yang sama. Jika berbeda, penerima menampilkan
"Gagal dekripsi" dan tidak pernah menampilkan plaintext.

## Cara menjalankan

Di Windows pakai `python` atau `py`; di Linux/macOS pakai `python3`.

### Satu komputer (logical, dua terminal)

```
# Terminal 1 (Receiver, jalankan lebih dulu)
python peer.py --cipher des --name Receiver --listen 5000 --key kunci123

# Terminal 2 (Sender)
python peer.py --cipher des --name Sender --connect 127.0.0.1:5000 --key kunci123
```

Ketik pesan lalu Enter. Komunikasinya dua arah: Receiver juga bisa mengetik balasan. `/quit` untuk
keluar; sisi yang satunya ikut berhenti otomatis. Untuk AES ganti `--cipher aes` dan pakai key 16
karakter, misalnya `kuncirahasia1234`. Jika port 5000 terpakai (di macOS biasanya dipakai AirPlay),
ganti ke port lain, misalnya 5050.

### Dua VM (VirtualBox atau VMware)

1. **Jaringan VM.** Kedua VM harus bisa saling ping. VirtualBox: pada Settings > Network pakai
   *Bridged Adapter*, atau *Host-only Adapter* untuk kedua VM, atau *NAT Network*. Jangan pakai NAT
   biasa karena kedua VM tidak saling terlihat. VMware: NAT, Host-only, atau Bridged semuanya bisa.
   Jika Wi-Fi kampus memblokir Bridged, pakai Host-only.
2. **Cek IP** di VM Receiver: `ip a` atau `hostname -I` (Linux), `ipconfig` (Windows). Misalnya
   `192.168.56.102`. Dari VM Sender uji dengan `ping 192.168.56.102`.
3. **Salin proyek** ke kedua VM (shared folder, drag and drop, `scp -r ki-secure-chat user@IP:~/`,
   atau flash disk). Python 3 biasanya sudah ada di Ubuntu (`python3 --version`); di Windows install
   dari python.org.
4. **VM Receiver** (jalankan lebih dulu):
   `python3 peer.py --cipher des --name Receiver --listen 5000 --key kunci123`
5. **VM Sender:**
   `python3 peer.py --cipher des --name Sender --connect 192.168.56.102:5000 --key kunci123`
6. Key diketik sendiri di masing-masing VM, tidak lewat jaringan. Cek bahwa **KCV sama** di kedua layar.

Jika muncul "Gagal terhubung": pastikan Receiver sudah berjalan, IP benar, `ping` berhasil, dan
firewall tidak memblokir port 5000 (Ubuntu dengan ufw: `sudo ufw allow 5000/tcp`; Windows: izinkan
Python pada dialog firewall, pilih jaringan Private). Jika hanya punya satu VM, jadikan komputer
host sebagai Receiver dan VM sebagai Sender (pada VirtualBox Host-only, alamat host biasanya
`192.168.56.1`; cek dengan `ipconfig` atau `ip a` di host).

### Melihat isi kabel dengan sniffer (opsional)

```
# Terminal 1
python peer.py --cipher des --name Receiver --listen 5000 --key kunci123
# Terminal 2 (sniffer di tengah)
python sniffer.py --listen 6000 --target 127.0.0.1:5000
# Terminal 3 (Sender mengira terhubung ke Receiver, padahal lewat sniffer)
python peer.py --cipher des --name Sender --connect 127.0.0.1:6000 --key kunci123
```

Di dua VM, jalankan sniffer di VM Receiver (`--target 127.0.0.1:5000`), lalu Sender menyambung
ke IP VM Receiver pada port sniffer, yaitu `--connect IP_RECEIVER:6000`, bukan port 5000.

### Menjalankan tes

```
python test_des.py        # 20 tes DES, di bawah 1 detik
python test_aes.py        # 20 tes AES, di bawah 1 detik
python test_e2e.py        # 14 tes dua proses, sekitar 15 detik
python -m unittest        # semuanya sekaligus (54 tes)
```

## Contoh keluaran (hasil jalan sungguhan, DES)

Terminal Sender (mengirim pesan, lalu menerima balasan):

```
[Sender] Algoritma: DES-CBC (blok 8 byte). Key dimuat, KCV=001812 (key TIDAK dikirim lewat jaringan; KCV sama di kedua sisi berarti key sama)
[Sender] Terhubung ke 127.0.0.1:5000
[Sender] >> plaintext        : Halo Receiver, ini pesan rahasia dari Sender
[Sender] >> IV (acak)        : 0f866fd5f0598c06
[Sender] >> KIRIM ciphertext : 8186242922dd68e95972e6a4add40c4907b1ca9bde66a7d30988b2f77fd69932ab5c473111b9bc3ac6f2bbebeeea7426
[Sender] >> ukuran paket     : 60 byte = 4 (panjang) + 8 (IV) + 48 (ciphertext)

[Sender] << DITERIMA paket    : 44 byte = 4 (panjang) + 8 (IV) + 32 (ciphertext)
[Sender] << IV                : 17d97a62a8791f6f
[Sender] << ciphertext (hex)  : 977f4b63fa330f8f77ee0e4dca1c7920e2ce006abaa1f3cf8bd45748cd031481
[Sender] << DEKRIPSI -> plaintext: Halo Sender, pesan diterima!
```

Terminal Receiver (menerima, lalu membalas). IV dan ciphertext sama persis dengan yang dikirim Sender:

```
[Receiver] << DITERIMA paket    : 60 byte = 4 (panjang) + 8 (IV) + 48 (ciphertext)
[Receiver] << IV                : 0f866fd5f0598c06
[Receiver] << ciphertext (hex)  : 8186242922dd68e95972e6a4add40c4907b1ca9bde66a7d30988b2f77fd69932ab5c473111b9bc3ac6f2bbebeeea7426
[Receiver] << DEKRIPSI -> plaintext: Halo Receiver, ini pesan rahasia dari Sender
[Receiver] >> plaintext        : Halo Sender, pesan diterima!
...
```

Terminal sniffer (dari eksekusi terpisah dengan pesan yang sama, jadi IV dan ciphertext-nya
berbeda dari contoh di atas). Hanya byte acak yang terlihat. Empat byte pertama (`00 00 00 38`)
adalah panjang paket (56 = 8 IV + 48 ciphertext), lalu IV (8 byte), lalu ciphertext:

```
[SNIFFER] klien -> server: 60 byte lewat
    0000  00 00 00 38 a3 fa 27 eb 6a 52 48 f7 d3 1d e3 d3  |...8..'.jRH.....|
    0010  58 9d da e3 80 6f 72 99 bb b6 9d 66 7a f4 17 cb  |X....or....fz...|
    ...
```

Jika key berbeda (misalnya Sender memakai `--key kuncisal`), Receiver menampilkan:

```
[Receiver] << Gagal dekripsi: Padding tidak valid (key salah atau data rusak). Pastikan --cipher dan key sama di kedua sisi.
```

## Format paket di jaringan

```
[ 4 byte panjang (big-endian) ][ IV acak: 8 byte (DES) atau 16 byte (AES) ][ ciphertext (kelipatan ukuran blok) ]
```

Panjang di 4 byte pertama dipakai penerima untuk memotong aliran TCP menjadi pesan utuh.
IV dibuat acak untuk setiap pesan dan boleh dikirim terbuka karena bukan rahasia. Key tidak dikirim.

## Cara kerja singkat (bahan penjelasan saat demo)

**Alur kirim:** teks diubah ke byte UTF-8, diberi padding PKCS#7 sampai kelipatan ukuran blok,
dienkripsi blok demi blok dengan CBC, lalu dikirim sebagai paket di atas. **Alur terima:** baca
4 byte panjang, baca isi paket, pisahkan IV dan ciphertext, dekripsi CBC, buang padding, ubah
ke teks.

**DES:** blok 64 bit, key 64 bit (8 bit paritas dibuang sehingga efektif 56 bit), 16 ronde
jaringan Feistel.

- *Permutasi awal (IP)* mengacak urutan bit blok, lalu blok dibagi menjadi L0 dan R0 (masing-masing 32 bit).
- *Tiap ronde:* `L(i) = R(i-1)` dan `R(i) = L(i-1) XOR f(R(i-1), K(i))`.
- *Fungsi f:* ekspansi E (32 menjadi 48 bit), XOR dengan subkey 48 bit, delapan S-box (6 bit masuk, 4 bit keluar, sumber ketaklinieran), lalu permutasi P.
- *Setelah 16 ronde:* L dan R ditukar, lalu permutasi akhir FP (kebalikan IP).
- *Key schedule:* PC-1 (64 menjadi 56 bit), dibagi dua bagian 28 bit, rotasi kiri 1 atau 2 bit tiap ronde, lalu PC-2 (56 menjadi 48 bit). Hasilnya 16 subkey.
- *Dekripsi* memakai proses yang sama dengan urutan subkey dibalik. Itu sifat jaringan Feistel.

**AES-128:** blok 16 byte disusun sebagai matriks state 4x4 dan diproses 10 ronde: SubBytes
(S-box dihitung dari invers di GF(2^8) lalu transformasi affine), ShiftRows, MixColumns (ronde
terakhir tidak memakainya), dan AddRoundKey, dengan 11 round key dari KeyExpansion.

**CBC:** `C0 = IV`, `Ci = E(Pi XOR C(i-1))`, dan saat dekripsi `Pi = D(Ci) XOR C(i-1)`.
**PKCS#7:** tambahkan n byte bernilai n (n antara 1 dan ukuran blok), bahkan jika panjang data
sudah kelipatan blok, sehingga padding selalu bisa dibuang dengan tepat.

**KCV (Key Check Value):** 3 byte pertama dari hasil enkripsi blok nol dengan key tersebut.
Dipakai untuk menunjukkan bahwa kedua sisi memegang key yang sama tanpa menampilkan key-nya.

## Skenario demo (sekitar 5 menit)

1. Jalankan `python test_des.py`: 20 tes lulus, termasuk cocok dengan vektor klasik DES.
2. Jalankan Receiver dan Sender (dua VM, atau dua terminal). Tunjukkan KCV sama di kedua sisi.
3. Sender mengirim pesan. Tunjukkan IV dan ciphertext di layar Sender sama persis dengan di layar Receiver, lalu plaintext hasil dekripsi.
4. Receiver membalas (arah sebaliknya), dan tunjukkan hal yang sama.
5. Kirim pesan yang sama dua kali. Ciphertext berbeda karena IV acak per pesan.
6. Opsional: jalankan lewat `sniffer.py` dan tunjukkan bahwa di kabel hanya ada byte acak.
7. Opsional: jalankan satu sisi dengan key berbeda dan tunjukkan "Gagal dekripsi".
8. Ketik `/quit` di satu sisi. Sisi lain berhenti sendiri.

## Pertanyaan yang mungkin muncul

**Mengapa DES padahal sudah tidak aman?** Tugas ini menekankan implementasi algoritma enkripsi
secara manual dan pengiriman ciphertext yang nyata, dan DES adalah algoritma blok dasar yang
strukturnya mudah dijelaskan. Program juga mendukung AES-128 (`--cipher aes`) sebagai alternatif modern.

**Mengapa IV ikut dikirim padahal key tidak?** IV bukan rahasia. Ia hanya perlu acak dan
berbeda untuk setiap pesan, supaya plaintext yang sama menghasilkan ciphertext berbeda. Penerima
membutuhkannya untuk mendekripsi blok pertama. Yang rahasia adalah key, dan key tidak pernah dikirim.

**Mengapa CBC, bukan ECB?** Pada ECB, blok plaintext yang sama menghasilkan ciphertext yang
sama sehingga pola data bocor. CBC merantai blok dan memakai IV acak.

**Mengapa key DES 8 karakter?** 8 byte adalah 64 bit. Delapan bit paritas dibuang oleh PC-1, jadi
yang efektif 56 bit. `test_des.py` membuktikannya: dua key yang hanya beda di bit paritas
menghasilkan ciphertext yang sama.

**Bagaimana membuktikan implementasinya benar?** Lewat tes otomatis yang bisa dijalankan saat
demo (`python test_des.py` dan `python test_aes.py`). DES cocok dengan vektor klasik dan subkey
contoh terkenal (K1 dan K16). AES cocok dengan vektor FIPS-197 dan NIST SP 800-38A. Hasil
enkripsi pesan lengkap (mode CBC dan padding) juga dicocokkan dengan keluaran `openssl enc`.
Tes-tes ini hanya memakai `des.py` dan `aes.py` buatan sendiri, tanpa library kripto.

**Bagaimana kalau key berbeda?** Dekripsi menghasilkan data acak. Hampir selalu padding tidak
valid sehingga muncul "Gagal dekripsi". Sesekali padding kebetulan lolos (peluang sekitar 1 dari
256), tetapi hasilnya tetap bukan teks asli.

**Library apa yang dipakai?** Hanya library standar Python untuk jaringan dan thread. Tidak ada
library enkripsi, hash, maupun TLS. `os.urandom` hanya membuat IV acak.

## Catatan keamanan dan batasan

- DES hanya memiliki key efektif 56 bit sehingga bisa dipecahkan dengan brute force (mesin khusus
  sudah melakukannya dalam hitungan hari sejak 1998). NIST menarik standar DES pada 2005. Untuk
  data sungguhan pakai AES, dan program ini menyediakannya lewat `--cipher aes`.
- CBC hanya menjamin kerahasiaan, bukan integritas atau keaslian pengirim (tidak ada MAC).
  `test_des.py` dan `test_aes.py` memuat tes yang memperlihatkan bahwa membalik satu bit di IV
  mengubah plaintext tanpa terdeteksi. Pengamanan lebih lanjut butuh MAC atau mode AEAD seperti GCM.
- Key dibagikan manual sebelumnya sesuai ketentuan tugas. Pertukaran key otomatis (misalnya
  RSA atau Diffie-Hellman) tidak termasuk di tugas ini.
- `--key` di command line bisa terlihat di riwayat shell dan daftar proses. Cukup untuk demo.
- Implementasi Python murni ini lambat (DES sekitar 21 ms dan AES sekitar 9 ms per 1 KB), cukup
  untuk chat tetapi bukan untuk data besar. Ukuran satu pesan dibatasi sekitar 1 MB.
- Implementasi ini untuk pembelajaran, bukan untuk produksi.

## Referensi

- NIST FIPS 46-3, *Data Encryption Standard (DES)*
- NIST FIPS 197, *Advanced Encryption Standard (AES)*
- NIST SP 800-38A, *Recommendation for Block Cipher Modes of Operation: Methods and Techniques*
