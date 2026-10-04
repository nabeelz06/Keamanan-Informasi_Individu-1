"""
Simulasi transmisi ciphertext dua arah (Sender <-> Receiver) lewat TCP socket.

Tugas Keamanan Informasi - Muhammad Nabil Fauzan (5025241024)

Setiap instance program adalah SATU pihak (satu proses/device terpisah).
Jalankan dua instance: satu mode --listen, satu mode --connect. Keduanya bisa
mengirim dan menerima (dua arah). Algoritma dipilih dengan --cipher (des atau aes) dan
harus sama di kedua sisi. Key sudah diketahui kedua pihak sebelumnya (--key) dan TIDAK
PERNAH dikirim lewat jaringan. Yang lewat jaringan hanya: panjang(4 byte) + IV + ciphertext.

Panjang key: DES 8 karakter (atau 16 digit hex), AES-128 16 karakter (atau 32 digit hex).

Contoh (DES):
  Terminal 1:  python peer.py --cipher des --name Receiver --listen 5000 --key kunci123
  Terminal 2:  python peer.py --cipher des --name Sender --connect 127.0.0.1:5000 --key kunci123
Untuk dua komputer atau dua VM, pakai IP mesin yang listen pada --connect.
"""

import argparse
import os
import socket
import struct
import sys
import threading
import time

import aes
import des

# Dua algoritma buatan sendiri dengan antarmuka sama: BLOCK, KEY_SIZE, expand_key,
# encrypt_block, encrypt_cbc, decrypt_cbc.
CIPHERS = {
    "des": (des, "DES-CBC"),
    "aes": (aes, "AES-128-CBC"),
}

MAX_FRAME = 1_000_000  # batas ukuran satu paket (byte), mencegah paket raksasa

_out_lock = threading.Lock()


def say(text):
    """Cetak satu blok teks secara atomik (thread kirim dan thread terima sama-sama mencetak)."""
    with _out_lock:
        print(text, flush=True)


def parse_key(text, key_size):
    if len(text) == key_size * 2:
        try:
            return bytes.fromhex(text)
        except ValueError:
            pass
    k = text.encode("utf-8")
    if len(k) != key_size:
        sys.exit(f"Key harus {key_size} karakter ({key_size} byte) atau {key_size * 2} digit hex "
                 f"untuk algoritma ini; key Anda {len(k)} byte. "
                 f"(DES memakai 8 byte, AES-128 memakai 16 byte; cek juga --cipher)")
    return k


def key_check_value(algo, key):
    """KCV = 3 byte pertama dari hasil enkripsi blok nol dengan key tersebut. Dipakai untuk
    membandingkan key di kedua sisi tanpa menampilkan key-nya (KCV sama berarti key sama)."""
    return algo.encrypt_block(bytes(algo.BLOCK), algo.expand_key(key))[:3].hex()


def send_frame(sock, payload):
    sock.sendall(struct.pack(">I", len(payload)) + payload)


def recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def recv_frame(sock):
    head = recv_exact(sock, 4)
    if head is None:
        return None
    (length,) = struct.unpack(">I", head)
    if length > MAX_FRAME:
        raise ValueError("Frame terlalu besar")
    return recv_exact(sock, length)


def receiver_loop(sock, algo, key, name, stop):
    """Thread penerima: baca paket dari jaringan, tampilkan ciphertext, lalu dekripsi."""
    block = algo.BLOCK
    alasan, kode = None, 0
    while not stop.is_set():
        try:
            payload = recv_frame(sock)
        except (OSError, ValueError) as e:
            alasan, kode = f"Koneksi terputus ({e}).", 1
            break
        if payload is None:
            alasan = "Koneksi ditutup oleh lawan bicara."
            break
        iv, ct = payload[:block], payload[block:]
        blok = [
            f"[{name}] << DITERIMA paket    : {4 + len(payload)} byte = 4 (panjang) + {block} (IV) + {len(ct)} (ciphertext)",
            f"[{name}] << IV                : {iv.hex()}",
            f"[{name}] << ciphertext (hex)  : {ct.hex()}",
        ]
        try:
            plain = algo.decrypt_cbc(payload, key).decode("utf-8")
            blok.append(f"[{name}] << DEKRIPSI -> plaintext: {plain}")
        except UnicodeDecodeError:
            blok.append(f"[{name}] << Gagal dekripsi: hasilnya bukan teks UTF-8 "
                        f"(kemungkinan key atau --cipher berbeda)")
        except Exception as e:
            blok.append(f"[{name}] << Gagal dekripsi: {e}. Pastikan --cipher dan key sama di kedua sisi.")
        say("\n" + "\n".join(blok))
    if alasan and not stop.is_set():
        # Thread utama sedang menunggu input(); keluar langsung agar program tidak menggantung.
        say(f"\n[{name}] {alasan} Selesai.")
        os._exit(kode)
    stop.set()


def main():
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError, OSError):
            pass

    ap = argparse.ArgumentParser(description="Peer komunikasi ciphertext dua arah (DES atau AES, CBC, buatan sendiri)")
    ap.add_argument("--name", default="Peer")
    ap.add_argument("--cipher", choices=sorted(CIPHERS), default="des",
                    help="algoritma enkripsi (harus sama di kedua sisi), bawaan: des")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--listen", type=int, metavar="PORT")
    g.add_argument("--connect", metavar="HOST:PORT")
    ap.add_argument("--key", required=True,
                    help="pre-shared key: DES 8 karakter (16 hex), AES 16 karakter (32 hex)")
    ap.add_argument("--wait", type=float, default=2.0,
                    help="detik menunggu balasan setelah input habis (untuk mode pipe)")
    args = ap.parse_args()

    host, port = None, None
    if args.connect:
        host, sep, port = args.connect.rpartition(":")
        if not sep or not host or not port.isdigit():
            ap.error("--connect harus berformat HOST:PORT, misalnya 127.0.0.1:5000")

    algo, label = CIPHERS[args.cipher]
    key = parse_key(args.key, algo.KEY_SIZE)
    name = args.name
    block = algo.BLOCK
    say(f"[{name}] Algoritma: {label} (blok {block} byte). Key dimuat, KCV={key_check_value(algo, key)} "
        f"(key TIDAK dikirim lewat jaringan; KCV sama di kedua sisi berarti key sama)")

    if args.listen is not None:
        srv = socket.socket()
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("0.0.0.0", args.listen))
        srv.listen(1)
        srv.settimeout(0.5)  # supaya Ctrl+C tetap bisa membatalkan penantian (termasuk di Windows)
        say(f"[{name}] Menunggu koneksi di port {args.listen} ...")
        try:
            while True:
                try:
                    sock, addr = srv.accept()
                    break
                except socket.timeout:
                    continue
        except KeyboardInterrupt:
            sys.exit(f"\n[{name}] Dibatalkan.")
        finally:
            srv.close()
        sock.settimeout(None)
        say(f"[{name}] Terhubung dengan {addr[0]}:{addr[1]}")
    else:
        sock = None
        try:
            for _ in range(20):  # coba beberapa kali jika listener belum siap
                try:
                    sock = socket.create_connection((host, int(port)))
                    break
                except OSError:
                    time.sleep(0.5)
        except KeyboardInterrupt:
            sys.exit(f"\n[{name}] Dibatalkan.")
        if sock is None:
            sys.exit(f"[{name}] Gagal terhubung ke {host}:{port}. Pastikan sisi --listen sudah "
                     f"berjalan dan port tidak diblokir firewall.")
        say(f"[{name}] Terhubung ke {host}:{port}")

    stop = threading.Event()
    t = threading.Thread(target=receiver_loop, args=(sock, algo, key, name, stop), daemon=True)
    t.start()

    say(f"[{name}] Ketik pesan lalu Enter. Ketik /quit untuk keluar.")
    try:
        for line in sys.stdin:
            if stop.is_set():
                break
            msg = line.rstrip("\r\n")
            if msg == "/quit":
                break
            if not msg:
                continue
            payload = algo.encrypt_cbc(msg.encode("utf-8"), key)
            if len(payload) > MAX_FRAME:
                say(f"[{name}] Pesan terlalu panjang (maksimum sekitar {MAX_FRAME // 1000} KB), tidak dikirim.")
                continue
            try:
                send_frame(sock, payload)
            except OSError as e:
                say(f"[{name}] Gagal mengirim: {e}")
                break
            iv, ct = payload[:block], payload[block:]
            say("\n".join([
                f"[{name}] >> plaintext        : {msg}",
                f"[{name}] >> IV (acak)        : {iv.hex()}",
                f"[{name}] >> KIRIM ciphertext : {ct.hex()}",
                f"[{name}] >> ukuran paket     : {4 + len(payload)} byte = 4 (panjang) + {block} (IV) + {len(ct)} (ciphertext)",
            ]))
        # beri waktu menerima balasan terakhir (penting untuk input via pipe)
        if not sys.stdin.isatty():
            stop.wait(args.wait)
    except KeyboardInterrupt:
        pass
    finally:
        stop.set()
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        sock.close()
        say(f"[{name}] Selesai.")


if __name__ == "__main__":
    main()
