"""
Simulasi transmisi ciphertext dua arah (Sender <-> Receiver) lewat TCP socket.

Tugas Keamanan Informasi - Muhammad Nabil Fauzan (5025241024)

Setiap instance program adalah SATU pihak (satu proses/device terpisah).
Jalankan dua instance: satu mode --listen, satu mode --connect. Keduanya bisa
mengirim dan menerima (dua arah). Key sudah diketahui kedua pihak sebelumnya
(--key, 16 karakter atau 32 digit hex) dan TIDAK PERNAH dikirim lewat jaringan.
Yang lewat jaringan hanya: panjang(4 byte) + IV(16 byte) + ciphertext.

Contoh:
  Terminal 1:  python peer.py --name Alice --listen 5000 --key kuncirahasia1234
  Terminal 2:  python peer.py --name Bob --connect 127.0.0.1:5000 --key kuncirahasia1234
Untuk dua komputer berbeda, pakai IP komputer yang listen pada --connect.
"""

import argparse
import os
import socket
import struct
import sys
import threading
import time

from aes import BLOCK, encrypt_cbc, decrypt_cbc, expand_key, encrypt_block

MAX_FRAME = 1_000_000  # batas ukuran satu paket (byte), mencegah paket raksasa

_out_lock = threading.Lock()


def say(text):
    """Cetak satu blok teks secara atomik (thread kirim dan thread terima sama-sama mencetak)."""
    with _out_lock:
        print(text, flush=True)


def parse_key(text):
    if len(text) == 32:
        try:
            return bytes.fromhex(text)
        except ValueError:
            pass
    k = text.encode("utf-8")
    if len(k) != BLOCK:
        sys.exit(f"Key harus 16 karakter (16 byte) atau 32 digit hex; key Anda {len(k)} byte")
    return k


def key_check_value(key):
    """KCV = 3 byte pertama dari AES_key(blok nol). Dipakai untuk membandingkan key
    di kedua sisi tanpa menampilkan key-nya (KCV sama berarti key sama)."""
    return encrypt_block(bytes(BLOCK), expand_key(key))[:3].hex()


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


def receiver_loop(sock, key, name, stop):
    """Thread penerima: baca paket dari jaringan, tampilkan ciphertext, lalu dekripsi."""
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
        iv, ct = payload[:BLOCK], payload[BLOCK:]
        blok = [
            f"[{name}] << DITERIMA paket    : {4 + len(payload)} byte = 4 (panjang) + {BLOCK} (IV) + {len(ct)} (ciphertext)",
            f"[{name}] << IV                : {iv.hex()}",
            f"[{name}] << ciphertext (hex)  : {ct.hex()}",
        ]
        try:
            plain = decrypt_cbc(payload, key).decode("utf-8")
            blok.append(f"[{name}] << DEKRIPSI -> plaintext: {plain}")
        except UnicodeDecodeError:
            blok.append(f"[{name}] << Gagal dekripsi: hasilnya bukan teks UTF-8 (kemungkinan key berbeda)")
        except Exception as e:
            blok.append(f"[{name}] << Gagal dekripsi: {e}")
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

    ap = argparse.ArgumentParser(description="Peer komunikasi ciphertext dua arah (AES-128 CBC manual)")
    ap.add_argument("--name", default="Peer")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--listen", type=int, metavar="PORT")
    g.add_argument("--connect", metavar="HOST:PORT")
    ap.add_argument("--key", required=True, help="pre-shared key, 16 karakter atau 32 hex")
    ap.add_argument("--wait", type=float, default=2.0,
                    help="detik menunggu balasan setelah input habis (untuk mode pipe)")
    args = ap.parse_args()

    host, port = None, None
    if args.connect:
        host, sep, port = args.connect.rpartition(":")
        if not sep or not host or not port.isdigit():
            ap.error("--connect harus berformat HOST:PORT, misalnya 127.0.0.1:5000")

    key = parse_key(args.key)
    name = args.name
    say(f"[{name}] Key dimuat: AES-128, KCV={key_check_value(key)} "
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
    t = threading.Thread(target=receiver_loop, args=(sock, key, name, stop), daemon=True)
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
            payload = encrypt_cbc(msg.encode("utf-8"), key)
            if len(payload) > MAX_FRAME:
                say(f"[{name}] Pesan terlalu panjang (maksimum sekitar {MAX_FRAME // 1000} KB), tidak dikirim.")
                continue
            try:
                send_frame(sock, payload)
            except OSError as e:
                say(f"[{name}] Gagal mengirim: {e}")
                break
            iv, ct = payload[:BLOCK], payload[BLOCK:]
            say("\n".join([
                f"[{name}] >> plaintext        : {msg}",
                f"[{name}] >> IV (acak)        : {iv.hex()}",
                f"[{name}] >> KIRIM ciphertext : {ct.hex()}",
                f"[{name}] >> ukuran paket     : {4 + len(payload)} byte = 4 (panjang) + {BLOCK} (IV) + {len(ct)} (ciphertext)",
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
