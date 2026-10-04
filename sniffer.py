"""
Penyadap pasif (sniffer) untuk demo: berdiri di antara dua peer dan menampilkan byte
yang BENAR-BENAR lewat di jaringan. Program ini hanya meneruskan data apa adanya dan
tidak memiliki key, jadi yang terlihat hanya byte acak: panjang(4) + IV + ciphertext
(IV 8 byte untuk DES, 16 byte untuk AES).

Tugas Keamanan Informasi - Muhammad Nabil Fauzan (5025241024)

Pemakaian (tiga terminal, contoh DES):
  Terminal 1:  python peer.py --cipher des --name Receiver --listen 5000 --key kunci123
  Terminal 2:  python sniffer.py --listen 6000 --target 127.0.0.1:5000
  Terminal 3:  python peer.py --cipher des --name Sender --connect 127.0.0.1:6000 --key kunci123
Sender mengira ia terhubung ke Receiver, padahal lewat sniffer. Ketik pesan di Sender/Receiver,
lalu lihat hex yang tercetak di Terminal 2: tidak ada plaintext, dan key tidak pernah lewat.

Di dua VM: jalankan sniffer di VM Receiver (target 127.0.0.1:5000), lalu Sender menyambung ke
IP VM Receiver pada port sniffer (6000), bukan port 5000.
"""

import argparse
import socket
import sys
import threading

_out_lock = threading.Lock()


def say(text):
    with _out_lock:
        print(text, flush=True)


def hexdump(data, limit=160):
    """Tampilan seperti `xxd`: offset, hex, dan kolom ASCII."""
    baris = []
    for off in range(0, min(len(data), limit), 16):
        potong = data[off:off + 16]
        hx = " ".join(f"{b:02x}" for b in potong)
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in potong)
        baris.append(f"    {off:04x}  {hx:<47}  |{asc}|")
    if len(data) > limit:
        baris.append(f"    ... (+{len(data) - limit} byte lagi tidak ditampilkan)")
    return "\n".join(baris)


def pipe(src, dst, label):
    """Teruskan byte dari src ke dst sambil menampilkannya."""
    try:
        while True:
            data = src.recv(65536)
            if not data:
                break
            dst.sendall(data)
            say(f"[SNIFFER] {label}: {len(data)} byte lewat\n{hexdump(data)}")
    except OSError:
        pass
    finally:
        try:
            dst.shutdown(socket.SHUT_WR)
        except OSError:
            pass


def handle(client, client_addr, target):
    try:
        server = socket.create_connection(target)
    except OSError as e:
        say(f"[SNIFFER] Gagal terhubung ke target {target[0]}:{target[1]}: {e}")
        client.close()
        return
    say(f"[SNIFFER] Koneksi disadap: klien {client_addr[0]}:{client_addr[1]} <-> target {target[0]}:{target[1]}")
    arah = [
        threading.Thread(target=pipe, args=(client, server, "klien -> server"), daemon=True),
        threading.Thread(target=pipe, args=(server, client, "server -> klien"), daemon=True),
    ]
    for t in arah:
        t.start()
    for t in arah:
        t.join()
    client.close()
    server.close()
    say("[SNIFFER] Koneksi selesai.")


def main():
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError, OSError):
            pass

    ap = argparse.ArgumentParser(description="Sniffer pasif untuk demo transmisi ciphertext")
    ap.add_argument("--listen", type=int, required=True, metavar="PORT",
                    help="port tempat sniffer menunggu klien (peer --connect diarahkan ke sini)")
    ap.add_argument("--target", required=True, metavar="HOST:PORT",
                    help="alamat peer --listen yang asli")
    args = ap.parse_args()

    host, sep, port = args.target.rpartition(":")
    if not sep or not host or not port.isdigit():
        ap.error("--target harus berformat HOST:PORT, misalnya 127.0.0.1:5000")
    target = (host, int(port))

    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", args.listen))
    srv.listen(5)
    srv.settimeout(0.5)  # supaya Ctrl+C responsif (termasuk di Windows)
    say(f"[SNIFFER] Menunggu klien di port {args.listen}, meneruskan ke {host}:{port}. Ctrl+C untuk berhenti.")
    try:
        while True:
            try:
                client, addr = srv.accept()
            except socket.timeout:
                continue
            client.settimeout(None)
            threading.Thread(target=handle, args=(client, addr, target), daemon=True).start()
    except KeyboardInterrupt:
        say("\n[SNIFFER] Berhenti.")
    finally:
        srv.close()


if __name__ == "__main__":
    main()
