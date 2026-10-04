"""
Tes end-to-end: dua proses peer.py saling kirim ciphertext lewat TCP.

Tugas Keamanan Informasi - Muhammad Nabil Fauzan (5025241024)

Sebuah relay (penyadap pasif) disisipkan di antara kedua proses. Relay hanya
meneruskan dan merekam byte, sehingga tes ini bisa membuktikan bahwa yang lewat
di jaringan HANYA: panjang + IV + ciphertext (tanpa plaintext dan tanpa key).

Jalankan:  python -m unittest -v test_e2e
"""
import os
import re
import socket
import subprocess
import sys
import threading
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
PEER = os.path.join(HERE, "peer.py")
SNIFFER = os.path.join(HERE, "sniffer.py")
KEY_TEXT = "kuncirahasia1234"  # 16 karakter = 16 byte
TIMEOUT = 15.0


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Relay:
    """Penyadap pasif: meneruskan byte apa adanya sambil merekamnya."""

    def __init__(self, listen_port, target_port):
        self.c2s = bytearray()  # klien (--connect) -> server (--listen)
        self.s2c = bytearray()  # server (--listen) -> klien (--connect)
        self._target_port = target_port
        self._srv = socket.socket()
        self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._srv.bind(("127.0.0.1", listen_port))
        self._srv.listen(1)
        self._socks = [self._srv]
        threading.Thread(target=self._run, daemon=True).start()

    def _run(self):
        try:
            client, _ = self._srv.accept()
            self._socks.append(client)
            server = socket.create_connection(("127.0.0.1", self._target_port))
            self._socks.append(server)
        except OSError:
            return
        for src, dst, log in ((client, server, self.c2s), (server, client, self.s2c)):
            threading.Thread(target=self._pipe, args=(src, dst, log), daemon=True).start()

    @staticmethod
    def _pipe(src, dst, log):
        try:
            while True:
                chunk = src.recv(4096)
                if not chunk:
                    break
                log.extend(chunk)
                dst.sendall(chunk)
        except OSError:
            pass
        finally:
            try:
                dst.shutdown(socket.SHUT_WR)
            except OSError:
                pass

    def close(self):
        for s in self._socks:
            try:
                s.close()
            except OSError:
                pass


def parse_frames(data):
    """Pecah aliran byte menjadi frame [4 byte panjang][payload]. Kembalikan (frames, utuh)."""
    frames, i = [], 0
    while i + 4 <= len(data):
        n = int.from_bytes(data[i:i + 4], "big")
        frames.append(bytes(data[i + 4:i + 4 + n]))
        i += 4 + n
    return frames, i == len(data)


class PeerProc:
    """Satu proses (peer.py atau sniffer.py) dengan stdin/stdout lewat pipe."""

    def __init__(self, *args, script=PEER):
        env = dict(os.environ, PYTHONIOENCODING="utf-8", PYTHONUTF8="1")
        self.p = subprocess.Popen(
            [sys.executable, "-u", script, *args],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=env,
        )
        self._buf = bytearray()
        self._lock = threading.Lock()
        self._reader = threading.Thread(target=self._read, daemon=True)
        self._reader.start()

    def _read(self):
        while True:
            chunk = self.p.stdout.read1(4096)
            if not chunk:
                break
            with self._lock:
                self._buf.extend(chunk)

    @property
    def output(self):
        with self._lock:
            return self._buf.decode("utf-8", "replace")

    def say(self, text):
        self.p.stdin.write((text + "\n").encode("utf-8"))
        self.p.stdin.flush()

    def wait_for(self, needle, count=1, timeout=TIMEOUT):
        end = time.time() + timeout
        while time.time() < end:
            if self.output.count(needle) >= count:
                return True
            time.sleep(0.05)
        return False

    def close_stdin(self):
        try:
            self.p.stdin.close()
        except OSError:
            pass

    def wait_exit(self, timeout=TIMEOUT):
        try:
            return self.p.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            return None

    def kill(self):
        if self.p.poll() is None:
            self.p.kill()
        self.p.wait()
        self._reader.join(timeout=2)
        for pipe in (self.p.stdin, self.p.stdout):
            try:
                pipe.close()
            except OSError:
                pass


class E2EBase(unittest.TestCase):
    def setUp(self):
        self.procs, self.relays = [], []

    def tearDown(self):
        for p in self.procs:
            p.kill()
        for r in self.relays:
            r.close()

    def spawn(self, *args, script=PEER):
        p = PeerProc(*args, script=script)
        self.procs.append(p)
        return p

    def start_pair(self, key_a=KEY_TEXT, key_b=KEY_TEXT, via_relay=True):
        """Alice --listen, Bob --connect (lewat relay penyadap bila via_relay)."""
        listen_port = free_port()
        alice = self.spawn("--name", "Alice", "--listen", str(listen_port), "--key", key_a)
        self.assertTrue(alice.wait_for("Menunggu koneksi"), alice.output)
        relay, bob_port = None, listen_port
        if via_relay:
            bob_port = free_port()
            relay = Relay(bob_port, listen_port)
            self.relays.append(relay)
        bob = self.spawn("--name", "Bob", "--connect", f"127.0.0.1:{bob_port}", "--key", key_b)
        self.assertTrue(alice.wait_for("Terhubung dengan"), alice.output)
        self.assertTrue(bob.wait_for("Terhubung ke"), bob.output)
        return alice, bob, relay


class TestTwoWayCommunication(E2EBase):
    def test_two_way_and_only_ciphertext_on_the_wire(self):
        alice, bob, relay = self.start_pair()
        m1 = "Halo Alice, ini pesan rahasia dari Bob \U0001F510"
        m2 = "Halo Bob, pesan diterima. Balasan dari Alice — 安全"

        bob.say(m1)  # arah Bob -> Alice
        self.assertTrue(alice.wait_for(f"plaintext: {m1}"), alice.output)
        alice.say(m2)  # arah Alice -> Bob
        self.assertTrue(bob.wait_for(f"plaintext: {m2}"), bob.output)

        bob.say("sama")  # plaintext yang sama dua kali -> ciphertext harus beda (IV acak)
        bob.say("sama")
        self.assertTrue(alice.wait_for("plaintext: sama", count=2), alice.output)

        bob.close_stdin()
        alice.close_stdin()
        self.assertEqual(bob.wait_exit(), 0, bob.output)
        self.assertEqual(alice.wait_exit(), 0, alice.output)
        time.sleep(0.3)

        c2s, utuh1 = parse_frames(relay.c2s)
        s2c, utuh2 = parse_frames(relay.s2c)
        self.assertTrue(utuh1 and utuh2, "aliran byte harus terdiri dari frame utuh")
        self.assertEqual(len(c2s), 3)
        self.assertEqual(len(s2c), 1)

        wire = bytes(relay.c2s) + bytes(relay.s2c)
        for rahasia in (m1, m2, "sama", "rahasia"):
            self.assertNotIn(rahasia.encode("utf-8"), wire, "plaintext tidak boleh terlihat di kabel")
        key = KEY_TEXT.encode()
        self.assertNotIn(key, wire, "key tidak boleh dikirim")
        self.assertNotIn(key.hex().encode(), wire)
        self.assertNotIn(key.hex().upper().encode(), wire)

        for frame in c2s + s2c:  # format: IV (16) + ciphertext (kelipatan 16)
            self.assertGreaterEqual(len(frame), 32)
            self.assertEqual(len(frame) % 16, 0)
        self.assertNotEqual(c2s[1], c2s[2], "IV acak -> ciphertext berbeda untuk plaintext sama")

        # IV + ciphertext yang dicetak pengirim harus sama persis dengan isi frame di kabel
        sent_iv = re.findall(r">> IV \(acak\)\s*: ([0-9a-f]+)", bob.output)
        sent_ct = re.findall(r">> KIRIM ciphertext\s*: ([0-9a-f]+)", bob.output)
        self.assertEqual([a + b for a, b in zip(sent_iv, sent_ct)], [f.hex() for f in c2s])
        # ... dan penerima mencetak IV + ciphertext yang sama
        got_iv = re.findall(r"<< IV\s*: ([0-9a-f]+)", alice.output)
        got_ct = re.findall(r"<< ciphertext \(hex\)\s*: ([0-9a-f]+)", alice.output)
        self.assertEqual((got_iv, got_ct), (sent_iv, sent_ct))

    def test_full_duplex_simultaneous_send(self):
        alice, bob, _ = self.start_pair(via_relay=False)
        for i in range(5):
            alice.say(f"dari-alice-{i}")
            bob.say(f"dari-bob-{i}")
        for i in range(5):
            self.assertTrue(bob.wait_for(f"plaintext: dari-alice-{i}"), bob.output)
            self.assertTrue(alice.wait_for(f"plaintext: dari-bob-{i}"), alice.output)

    def test_long_message_spanning_many_tcp_segments(self):
        alice, bob, _ = self.start_pair()
        panjang = ("Keamanan Informasi ITS 2026 " * 400).strip()  # sekitar 11 KB
        bob.say(panjang)
        self.assertTrue(alice.wait_for(f"plaintext: {panjang}"), alice.output[-300:])


class TestFailureCases(E2EBase):
    def test_wrong_key_cannot_read_messages(self):
        alice, bob, _ = self.start_pair(key_a=KEY_TEXT, key_b="kuncisalahbanget", via_relay=False)
        pesan = ["rahasia penting satu", "rahasia penting dua", "rahasia penting tiga"]
        for m in pesan:
            bob.say(m)
        self.assertTrue(alice.wait_for("DITERIMA paket", count=3), alice.output)
        time.sleep(0.5)
        for m in pesan:
            self.assertNotIn(m, alice.output, "key salah tidak boleh bisa membuka pesan")
        self.assertGreaterEqual(alice.output.count("Gagal dekripsi"), 2, alice.output)

    def test_peer_exits_when_other_side_disconnects(self):
        alice, bob, _ = self.start_pair(via_relay=False)
        bob.say("sampai jumpa")
        self.assertTrue(alice.wait_for("plaintext: sampai jumpa"), alice.output)
        bob.say("/quit")
        self.assertEqual(bob.wait_exit(), 0, bob.output)
        # Alice TIDAK ditutup stdin-nya: ia harus berhenti sendiri karena lawan memutus koneksi
        self.assertIsNotNone(alice.wait_exit(timeout=8), "peer harus keluar sendiri saat lawan putus:\n" + alice.output)


def dump_bytes(output, label):
    """Gabungkan byte dari hexdump sniffer untuk satu arah (mis. 'klien -> server')."""
    hasil = bytearray()
    for blok in output.split("[SNIFFER] ")[1:]:
        if blok.startswith(label):
            for hx in re.findall(r"^    [0-9a-f]{4}  ([0-9a-f ]{1,47}?)  \|", blok, flags=re.M):
                hasil.extend(bytes.fromhex(hx.replace(" ", "")))
    return bytes(hasil)


class TestSniffer(E2EBase):
    def test_sniffer_hanya_melihat_ciphertext(self):
        listen_port, sniff_port = free_port(), free_port()
        alice = self.spawn("--name", "Alice", "--listen", str(listen_port), "--key", KEY_TEXT)
        self.assertTrue(alice.wait_for("Menunggu koneksi"), alice.output)
        sniffer = self.spawn("--listen", str(sniff_port), "--target", f"127.0.0.1:{listen_port}", script=SNIFFER)
        self.assertTrue(sniffer.wait_for("Menunggu klien"), sniffer.output)
        bob = self.spawn("--name", "Bob", "--connect", f"127.0.0.1:{sniff_port}", "--key", KEY_TEXT)
        self.assertTrue(alice.wait_for("Terhubung dengan"), alice.output)

        bob.say("pesan rahasia lewat sniffer")
        self.assertTrue(alice.wait_for("plaintext: pesan rahasia lewat sniffer"), alice.output)
        alice.say("balasan rahasia dari alice")
        self.assertTrue(bob.wait_for("plaintext: balasan rahasia dari alice"), bob.output)
        self.assertTrue(sniffer.wait_for("server -> klien"), sniffer.output)
        time.sleep(0.3)

        c2s = dump_bytes(sniffer.output, "klien -> server")
        s2c = dump_bytes(sniffer.output, "server -> klien")
        iv = re.findall(r">> IV \(acak\)\s*: ([0-9a-f]+)", bob.output)[0]
        ct = re.findall(r">> KIRIM ciphertext\s*: ([0-9a-f]+)", bob.output)[0]
        payload = bytes.fromhex(iv + ct)
        self.assertEqual(c2s, len(payload).to_bytes(4, "big") + payload, "yang tampak di sniffer = paket yang dikirim Bob")
        self.assertGreater(len(s2c), 4 + 32)
        for rahasia in (b"rahasia", b"sniffer", b"alice", KEY_TEXT.encode(), KEY_TEXT.encode().hex().encode()):
            self.assertNotIn(rahasia, c2s + s2c)


if __name__ == "__main__":
    unittest.main(verbosity=2)
