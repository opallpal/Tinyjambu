"""
uart_channel.py
================
Menyediakan jalur komunikasi serial antara simulator perangkat dan penerima.

Lingkungan pengujian ini tidak memiliki port serial fisik / virtual serial
port (mis. socat, com0com) yang terpasang, sehingga modul ini menyediakan
SimulatedSerialLink: sebuah jalur point-to-point berbasis TCP loopback yang
meniru perilaku UART (byte-stream, framing panjang-pesan, tanpa antrean topik
seperti MQTT). Antarmuka (open/write/read_frame/close) sengaja dibuat mirip
pyserial agar pada deployment nyata modul ini tinggal diganti dengan:

    import serial
    ser = serial.Serial('/dev/ttyUSB0', 115200, timeout=1)

tanpa mengubah device_sim.py maupun receiver_server.py secara signifikan.
"""

import socket
import struct
import threading

HOST = "127.0.0.1"


class SerialServer:
    """Sisi penerima (gateway). Menerima banyak koneksi 'perangkat' secara paralel."""

    def __init__(self, port=0):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((HOST, port))
        self._sock.listen(64)
        self.port = self._sock.getsockname()[1]
        self._running = False

    def serve_forever(self, handler):
        """handler(frame_bytes, client_addr) -> response_bytes (dikirim balik sebagai ACK,
        meniru pola request-response satu-koneksi khas UART)."""
        self._running = True

        def handle(conn, addr):
            try:
                while self._running:
                    header = _recv_exact(conn, 4)
                    if header is None:
                        break
                    (length,) = struct.unpack("<I", header)
                    payload = _recv_exact(conn, length)
                    if payload is None:
                        break
                    response = handler(payload, addr)
                    if response is not None:
                        conn.sendall(struct.pack("<I", len(response)) + response)
            except (ConnectionResetError, OSError):
                pass
            finally:
                conn.close()

        def accept_loop():
            while self._running:
                try:
                    conn, addr = self._sock.accept()
                except OSError:
                    break
                t = threading.Thread(target=handle, args=(conn, addr), daemon=True)
                t.start()

        self._thread = threading.Thread(target=accept_loop, daemon=True)
        self._thread.start()

    def stop(self):
        self._running = False
        try:
            self._sock.close()
        except OSError:
            pass


class SerialClient:
    """Sisi pengirim (simulator perangkat IoT). Satu koneksi TCP = satu 'kabel UART'."""

    def __init__(self, port, host=HOST, timeout=5.0):
        self._sock = socket.create_connection((host, port), timeout=timeout)

    def write_frame(self, data: bytes):
        header = struct.pack("<I", len(data))
        self._sock.sendall(header + data)

    def read_frame(self, timeout=5.0):
        self._sock.settimeout(timeout)
        header = _recv_exact(self._sock, 4)
        if header is None:
            return None
        (length,) = struct.unpack("<I", header)
        return _recv_exact(self._sock, length)

    def close(self):
        try:
            self._sock.close()
        except OSError:
            pass


def _recv_exact(sock, n):
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return bytes(buf)
