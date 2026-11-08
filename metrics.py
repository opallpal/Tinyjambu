"""
metrics.py
==========
Merekam latensi (Round-Trip Time), throughput, serta penggunaan CPU dan RAM
pada sisi pengirim dan penerima.
"""

import csv
import os
import threading
import time

import psutil


class ResourceSampler:
    """Mencuplik penggunaan CPU (%) dan RAM (MB) proses saat ini pada interval tertentu."""

    def __init__(self, interval=1.0):
        self.interval = interval
        self._proc = psutil.Process(os.getpid())
        self._samples = []
        self._running = False
        self._thread = None
        self._proc.cpu_percent(None)  # warm-up baseline

    def _loop(self):
        while self._running:
            cpu = self._proc.cpu_percent(None)
            ram_mb = self._proc.memory_info().rss / (1024 * 1024)
            self._samples.append({"t": time.time(), "cpu_percent": cpu, "ram_mb": ram_mb})
            time.sleep(self.interval)

    def start(self):
        self._running = True
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop(self):
        self._running = False
        if self._thread:
            self._thread.join(timeout=2)

    def summary(self):
        if not self._samples:
            return {"cpu_percent_mean": 0.0, "ram_mb_mean": 0.0}
        cpu_vals = [s["cpu_percent"] for s in self._samples]
        ram_vals = [s["ram_mb"] for s in self._samples]
        return {
            "cpu_percent_mean": sum(cpu_vals) / len(cpu_vals),
            "ram_mb_mean": sum(ram_vals) / len(ram_vals),
        }


class MetricsWriter:
    """Menulis satu baris hasil pengukuran per pengulangan ke berkas CSV di results/."""

    FIELDS = [
        "scenario", "channel", "condition", "payload_bytes", "concurrency",
        "iteration", "rtt_ms", "throughput_kbps", "cpu_percent", "ram_mb",
        "tag_valid", "detected_tamper", "attack_variant", "timestamp",
    ]

    def __init__(self, path):
        self.path = path
        self._lock = threading.Lock()
        new_file = not os.path.exists(path)
        self._fh = open(path, "a", newline="")
        self._writer = csv.DictWriter(self._fh, fieldnames=self.FIELDS)
        if new_file:
            self._writer.writeheader()
            self._fh.flush()

    def write(self, row: dict):
        with self._lock:
            full = {k: row.get(k, "") for k in self.FIELDS}
            self._writer.writerow(full)
            self._fh.flush()

    def close(self):
        self._fh.close()


def measure_rtt_and_throughput(send_fn, payload_bytes_len):
    """Menjalankan send_fn() (round-trip kirim+terima), mengembalikan (rtt_ms, throughput_kbps, result)."""
    t0 = time.perf_counter()
    result = send_fn()
    t1 = time.perf_counter()
    rtt_ms = (t1 - t0) * 1000.0
    throughput_kbps = (payload_bytes_len * 8 / 1000.0) / (t1 - t0) if t1 > t0 else 0.0
    return rtt_ms, throughput_kbps, result
