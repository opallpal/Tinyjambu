"""
run_benchmark.py
==================
Orkestrator utama: menjalankan Fase Inisialisasi -> Pemanasan -> Pengujian
Performa (S1-S3) -> Pengujian Keamanan (S4) -> Analisis, sesuai alur pada
Bab 3 kerangka penelitian. Menulis hasil mentah ke results/raw_results.csv.

Pemakaian:
    python run_benchmark.py [--repeats 31] [--warmup 5] [--quick]
"""

import argparse
import concurrent.futures as cf
import os
import time

import attacker
import crypto_utils
import device_sim
import metrics
import receiver_server

RESULTS_DIR = "results"
DB_PATH = "data/log.sqlite"
RAW_CSV = os.path.join(RESULTS_DIR, "raw_results.csv")

CHANNELS = ["uart", "mqtt"]
S1_PAYLOAD = 256
S2_PAYLOADS = [64, 256, 1024]
S3_PAYLOAD = 256
S3_CONCURRENCY = [1, 10, 50]


def send_one(channel, uart_port, key, meta, payload_bytes):
    if channel == "uart":
        return device_sim.send_over_uart(uart_port, key, meta, payload_bytes)
    return device_sim.send_over_mqtt(key, meta, payload_bytes)


def run_scenario_performance(scenario_code, channel, payload_bytes, concurrency,
                              repeats, uart_port, key, writer: metrics.MetricsWriter,
                              sampler: metrics.ResourceSampler):
    def one_iteration(i):
        meta = {
            "scenario": scenario_code, "channel": channel, "condition": "normal",
            "attack_variant": None, "payload_bytes": payload_bytes,
            "concurrency": concurrency, "iteration": i,
        }
        rtt_ms, throughput_kbps, ack = send_one(channel, uart_port, key, meta, payload_bytes)
        res = sampler.summary()
        writer.write({
            "scenario": scenario_code, "channel": channel, "condition": "normal",
            "payload_bytes": payload_bytes, "concurrency": concurrency, "iteration": i,
            "rtt_ms": round(rtt_ms, 4), "throughput_kbps": round(throughput_kbps, 4),
            "cpu_percent": round(res["cpu_percent_mean"], 3), "ram_mb": round(res["ram_mb_mean"], 3),
            "tag_valid": ack.get("status") == "ok", "detected_tamper": "",
            "attack_variant": "", "timestamp": time.time(),
        })

    if concurrency <= 1:
        for i in range(1, repeats + 1):
            one_iteration(i)
    else:
        with cf.ThreadPoolExecutor(max_workers=concurrency) as ex:
            list(ex.map(one_iteration, range(1, repeats + 1)))


def run_scenario_security(channel, payload_bytes, repeats, uart_port, key,
                           writer: metrics.MetricsWriter):
    conditions = [("normal", None)] + [("tampered", v) for v in attacker.ATTACK_VARIANTS]
    for condition, variant in conditions:
        for i in range(1, repeats + 1):
            meta = {
                "scenario": "S4", "channel": channel, "condition": condition,
                "attack_variant": variant, "payload_bytes": payload_bytes,
                "concurrency": 1, "iteration": i,
            }
            rtt_ms, throughput_kbps, ack = send_one(channel, uart_port, key, meta, payload_bytes)
            accepted = ack.get("status") == "ok"
            if condition == "normal":
                detected = not accepted  # false rejection bila pesan valid malah ditolak
            else:
                detected = not accepted  # deteksi sukses bila pesan tampered ditolak
            writer.write({
                "scenario": "S4", "channel": channel, "condition": condition,
                "payload_bytes": payload_bytes, "concurrency": 1, "iteration": i,
                "rtt_ms": round(rtt_ms, 4), "throughput_kbps": round(throughput_kbps, 4),
                "cpu_percent": "", "ram_mb": "",
                "tag_valid": accepted, "detected_tamper": detected,
                "attack_variant": variant or "", "timestamp": time.time(),
            })


def warmup(channel, uart_port, key, n, uart_port_holder=None):
    for _ in range(n):
        meta = {"scenario": "warmup", "channel": channel, "condition": "normal",
                "attack_variant": None, "payload_bytes": 256, "concurrency": 1, "iteration": 0}
        try:
            send_one(channel, uart_port, key, meta, 256)
        except Exception:
            pass


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--repeats", type=int, default=31)
    ap.add_argument("--warmup", type=int, default=5)
    ap.add_argument("--quick", action="store_true", help="Mode cepat: repeats=5, tanpa S3=50")
    args = ap.parse_args()

    repeats = 5 if args.quick else args.repeats
    warmup_n = 2 if args.quick else args.warmup
    concurrency_levels = [1, 10] if args.quick else S3_CONCURRENCY

    os.makedirs(RESULTS_DIR, exist_ok=True)
    os.makedirs("data", exist_ok=True)
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    if os.path.exists(RAW_CSV):
        os.remove(RAW_CSV)

    print("=== FASE INISIALISASI ===")
    key = crypto_utils.generate_key()
    srv = receiver_server.ReceiverServer(key, db_path=DB_PATH)
    uart_port = srv.start_uart()
    srv.start_mqtt()
    sampler = metrics.ResourceSampler(interval=0.5)
    sampler.start()
    writer = metrics.MetricsWriter(RAW_CSV)
    time.sleep(0.3)
    print(f"Receiver aktif. UART simulasi pada port {uart_port}, MQTT broker in-process siap.")

    print("=== FASE PEMANASAN ===")
    for ch in CHANNELS:
        warmup(ch, uart_port, key, warmup_n)
    print(f"Pemanasan selesai ({warmup_n}x per jalur, tidak masuk hasil).")

    print("=== FASE PENGUJIAN PERFORMA ===")
    print("-- Skenario S1: Baseline --")
    for ch in CHANNELS:
        run_scenario_performance("S1", ch, S1_PAYLOAD, 1, repeats, uart_port, key, writer, sampler)
        print(f"  S1 {ch} selesai ({repeats} pengulangan)")

    print("-- Skenario S2: Variasi ukuran payload --")
    for ch in CHANNELS:
        for payload in S2_PAYLOADS:
            run_scenario_performance("S2", ch, payload, 1, repeats, uart_port, key, writer, sampler)
            print(f"  S2 {ch} payload={payload}B selesai")

    print("-- Skenario S3: Variasi konkurensi --")
    for ch in CHANNELS:
        for conc in concurrency_levels:
            run_scenario_performance("S3", ch, S3_PAYLOAD, conc, repeats, uart_port, key, writer, sampler)
            print(f"  S3 {ch} concurrency={conc} selesai")

    print("=== FASE PENGUJIAN KEAMANAN (S4) ===")
    for ch in CHANNELS:
        run_scenario_security(ch, S1_PAYLOAD, repeats, uart_port, key, writer)
        print(f"  S4 {ch} selesai (normal + {len(attacker.ATTACK_VARIANTS)} varian tampered)")

    sampler.stop()
    writer.close()
    srv.stop()
    print(f"\nSelesai. Hasil mentah tersimpan di {RAW_CSV}")
    print(f"Data valid & log verifikasi tersimpan di {DB_PATH}")


if __name__ == "__main__":
    main()
