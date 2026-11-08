"""
dashboard_server.py
===================
Web server Flask untuk pemantauan real-time simulasi TinyJambu-128 IoT AEAD.
Menyediakan REST API untuk streaming data sensor dari SQLite, audit log keamanan,
serta kontrol untuk memulai benchmark langsung dari antarmuka web.
"""

import json
import os
import sqlite3
import subprocess
import sys
import threading
import time
from flask import Flask, jsonify, request, send_from_directory

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "data", "log.sqlite")
RESULTS_DIR = os.path.join(BASE_DIR, "results")
RAW_CSV = os.path.join(RESULTS_DIR, "raw_results.csv")
DASHBOARD_DIR = os.path.join(BASE_DIR, "dashboard")

try:
    import psutil
except ImportError:
    psutil = None

app = Flask(__name__, static_folder=DASHBOARD_DIR)

# Status eksekusi benchmark di latar belakang
benchmark_state = {
    "is_running": False,
    "current_scenario": "Idle",
    "progress_pct": 0,
    "log_message": "Siap dijalankan.",
    "started_at": None,
    "finished_at": None,
    "last_exit_code": 0,
}
benchmark_process = None
benchmark_lock = threading.Lock()


def get_db_connection():
    if not os.path.exists(DB_PATH):
        return None
    # Buka dengan timeout agar tidak lock saat simulasi menulis data
    conn = sqlite3.connect(DB_PATH, timeout=5.0)
    conn.row_factory = sqlite3.Row
    return conn


@app.route("/")
def index():
    return send_from_directory(DASHBOARD_DIR, "realtime.html")


@app.route("/realtime")
def realtime():
    return send_from_directory(DASHBOARD_DIR, "realtime.html")


@app.route("/report")
def report():
    return send_from_directory(DASHBOARD_DIR, "index.html")


@app.route("/dashboard/<path:filename>")
def static_dashboard(filename):
    return send_from_directory(DASHBOARD_DIR, filename)


@app.route("/api/status")
def api_status():
    global benchmark_state
    conn = get_db_connection()
    total_sensor = 0
    total_verif = 0
    total_accepted = 0
    total_rejected = 0

    if conn:
        try:
            c = conn.cursor()
            c.execute("SELECT count(*) FROM sensor_data")
            total_sensor = c.fetchone()[0]
            c.execute("SELECT count(*) FROM verification_log")
            total_verif = c.fetchone()[0]
            c.execute("SELECT count(*) FROM verification_log WHERE result = 'accepted'")
            total_accepted = c.fetchone()[0]
            c.execute("SELECT count(*) FROM verification_log WHERE result = 'rejected'")
            total_rejected = c.fetchone()[0]
        except Exception:
            pass
        finally:
            conn.close()

    cpu_pct = 0.0
    ram_pct = 0.0
    ram_mb = 0.0
    if psutil:
        cpu_pct = psutil.cpu_percent(interval=None)
        mem = psutil.virtual_memory()
        ram_pct = mem.percent
        ram_mb = round(mem.used / (1024 * 1024), 1)

    return jsonify({
        "benchmark": benchmark_state,
        "counts": {
            "sensor_records": total_sensor,
            "verifications": total_verif,
            "accepted": total_accepted,
            "rejected": total_rejected,
        },
        "system": {
            "cpu_percent": cpu_pct,
            "ram_percent": ram_pct,
            "ram_mb": ram_mb,
        }
    })


@app.route("/api/sensor-stream")
def api_sensor_stream():
    """Mengambil data sensor terbaru dari SQLite."""
    limit = request.args.get("limit", 30, type=int)
    after_id = request.args.get("after_id", 0, type=int)

    conn = get_db_connection()
    if not conn:
        return jsonify({"data": [], "last_id": after_id})

    try:
        c = conn.cursor()
        if after_id > 0:
            query = """
                SELECT id, device_id, channel, scenario, suhu, kelembaban, cahaya, device_ts, received_at
                FROM sensor_data
                WHERE id > ?
                ORDER BY id ASC
                LIMIT ?
            """
            c.execute(query, (after_id, limit))
        else:
            query = """
                SELECT id, device_id, channel, scenario, suhu, kelembaban, cahaya, device_ts, received_at
                FROM sensor_data
                ORDER BY id DESC
                LIMIT ?
            """
            c.execute(query, (limit,))

        rows = c.fetchall()
        data = [dict(r) for r in rows]
        last_id = max([r["id"] for r in data]) if data else after_id
        return jsonify({"data": data, "last_id": last_id})
    except Exception as e:
        return jsonify({"error": str(e), "data": [], "last_id": after_id}), 500
    finally:
        conn.close()


@app.route("/api/security-log")
def api_security_log():
    """Mengambil riwayat verifikasi enkripsi TinyJambu & deteksi tampering."""
    limit = request.args.get("limit", 30, type=int)
    after_id = request.args.get("after_id", 0, type=int)

    conn = get_db_connection()
    if not conn:
        return jsonify({"logs": [], "last_id": after_id})

    try:
        c = conn.cursor()
        if after_id > 0:
            query = """
                SELECT id, device_id, channel, scenario, condition_, attack_variant, result, reason, timestamp
                FROM verification_log
                WHERE id > ?
                ORDER BY id ASC
                LIMIT ?
            """
            c.execute(query, (after_id, limit))
        else:
            query = """
                SELECT id, device_id, channel, scenario, condition_, attack_variant, result, reason, timestamp
                FROM verification_log
                ORDER BY id DESC
                LIMIT ?
            """
            c.execute(query, (limit,))

        rows = c.fetchall()
        logs = [dict(r) for r in rows]
        last_id = max([r["id"] for r in logs]) if logs else after_id
        return jsonify({"logs": logs, "last_id": last_id})
    except Exception as e:
        return jsonify({"error": str(e), "logs": [], "last_id": after_id}), 500
    finally:
        conn.close()


@app.route("/api/performance-metrics")
def api_perf_metrics():
    """Mengambil baris metrik RTT & throughput terbaru dari results/raw_results.csv."""
    limit = request.args.get("limit", 30, type=int)
    if not os.path.exists(RAW_CSV):
        return jsonify({"metrics": []})

    try:
        import pandas as pd
        df = pd.read_csv(RAW_CSV)
        tail = df.tail(limit).to_dict(orient="records")
        return jsonify({"metrics": tail})
    except Exception as e:
        return jsonify({"error": str(e), "metrics": []})


def _run_benchmark_worker(mode="quick"):
    global benchmark_state, benchmark_process
    python_exe = sys.executable

    cmd = [python_exe, "run_benchmark.py"]
    if mode == "quick":
        cmd.append("--quick")

    try:
        with benchmark_lock:
            benchmark_state["is_running"] = True
            benchmark_state["log_message"] = f"Menjalankan benchmark ({mode})..."
            benchmark_state["started_at"] = time.time()
            benchmark_state["finished_at"] = None

        proc = subprocess.Popen(
            cmd,
            cwd=BASE_DIR,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1
        )
        benchmark_process = proc

        # Baca output baris demi baris
        for line in iter(proc.stdout.readline, ''):
            line_str = line.strip()
            if line_str:
                with benchmark_lock:
                    benchmark_state["log_message"] = line_str
                    if "S1" in line_str:
                        benchmark_state["current_scenario"] = "S1 - Baseline Latensi"
                    elif "S2" in line_str:
                        benchmark_state["current_scenario"] = "S2 - Variasi Payload"
                    elif "S3" in line_str:
                        benchmark_state["current_scenario"] = "S3 - Skalabilitas Konkurensi"
                    elif "S4" in line_str:
                        benchmark_state["current_scenario"] = "S4 - Uji Tampering Keamanan"
                    elif "Analisis" in line_str:
                        benchmark_state["current_scenario"] = "Menganalisis Hasil"

        proc.wait()
        exit_code = proc.returncode

        # Setelah benchmark selesai, jalankan analyze.py
        if exit_code == 0:
            with benchmark_lock:
                benchmark_state["log_message"] = "Menjalankan analisis statistik..."
            subprocess.run([python_exe, "analyze.py"], cwd=BASE_DIR, check=False)

        with benchmark_lock:
            benchmark_state["is_running"] = False
            benchmark_state["finished_at"] = time.time()
            benchmark_state["last_exit_code"] = exit_code
            benchmark_state["log_message"] = "Selesai dengan sukses!" if exit_code == 0 else f"Gagal (kode: {exit_code})"
            benchmark_state["current_scenario"] = "Selesai"

    except Exception as e:
        with benchmark_lock:
            benchmark_state["is_running"] = False
            benchmark_state["log_message"] = f"Kesalahan: {e}"
            benchmark_state["current_scenario"] = "Error"
    finally:
        benchmark_process = None


@app.route("/api/run", methods=["POST"])
def api_run_benchmark():
    global benchmark_state
    if benchmark_state["is_running"]:
        return jsonify({"status": "error", "message": "Benchmark sedang berjalan!"}), 400

    data = request.get_json(silent=True) or {}
    mode = data.get("mode", "quick")

    th = threading.Thread(target=_run_benchmark_worker, args=(mode,), daemon=True)
    th.start()

    return jsonify({"status": "ok", "message": f"Benchmark ({mode}) dimulai di latar belakang."})


@app.route("/api/stop", methods=["POST"])
def api_stop_benchmark():
    global benchmark_process, benchmark_state
    if benchmark_process and benchmark_state["is_running"]:
        try:
            benchmark_process.terminate()
            with benchmark_lock:
                benchmark_state["is_running"] = False
                benchmark_state["log_message"] = "Dihentikan oleh pengguna."
                benchmark_state["current_scenario"] = "Dihentikan"
            return jsonify({"status": "ok", "message": "Benchmark dihentikan."})
        except Exception as e:
            return jsonify({"status": "error", "message": str(e)}), 500
    return jsonify({"status": "idle", "message": "Tidak ada proses yang sedang berjalan."})


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"================================================================")
    print(f" TinyJambu Real-Time Monitoring Dashboard Server")
    print(f" Berjalan di: http://127.0.0.1:{port}")
    print(f" Akses Dashboard Real-Time: http://127.0.0.1:{port}/realtime")
    print(f" Akses Laporan Benchmark:   http://127.0.0.1:{port}/report")
    print(f"================================================================")
    app.run(host="0.0.0.0", port=port, debug=False)

