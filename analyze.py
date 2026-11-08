"""
analyze.py
===========
Mengolah berkas hasil pengujian (results/raw_results.csv) menjadi statistik
deskriptif (mean, standard deviation, confidence interval 95%), tabel, dan
grafik perbandingan. Juga mengekspor data ringkas ke dashboard/data.js agar
dashboard/index.html dapat menampilkannya tanpa perlu server terpisah.
"""

import json
import os
import sqlite3

import numpy as np
import pandas as pd
from scipy import stats

RESULTS_DIR = "results"
RAW_CSV = os.path.join(RESULTS_DIR, "raw_results.csv")
DB_PATH = "data/log.sqlite"
DASHBOARD_DATA_JS = "dashboard/data.js"


def ci95(series):
    series = series.dropna()
    n = len(series)
    if n < 2:
        return (float("nan"), float("nan"))
    mean = series.mean()
    sem = stats.sem(series)
    h = sem * stats.t.ppf(0.975, n - 1)
    return (mean - h, mean + h)


def summarize_group(df, group_cols, value_cols):
    rows = []
    for keys, g in df.groupby(group_cols):
        if not isinstance(keys, tuple):
            keys = (keys,)
        row = dict(zip(group_cols, keys))
        row["n"] = len(g)
        for vc in value_cols:
            s = pd.to_numeric(g[vc], errors="coerce").dropna()
            if len(s) == 0:
                row[f"{vc}_mean"] = None
                row[f"{vc}_sd"] = None
                row[f"{vc}_ci_low"] = None
                row[f"{vc}_ci_high"] = None
                continue
            lo, hi = ci95(s)
            row[f"{vc}_mean"] = round(float(s.mean()), 4)
            row[f"{vc}_sd"] = round(float(s.std(ddof=1)) if len(s) > 1 else 0.0, 4)
            row[f"{vc}_ci_low"] = round(float(lo), 4) if not np.isnan(lo) else None
            row[f"{vc}_ci_high"] = round(float(hi), 4) if not np.isnan(hi) else None
        rows.append(row)
    return pd.DataFrame(rows)


def analyze_performance(df):
    perf = df[df["scenario"].isin(["S1", "S2", "S3"])].copy()
    value_cols = ["rtt_ms", "throughput_kbps", "cpu_percent", "ram_mb"]
    summary = summarize_group(perf, ["scenario", "channel", "payload_bytes", "concurrency"], value_cols)
    summary.to_csv(os.path.join(RESULTS_DIR, "summary_performance.csv"), index=False)
    return summary


def analyze_security(df):
    sec = df[df["scenario"] == "S4"].copy()
    if sec.empty:
        return pd.DataFrame(), pd.DataFrame()

    sec["tag_valid_bool"] = sec["tag_valid"].astype(str).str.lower() == "true"
    sec["detected_bool"] = sec["detected_tamper"].astype(str).str.lower() == "true"

    rows = []
    for (scenario, channel, condition, variant), g in sec.groupby(
        ["scenario", "channel", "condition", "attack_variant"], dropna=False
    ):
        n = len(g)
        if condition == "tampered":
            detection_rate = g["detected_bool"].mean() * 100
            rows.append({
                "channel": channel, "condition": condition,
                "attack_variant": variant, "n": n,
                "detection_rate_pct": round(float(detection_rate), 2),
                "false_rejection_rate_pct": None,
            })
        else:
            false_rejection_rate = (~g["tag_valid_bool"]).mean() * 100
            rows.append({
                "channel": channel, "condition": condition,
                "attack_variant": "-", "n": n,
                "detection_rate_pct": None,
                "false_rejection_rate_pct": round(float(false_rejection_rate), 2),
            })
    security_summary = pd.DataFrame(rows)
    security_summary.to_csv(os.path.join(RESULTS_DIR, "summary_security.csv"), index=False)

    rtt_summary = summarize_group(sec, ["channel", "condition"], ["rtt_ms"])
    return security_summary, rtt_summary


def db_counts():
    if not os.path.exists(DB_PATH):
        return {"sensor_data": 0, "verification_log": 0}
    conn = sqlite3.connect(DB_PATH)
    n1 = conn.execute("SELECT COUNT(*) FROM sensor_data").fetchone()[0]
    n2 = conn.execute("SELECT COUNT(*) FROM verification_log").fetchone()[0]
    conn.close()
    return {"sensor_data": n1, "verification_log": n2}


def export_dashboard_data(perf_summary: pd.DataFrame, sec_summary: pd.DataFrame,
                            sec_rtt: pd.DataFrame, raw_df: pd.DataFrame):
    def df_records(d):
        return json.loads(d.replace({np.nan: None}).to_json(orient="records"))

    payload = {
        "generated_at": pd.Timestamp.now().isoformat(),
        "counts": db_counts(),
        "raw_total_rows": int(len(raw_df)),
        "performance": df_records(perf_summary) if not perf_summary.empty else [],
        "security_summary": df_records(sec_summary) if not sec_summary.empty else [],
        "security_rtt": df_records(sec_rtt) if not sec_rtt.empty else [],
    }
    os.makedirs("dashboard", exist_ok=True)
    with open(DASHBOARD_DATA_JS, "w") as f:
        f.write("// Berkas ini dibangkitkan otomatis oleh analyze.py — jangan diedit manual.\n")
        f.write("const BENCHMARK_DATA = ")
        json.dump(payload, f, indent=2)
        f.write(";\n")
    return payload


def main():
    if not os.path.exists(RAW_CSV):
        print(f"Berkas {RAW_CSV} tidak ditemukan. Jalankan run_benchmark.py terlebih dahulu.")
        return
    df = pd.read_csv(RAW_CSV)

    perf_summary = analyze_performance(df)
    sec_summary, sec_rtt = analyze_security(df)
    payload = export_dashboard_data(perf_summary, sec_summary, sec_rtt, df)

    print("=== Ringkasan Performa (S1-S3) ===")
    print(perf_summary.to_string(index=False))
    print("\n=== Ringkasan Keamanan (S4): Detection Rate & False Rejection Rate ===")
    print(sec_summary.to_string(index=False))
    print(f"\nData tersimpan di SQLite -> sensor_data: {payload['counts']['sensor_data']} baris, "
          f"verification_log: {payload['counts']['verification_log']} baris")
    print(f"\nBerkas keluaran:\n - {RESULTS_DIR}/summary_performance.csv\n - {RESULTS_DIR}/summary_security.csv\n - {DASHBOARD_DATA_JS}")

    try:
        make_charts(df, perf_summary)
    except Exception as e:
        print(f"(Grafik matplotlib dilewati: {e})")


def make_charts(df, perf_summary):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    # Grafik 1: Latensi vs ukuran payload (S2) per jalur komunikasi
    s2 = perf_summary[perf_summary["scenario"] == "S2"].sort_values("payload_bytes")
    if not s2.empty:
        fig, ax = plt.subplots(figsize=(6, 4))
        for ch, g in s2.groupby("channel"):
            ax.errorbar(g["payload_bytes"], g["rtt_ms_mean"],
                        yerr=(g["rtt_ms_mean"] - g["rtt_ms_ci_low"]).abs(),
                        marker="o", capsize=4, label=ch.upper())
        ax.set_xlabel("Ukuran payload (byte)")
        ax.set_ylabel("Latensi rata-rata (ms)")
        ax.set_title("Latensi vs Ukuran Payload (Skenario S2)")
        ax.legend()
        fig.tight_layout()
        fig.savefig(os.path.join(RESULTS_DIR, "chart_s2_latency.png"), dpi=150)
        plt.close(fig)

    # Grafik 2: Latensi & CPU vs konkurensi (S3)
    s3 = perf_summary[perf_summary["scenario"] == "S3"].sort_values("concurrency")
    if not s3.empty:
        fig, ax = plt.subplots(figsize=(6, 4))
        for ch, g in s3.groupby("channel"):
            ax.plot(g["concurrency"], g["rtt_ms_mean"], marker="o", label=f"{ch.upper()} latensi")
        ax.set_xlabel("Jumlah perangkat konkuren")
        ax.set_ylabel("Latensi rata-rata (ms)")
        ax.set_title("Latensi vs Tingkat Konkurensi (Skenario S3)")
        ax.legend()
        fig.tight_layout()
        fig.savefig(os.path.join(RESULTS_DIR, "chart_s3_concurrency.png"), dpi=150)
        plt.close(fig)

    print(f" - {RESULTS_DIR}/chart_s2_latency.png\n - {RESULTS_DIR}/chart_s3_concurrency.png")


if __name__ == "__main__":
    main()
