# benchmark-tinyjambu

Implementasi kerja dari kerangka penelitian *"Benchmarking Algoritma Kriptografi
Tiny Jambu dengan Beban Kerja pada Perangkat IoT"* — sistem simulasi lengkap:
enkripsi AEAD, streaming data sensor via UART & MQTT, deteksi tampering, dan
dashboard pemantauan.

## Menjalankan

```bash
pip install psutil pandas numpy scipy matplotlib flask
python run_benchmark.py            # 31 pengulangan penuh (default, sesuai kerangka Bab 3.3)
python run_benchmark.py --quick    # mode cepat (5 pengulangan) untuk uji coba
python analyze.py                  # hitung mean/SD/CI95%, tulis dashboard/data.js & grafik PNG
```

Lalu buka `dashboard/index.html` langsung di browser (tidak perlu server —
data sudah ter-embed di `dashboard/data.js`).

## Struktur

Mengikuti persis Tabel 1 pada kerangka penelitian:

| Berkas | Isi |
|---|---|
| `crypto_utils.py` | Implementasi TinyJambu-128 AEAD (NLFSR 128-bit, key 128-bit, nonce 96-bit, tag 64-bit) |
| `device_sim.py` | Simulator perangkat: bangkitkan JSON sensor, enkripsi, kirim via UART/MQTT |
| `uart_channel.py` | Kanal UART simulasi (TCP loopback framed, API mirip pyserial) |
| `mqtt_channel.py` | Broker + client MQTT simulasi in-process (API mirip paho-mqtt) |
| `attacker.py` | 4 varian tampering: bitflip ciphertext, random tag, wrong nonce, wrong key |
| `receiver_server.py` | Verifikasi tag, dekripsi, simpan ke `data/log.sqlite`, kirim ACK |
| `metrics.py` | Perekam RTT, throughput, CPU%, RAM |
| `run_benchmark.py` | Orkestrator fase Inisialisasi → Pemanasan → S1/S2/S3 (performa) → S4 (keamanan) |
| `analyze.py` | Statistik deskriptif (mean, SD, CI95%) + grafik + ekspor data dashboard |
| `dashboard/index.html` | Dashboard monitoring (KPI, grafik latensi, tabel detection/false-rejection rate) |

## Keterbatasan penting (baca sebelum dipakai di skripsi)

1. **UART & MQTT disimulasikan secara software.** Sandbox pengembangan ini
   tidak memiliki port serial fisik maupun broker Mosquitto/akses jaringan,
   sehingga `uart_channel.py` memakai TCP loopback dan `mqtt_channel.py`
   memakai broker in-process bergaya publish/subscribe. Interfacenya sengaja
   dibuat mirip `pyserial`/`paho-mqtt` sehingga untuk pengujian di ESP32 asli,
   cukup ganti dua modul ini tanpa mengubah `device_sim.py`/`receiver_server.py`.
2. **Implementasi TinyJambu-128 mengikuti struktur publik algoritma** (state
   NLFSR 128-bit, permutasi P1024/P384, frame-bit domain separation) dan sudah
   diuji konsisten (round-trip enkripsi-dekripsi benar, tampering terdeteksi
   dan ditolak). Namun kesesuaian bit-exact terhadap test vector resmi NIST
   LWC belum divalidasi. Jika Bab metodologi/skripsi mengklaim kesesuaian
   standar resmi, validasikan `crypto_utils.py` terhadap reference
   implementation resmi NIST LWC terlebih dahulu.
3. Pengukuran CPU/RAM dilakukan pada satu proses host (pengirim & penerima
   berjalan di proses yang sama pada simulasi ini), sesuai batasan yang sudah
   dicatat pada Bab 8 kerangka penelitian — bukan representasi mikrokontroler
   produksi.

## Hasil contoh (31 pengulangan, sudah dijalankan)

Tersedia di `results/raw_results.csv` (mentah), `results/summary_performance.csv`,
`results/summary_security.csv`, dan dua grafik PNG. Detection rate = 100% dan
false rejection rate = 0% pada seluruh jalur komunikasi (UART & MQTT),
sesuai indikator keberhasilan Bab 7.
