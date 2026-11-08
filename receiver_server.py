"""
receiver_server.py
====================
Menerima paket dari jalur UART maupun MQTT, melakukan verifikasi tag
TinyJambu, dekripsi TinyJambu-128, penyimpanan hasil valid ke SQLite, serta
pencatatan log verifikasi (untuk mendukung perhitungan detection rate dan
false rejection rate pada skenario S4).
"""

import json
import sqlite3
import threading
import time

import mqtt_channel
import uart_channel
from crypto_utils import TinyJambuContext, TinyJambuError

DATA_TOPIC = "tinyjambu/sensor/data"
ACK_TOPIC_PREFIX = "tinyjambu/ack/"

DB_SCHEMA = """
CREATE TABLE IF NOT EXISTS sensor_data (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id TEXT,
    channel TEXT,
    scenario TEXT,
    suhu REAL,
    kelembaban REAL,
    cahaya REAL,
    device_ts REAL,
    received_at REAL
);
CREATE TABLE IF NOT EXISTS verification_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id TEXT,
    channel TEXT,
    scenario TEXT,
    condition_ TEXT,
    attack_variant TEXT,
    result TEXT,
    reason TEXT,
    timestamp REAL
);
"""


def init_db(path):
    conn = sqlite3.connect(path, check_same_thread=False)
    conn.executescript(DB_SCHEMA)
    conn.commit()
    return conn


class ReceiverServer:
    def __init__(self, key: bytes, db_path="data/log.sqlite"):
        self.ctx = TinyJambuContext(key)
        self.conn = init_db(db_path)
        self._db_lock = threading.Lock()
        self._uart_server = None
        self._mqtt_client = None

    # -- inti verifikasi & penyimpanan --------------------------------
    def _handle_envelope_bytes(self, raw: bytes, channel: str):
        try:
            envelope = json.loads(raw.decode())
        except Exception:
            return {"status": "error", "reason": "malformed_envelope"}

        device_id = envelope.get("device_id", "unknown")
        meta = envelope.get("meta", {})
        scenario = meta.get("scenario", "")
        condition = meta.get("condition", "")
        variant = meta.get("attack_variant")
        nonce = bytes.fromhex(envelope["nonce"])
        ct = bytes.fromhex(envelope["ciphertext"])
        tag = bytes.fromhex(envelope["tag"])
        ad = device_id.encode()

        result, reason, ack = "rejected", "", {"status": "rejected"}
        try:
            pt = self.ctx.decrypt(nonce, ct, tag, associated_data=ad)
            data = json.loads(pt.decode())
            with self._db_lock:
                self.conn.execute(
                    "INSERT INTO sensor_data (device_id, channel, scenario, suhu, kelembaban, cahaya, device_ts, received_at) "
                    "VALUES (?,?,?,?,?,?,?,?)",
                    (device_id, channel, scenario, data.get("suhu"), data.get("kelembaban"),
                     data.get("cahaya"), data.get("ts"), time.time()),
                )
                self.conn.commit()
            result, ack = "accepted", {"status": "ok"}
        except TinyJambuError as e:
            reason = str(e)
        except Exception as e:
            reason = f"error:{e}"

        with self._db_lock:
            self.conn.execute(
                "INSERT INTO verification_log (device_id, channel, scenario, condition_, attack_variant, result, reason, timestamp) "
                "VALUES (?,?,?,?,?,?,?,?)",
                (device_id, channel, scenario, condition, variant, result, reason, time.time()),
            )
            self.conn.commit()
        return ack

    # -- UART -----------------------------------------------------------
    def start_uart(self, port=0):
        self._uart_server = uart_channel.SerialServer(port=port)

        def handler(payload, _addr):
            ack = self._handle_envelope_bytes(payload, channel="uart")
            return json.dumps(ack).encode()

        self._uart_server.serve_forever(handler)
        return self._uart_server.port

    # -- MQTT -------------------------------------------------------------
    def start_mqtt(self):
        self._mqtt_client = mqtt_channel.MQTTClient(client_id="receiver")
        self._mqtt_client.connect()
        self._mqtt_client.subscribe(DATA_TOPIC)

        def on_message(_topic, payload):
            envelope_preview = json.loads(payload.decode())
            device_id = envelope_preview.get("device_id", "unknown")
            ack = self._handle_envelope_bytes(payload, channel="mqtt")
            self._mqtt_client.publish(ACK_TOPIC_PREFIX + device_id, json.dumps(ack).encode())

        self._mqtt_client.on_message_callback(on_message)
        self._mqtt_client.loop_start()

    def stop(self):
        if self._uart_server:
            self._uart_server.stop()
        if self._mqtt_client:
            self._mqtt_client.loop_stop()
