"""
device_sim.py
==============
Simulator perangkat IoT: membangkitkan data sensor sintetis (suhu, kelembaban,
cahaya) dalam format JSON dengan ukuran payload bertingkat, melakukan enkripsi
TinyJambu-128 AEAD, dan mengirimkannya melalui UART atau MQTT.
"""

import json
import random
import time
import uuid

import attacker
import mqtt_channel
import uart_channel

ACK_TOPIC_PREFIX = "tinyjambu/ack/"
DATA_TOPIC = "tinyjambu/sensor/data"


def build_sensor_json(target_bytes: int) -> bytes:
    """Bangkitkan JSON data sensor sintetis dan padding agar mendekati target_bytes."""
    obj = {
        "suhu": round(random.uniform(20.0, 35.0), 2),
        "kelembaban": random.randint(40, 90),
        "cahaya": random.randint(100, 1000),
        "ts": round(time.time(), 3),
    }
    s = json.dumps(obj, separators=(",", ":"))
    needed = target_bytes - len(s)
    if needed <= 2:
        return s.encode()[:target_bytes] if len(s) > target_bytes else s.encode()

    overhead = len(',"filler":"' + '"')
    fill_len = max(0, needed - overhead)
    obj["filler"] = "x" * fill_len
    s2 = json.dumps(obj, separators=(",", ":"))
    diff = target_bytes - len(s2)
    if diff != 0:
        fill_len = max(0, fill_len + diff)
        obj["filler"] = "x" * fill_len
        s2 = json.dumps(obj, separators=(",", ":"))
    return s2.encode()


def build_envelope(device_id, key, meta, plaintext):
    condition = meta["condition"]
    variant = meta.get("attack_variant")
    ad = device_id.encode()
    nonce, ct, tag = attacker.make_packet(plaintext, ad, key, condition, variant)
    return {
        "meta": meta,
        "device_id": device_id,
        "nonce": nonce.hex(),
        "ciphertext": ct.hex(),
        "tag": tag.hex(),
    }


def send_over_uart(port, key, meta, target_payload_bytes, device_id=None):
    device_id = device_id or f"dev-{uuid.uuid4().hex[:8]}"
    plaintext = build_sensor_json(target_payload_bytes)
    envelope = build_envelope(device_id, key, meta, plaintext)
    payload_wire_bytes = json.dumps(envelope).encode()

    client = uart_channel.SerialClient(port)
    t0 = time.perf_counter()
    client.write_frame(payload_wire_bytes)
    ack_raw = client.read_frame(timeout=5.0)
    t1 = time.perf_counter()
    client.close()

    ack = json.loads(ack_raw) if ack_raw else {"status": "timeout"}
    rtt_ms = (t1 - t0) * 1000.0
    throughput_kbps = (len(payload_wire_bytes) * 8 / 1000.0) / (t1 - t0) if t1 > t0 else 0.0
    return rtt_ms, throughput_kbps, ack


def send_over_mqtt(key, meta, target_payload_bytes, device_id=None):
    device_id = device_id or f"dev-{uuid.uuid4().hex[:8]}"
    plaintext = build_sensor_json(target_payload_bytes)
    envelope = build_envelope(device_id, key, meta, plaintext)
    payload_wire_bytes = json.dumps(envelope).encode()

    client = mqtt_channel.MQTTClient(client_id=device_id)
    client.connect()
    client.subscribe(ACK_TOPIC_PREFIX + device_id)
    # Catatan: TIDAK memanggil loop_start() di sini karena device menunggu balasan
    # secara blocking lewat get_one(); loop_start() hanya untuk client bergaya
    # callback (dipakai oleh receiver_server sebagai subscriber topik data).

    t0 = time.perf_counter()
    client.publish(DATA_TOPIC, payload_wire_bytes)
    _topic, ack_raw = client.get_one(timeout=5.0)
    t1 = time.perf_counter()
    client._broker.unsubscribe_all(client.client_id)

    ack = json.loads(ack_raw) if ack_raw else {"status": "timeout"}
    rtt_ms = (t1 - t0) * 1000.0
    throughput_kbps = (len(payload_wire_bytes) * 8 / 1000.0) / (t1 - t0) if t1 > t0 else 0.0
    return rtt_ms, throughput_kbps, ack
