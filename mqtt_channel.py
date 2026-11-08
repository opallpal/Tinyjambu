"""
mqtt_channel.py
================
Menyediakan jalur publish/subscribe menuju broker MQTT.

Lingkungan pengujian ini tidak memiliki akses jaringan/broker Mosquitto
sungguhan, sehingga modul ini menyediakan SimulatedMQTTBroker + client
in-process yang meniru semantik publish/subscribe (topic-based, banyak
publisher & subscriber, tanpa koneksi point-to-point seperti UART).
Antarmuka client (connect/publish/subscribe/loop_start) sengaja dibuat
mirip paho-mqtt agar pada deployment nyata modul ini tinggal diganti dengan:

    import paho.mqtt.client as mqtt
    client = mqtt.Client()
    client.connect(broker_host, 1883)

tanpa mengubah device_sim.py maupun receiver_server.py secara signifikan.
"""

import queue
import threading
import time
import uuid


class SimulatedMQTTBroker:
    """Broker in-process: mencocokkan publisher ke seluruh subscriber pada topik yang sama."""

    _instance = None
    _lock = threading.Lock()

    def __init__(self):
        self._subscribers = {}  # topic -> {client_id: Queue}
        self._sub_lock = threading.Lock()

    @classmethod
    def instance(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = SimulatedMQTTBroker()
            return cls._instance

    def subscribe(self, topic, client_id, q):
        with self._sub_lock:
            self._subscribers.setdefault(topic, {})[client_id] = q

    def unsubscribe_all(self, client_id):
        with self._sub_lock:
            for subs in self._subscribers.values():
                subs.pop(client_id, None)

    def publish(self, topic, payload: bytes):
        with self._sub_lock:
            targets = list(self._subscribers.get(topic, {}).items())
        for _cid, q in targets:
            q.put((topic, payload, time.time()))


class MQTTClient:
    """Client MQTT simulasi. Bisa dipakai sebagai publisher (device) maupun subscriber (receiver)."""

    def __init__(self, client_id=None):
        self.client_id = client_id or str(uuid.uuid4())
        self._broker = SimulatedMQTTBroker.instance()
        self._queue = queue.Queue()
        self._on_message = None
        self._running = False
        self._thread = None

    def connect(self, *_args, **_kwargs):
        # Tidak ada koneksi jaringan nyata pada broker simulasi in-process.
        return 0

    def subscribe(self, topic, *_args, **_kwargs):
        self._broker.subscribe(topic, self.client_id, self._queue)

    def publish(self, topic, payload: bytes, *_args, **_kwargs):
        self._broker.publish(topic, payload)

    def on_message_callback(self, callback):
        """callback(topic, payload_bytes)"""
        self._on_message = callback

    def loop_start(self):
        self._running = True

        def loop():
            while self._running:
                try:
                    topic, payload, _ts = self._queue.get(timeout=0.5)
                except queue.Empty:
                    continue
                if self._on_message:
                    self._on_message(topic, payload)

        self._thread = threading.Thread(target=loop, daemon=True)
        self._thread.start()

    def loop_stop(self):
        self._running = False
        if self._thread:
            self._thread.join(timeout=2)
        self._broker.unsubscribe_all(self.client_id)

    def get_one(self, timeout=5.0):
        """Mode blocking (dipakai device_sim untuk menunggu balasan ACK dari receiver)."""
        try:
            topic, payload, _ts = self._queue.get(timeout=timeout)
            return topic, payload
        except queue.Empty:
            return None, None
