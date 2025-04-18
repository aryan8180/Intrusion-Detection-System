# Scapy-based packet capture
from scapy.all import sniff, IP, TCP, UDP
from queue import Queue
import threading

class PacketCapture:
    def __init__(self, interface="eth0"):
        self.interface = interface
        self.packet_queue = Queue(maxsize=1000)
        self.stop_event = threading.Event()

    def _packet_handler(self, packet):
        if IP in packet and (TCP in packet or UDP in packet):
            self.packet_queue.put(packet)

    def start(self):
        def capture():
            sniff(
                iface=self.interface,
                prn=self._packet_handler,
                store=False,
                stop_filter=lambda _: self.stop_event.is_set()
            )
        self.thread = threading.Thread(target=capture)
        self.thread.start()

    def stop(self):
        self.stop_event.set()
        self.thread.join()