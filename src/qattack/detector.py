"""
QuSec Attacker — Communication Channel Detector (qattack.detector).

Detects the active communication channel between the two ESP32 nodes
(Laptop A / ESP32-1 <-> Laptop B / ESP32-2 connected via optical fiber / Ethernet):
1. Hardware ESP32 Sniffing: Interrogates the Attacker ESP32 board for detected packets.
2. Passive UDP Channel Sniffer: Listens on common classical (9877, 9879) and optical (9876, 9878)
   ports to lock onto in-flight QuSec packet traffic.
3. Active Subnet / QuSec Discovery: Probes local interfaces and ESP32 default subnet (192.168.4.x).
"""

import os
import time
import json
import socket
import logging
import threading
from typing import Optional, Dict, Any, List, Callable

logger = logging.getLogger("qattack.detector")

DEFAULT_SEARCH_PORTS = [9877, 9879, 9876, 9878]


class DetectedChannel:
    """Represents a detected communication channel between two ESP32 / Laptop nodes."""

    def __init__(
        self,
        peer_a_ip: str = "192.168.4.1",
        peer_b_ip: str = "192.168.4.2",
        classical_port: int = 9877,
        optical_port: int = 9876,
        link_type: str = "Optical Fibre Link via Ethernet (UDP)",
        source_detection: str = "Passive Sniffer",
    ):
        self.peer_a_ip = peer_a_ip
        self.peer_b_ip = peer_b_ip
        self.classical_port = classical_port
        self.optical_port = optical_port
        self.link_type = link_type
        self.source_detection = source_detection
        self.packet_count = 0
        self.first_detected = time.time()
        self.last_seen = time.time()
        self.is_locked = True
        self.detected_protocols: List[str] = []

    def to_dict(self) -> Dict[str, Any]:
        return {
            "peer_a_ip": self.peer_a_ip,
            "peer_b_ip": self.peer_b_ip,
            "classical_port": self.classical_port,
            "optical_port": self.optical_port,
            "link_type": self.link_type,
            "source_detection": self.source_detection,
            "packet_count": self.packet_count,
            "is_locked": self.is_locked,
            "last_seen": self.last_seen,
            "protocols": self.detected_protocols,
        }

    def __str__(self) -> str:
        return (
            f"DetectedChannel({self.peer_a_ip} <---> {self.peer_b_ip} | "
            f"Classical UDP:{self.classical_port}, Optical UDP:{self.optical_port} | {self.link_type})"
        )


class ChannelDetector:
    """
    Automated Channel Detector for QuSec ESP32 Communication Links.
    Identifies the active communication channel between the two ESP32 nodes.
    """

    def __init__(
        self,
        esp32_device: Optional[Any] = None,
        default_target_ip: str = "127.0.0.1",
        default_classical_port: int = 9877,
        default_optical_port: int = 9876,
        on_channel_detected: Optional[Callable[[DetectedChannel], None]] = None,
    ):
        self.esp32_device = esp32_device
        self.default_target_ip = default_target_ip
        self.default_classical_port = default_classical_port
        self.default_optical_port = default_optical_port
        self.on_channel_detected = on_channel_detected

        self.current_channel: Optional[DetectedChannel] = None
        self.is_detecting = False
        self._stop_event = threading.Event()
        self._listener_threads: List[threading.Thread] = []
        self._listener_sockets: List[socket.socket] = []
        self.detection_history: List[Dict[str, Any]] = []

    def start_detection(self, background: bool = True) -> DetectedChannel:
        """
        Start channel detection.
        1. Checks physical Attacker ESP32 hardware bridge if available.
        2. Spawns passive UDP listeners on classical & optical ports.
        3. Returns the detected channel (or default channel if waiting for first packet).
        """
        if self.is_detecting:
            return self.current_channel or self._get_fallback_channel()

        self.is_detecting = True
        self._stop_event.clear()

        # 1. Attempt hardware detection through the Attacker ESP32 board
        hw_channel = self._detect_via_esp32_hardware()
        if hw_channel:
            self.current_channel = hw_channel
            if self.on_channel_detected:
                self.on_channel_detected(hw_channel)

        # 2. Start passive network packet listeners
        self._start_passive_listeners()

        # 3. If no channel detected yet, create default listening channel
        if not self.current_channel:
            self.current_channel = self._get_fallback_channel()

        if not background:
            # Synchronous wait for up to 2 seconds for active packets
            timeout = time.time() + 2.0
            while time.time() < timeout:
                if self.current_channel and self.current_channel.packet_count > 0:
                    break
                time.sleep(0.1)

        return self.current_channel

    def stop_detection(self):
        """Stop background channel detection listeners."""
        self.is_detecting = False
        self._stop_event.set()

        for s in self._listener_sockets:
            try:
                s.close()
            except Exception:
                pass
        self._listener_sockets.clear()

        for t in self._listener_threads:
            if t.is_alive():
                t.join(timeout=0.5)
        self._listener_threads.clear()

    def _get_fallback_channel(self) -> DetectedChannel:
        """Fallback candidate channel based on configured defaults."""
        return DetectedChannel(
            peer_a_ip="192.168.4.1",
            peer_b_ip=self.default_target_ip,
            classical_port=self.default_classical_port,
            optical_port=self.default_optical_port,
            link_type="Optical Fibre Link via Ethernet (UDP - Standby/Auto-Lock)",
            source_detection="Default Subnet Configuration",
        )

    def _detect_via_esp32_hardware(self) -> Optional[DetectedChannel]:
        """Query Attacker ESP32 for detected channel."""
        if not self.esp32_device or not getattr(self.esp32_device, "is_connected", False):
            return None

        try:
            logger.info("Probing Attacker ESP32 hardware for detected communication channel...")
            resp = self.esp32_device.send_command("DETECT")
            if resp and isinstance(resp, dict) and resp.get("status") == "OK":
                target_ip = resp.get("target_ip", self.default_target_ip)
                port = int(resp.get("target_port", self.default_classical_port))
                chan = DetectedChannel(
                    peer_a_ip="192.168.4.1",
                    peer_b_ip=target_ip,
                    classical_port=port,
                    optical_port=port - 1 if port % 2 == 1 else port,
                    link_type="ESP32 Promiscuous Sniffer Detected Link",
                    source_detection="Attacker ESP32 Hardware",
                )
                chan.packet_count = resp.get("packets_sniffed", 1)
                return chan
        except Exception as e:
            logger.debug("ESP32 hardware detection query failed: %s", e)
        return None

    def _start_passive_listeners(self):
        """Bind passive UDP sniffer sockets to catch in-flight QuSec packets."""
        # Try binding to common QuSec ports
        for port in DEFAULT_SEARCH_PORTS:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                if hasattr(socket, "SO_REUSEPORT"):
                    try:
                        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
                    except Exception:
                        pass
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                sock.settimeout(0.4)
                sock.bind(("0.0.0.0", port))
                self._listener_sockets.append(sock)

                thread = threading.Thread(
                    target=self._listen_port_worker,
                    args=(sock, port),
                    daemon=True,
                    name=f"ChannelSniffer-{port}",
                )
                thread.start()
                self._listener_threads.append(thread)
            except Exception as e:
                logger.debug("Could not bind detector on port %d: %s", port, e)

    def _listen_port_worker(self, sock: socket.socket, port: int):
        """Worker thread listening on a specific UDP port for channel packets."""
        while not self._stop_event.is_set() and self.is_detecting:
            try:
                data, addr = sock.recvfrom(65535)
                src_ip, src_port = addr
                self._process_sniffed_packet(data, src_ip, src_port, port)
            except socket.timeout:
                continue
            except Exception:
                break

    def _process_sniffed_packet(self, data: bytes, src_ip: str, src_port: int, listen_port: int):
        """Inspect packet and update detected communication channel."""
        try:
            text = data.decode("utf-8", errors="ignore")
            # Check for QuSec signature keywords
            is_qusec = any(
                k in text for k in (
                    "TELEPORT_MESSAGE", "TELEPORT_QUANTUM_BURST", "QUSEC",
                    "bob_qubits", "c0_bits", "c1_bits", "quantum_signature",
                    "Wegman-Carter", "KEY_EXCHANGE"
                )
            )

            # Extract destination info if JSON
            target_ip = self.default_target_ip
            proto_name = "QUSEC_UDP"
            try:
                pkt_json = json.loads(text)
                proto_name = pkt_json.get("type", "QUSEC_PACKET")
                if "recipient_ip" in pkt_json:
                    target_ip = pkt_json["recipient_ip"]
            except Exception:
                pass

            now = time.time()
            if self.current_channel is None:
                self.current_channel = DetectedChannel(
                    peer_a_ip=src_ip,
                    peer_b_ip=target_ip if target_ip != "127.0.0.1" else src_ip,
                    classical_port=listen_port if listen_port % 2 == 1 else listen_port + 1,
                    optical_port=listen_port if listen_port % 2 == 0 else listen_port - 1,
                    link_type="Optical Fibre Link via Ethernet (UDP Sniffed)",
                    source_detection=f"Passive Sniffer (Port {listen_port})",
                )
            else:
                # Update channel
                if src_ip not in (self.current_channel.peer_a_ip, "127.0.0.1"):
                    self.current_channel.peer_a_ip = src_ip
                if target_ip not in (self.current_channel.peer_b_ip, "127.0.0.1"):
                    self.current_channel.peer_b_ip = target_ip

            self.current_channel.packet_count += 1
            self.current_channel.last_seen = now
            self.current_channel.is_locked = True
            if proto_name not in self.current_channel.detected_protocols:
                self.current_channel.detected_protocols.append(proto_name)

            self.detection_history.append({
                "time": now,
                "src": f"{src_ip}:{src_port}",
                "dest_port": listen_port,
                "bytes": len(data),
                "is_qusec": is_qusec,
                "protocol": proto_name,
            })
            if len(self.detection_history) > 100:
                self.detection_history.pop(0)

            if self.on_channel_detected:
                self.on_channel_detected(self.current_channel)

        except Exception as ex:
            logger.debug("Sniffed packet parse error: %s", ex)
