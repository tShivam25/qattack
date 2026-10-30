"""
QAttack — QuSec Adversary Engine & Threat Vector Framework (qattack.attacker).

Core Engine for:
- Detecting communication channels between two ESP32 nodes connected via optical fiber/Ethernet.
- Launching the 3 primary attack vectors:
  1. Forgery (MAC / signature falsification & payload corruption)
  2. Impersonation (Spoofed peer identity & unauthorized node hijacking)
  3. Quantum Channel Manipulation (Qubit state collapse, phase flips, QBER injection > Q_th)
- Automated randomized in-between chat attacks.
- Dynamic mathematical QBER threshold proofs.
- Hardware ESP32 bridge (GPIO 4 alarm strobe, hardware TRNG, packet TX).
"""

import os
import sys
import time
import json
import math
import uuid
import random
import socket
import logging
import threading
from typing import Optional, Dict, Any, List, Tuple, Union

from qattack.attacks import (
    AttackType,
    ForgeryAttack,
    ImpersonationAttack,
    QuantumChannelManipulationAttack,
    string_to_bits,
    bits_to_string,
)
from qattack.detector import ChannelDetector, DetectedChannel
from qattack.esp32 import AttackerESP32Device
from qattack.tui import (
    get_console,
    render_claude_banner,
    render_attack_card,
    render_channel_card,
    print_help,
    HAS_RICH,
)

logger = logging.getLogger("qattack.core")

DEFAULT_CLASSICAL_PORT = 9877
DEFAULT_OPTICAL_PORT = 9876


def hoeffding_margin(n: int, delta: float = 0.001) -> float:
    """Calculate Hoeffding confidence margin for sample size n."""
    if n <= 0:
        return 0.0
    return math.sqrt(math.log(2.0 / delta) / (2.0 * n))


class StandaloneDynamicThresholdEngine:
    """
    Mathematical Dynamic QBER Threshold Engine.
    Formula: Q_th(n, Phi) = min(0.110, max(0.035, Q0 + alpha*Phi + beta*eps_hoeffding))
    """

    def __init__(
        self,
        baseline_q0: float = 0.010,
        alpha_traffic: float = 0.012,
        beta_stat: float = 0.28,
        confidence_delta: float = 0.001,
        max_qber_ceiling: float = 0.110,
        min_qber_floor: float = 0.035,
    ):
        self.baseline_q0 = baseline_q0
        self.alpha_traffic = alpha_traffic
        self.beta_stat = beta_stat
        self.confidence_delta = confidence_delta
        self.max_qber_ceiling = max_qber_ceiling
        self.min_qber_floor = min_qber_floor
        self._timestamps: List[float] = []
        self._window_seconds = 4.0

    def record_transmission(self):
        self._timestamps.append(time.time())

    def get_traffic_rate(self) -> float:
        now = time.time()
        self._timestamps = [t for t in self._timestamps if now - t <= self._window_seconds]
        return len(self._timestamps) / self._window_seconds

    def compute_threshold(self, sample_size_n: int = 32, traffic_rate_phi: Optional[float] = None) -> Tuple[float, Dict[str, Any]]:
        phi = traffic_rate_phi if traffic_rate_phi is not None else self.get_traffic_rate()
        delta_traffic = self.alpha_traffic * phi
        eps_hoeffding = hoeffding_margin(sample_size_n, self.confidence_delta)
        delta_stat = self.beta_stat * eps_hoeffding

        raw_threshold = self.baseline_q0 + delta_traffic + delta_stat
        q_clamped = max(self.min_qber_floor, min(self.max_qber_ceiling, raw_threshold))

        proof = {
            "q_baseline": self.baseline_q0,
            "traffic_rate_phi": phi,
            "delta_traffic": delta_traffic,
            "sample_size_n": sample_size_n,
            "hoeffding_eps": eps_hoeffding,
            "delta_stat": delta_stat,
            "q_raw": raw_threshold,
            "q_threshold": q_clamped,
        }
        return q_clamped, proof


class QAttack:
    """
    Primary QuSec Adversary Engine (qattack).
    Implements channel detection between the two target ESP32s, the 3 canonical
    attack types (Forgery, Impersonation, Quantum Channel Manipulation),
    and automated randomized attacks.
    """

    def __init__(
        self,
        target_host: str = "127.0.0.1",
        target_classical_port: Optional[int] = None,
        target_optical_port: Optional[int] = None,
        esp32_port: Optional[str] = None,
        force_simulation: bool = False,
        auto_detect: bool = True,
        target_port: Optional[int] = None,
        qber_baseline: Optional[float] = None,
        esp_port: Optional[str] = None,
        **kwargs,
    ):
        self.target_host = target_host
        self.target_classical_port = target_classical_port or target_port or DEFAULT_CLASSICAL_PORT
        self.target_optical_port = target_optical_port or ((target_port - 1) if target_port else DEFAULT_OPTICAL_PORT)
        self.force_simulation = force_simulation
        actual_esp = esp32_port or esp_port

        # Hardware interface (3rd ESP32 - Attacker board)
        self.esp32 = AttackerESP32Device(port=actual_esp)
        self.esp = self.esp32
        if not self.force_simulation:
            self.esp32.auto_detect_and_connect(preferred_port=actual_esp)

        # Dynamic QBER Threshold Engine
        baseline = qber_baseline if qber_baseline is not None else 0.010
        self.threshold_engine = StandaloneDynamicThresholdEngine(baseline_q0=baseline, alpha_traffic=0.012)

        # Communication Channel Detector
        self.detector = ChannelDetector(
            esp32_device=self.esp32,
            default_target_ip=self.target_host,
            default_classical_port=self.target_classical_port,
            default_optical_port=self.target_optical_port,
            on_channel_detected=self._on_channel_detected_update,
        )
        self.detected_channel: Optional[DetectedChannel] = None

        # Telemetry & Stats
        self.stats = {
            "attacks_launched": 0,
            "forgery_attacks": 0,
            "impersonation_attacks": 0,
            "quantum_manipulation_attacks": 0,
            "packets_injected": 0,
            "bytes_transmitted": 0,
            "tampered_packets": 0,
            "last_attack_type": "None",
            "last_injected_qber": 0.0,
            "last_attack_time": None,
            "auto_attacks_count": 0,
            "captured_packets": [],
            "channel_detections_count": 0,
        }

        # UDP Sockets for direct channel tampering
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

        # Console
        self.console = get_console()

        # MITM Proxy state
        self._proxy_running = False
        self._proxy_thread: Optional[threading.Thread] = None

        # Automated Randomized Attack state
        self.auto_attack_enabled = False
        self.auto_attack_min_interval = 6.0
        self.auto_attack_max_interval = 18.0
        self.auto_attack_rate = 0.35
        self._auto_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

        # Run channel detection if enabled
        if auto_detect:
            self.detect_channel(background=True)

    def _on_channel_detected_update(self, channel: DetectedChannel):
        """Callback invoked when channel detector locks onto communication traffic."""
        self.detected_channel = channel
        self.target_host = channel.peer_b_ip
        self.target_classical_port = channel.classical_port
        self.target_optical_port = channel.optical_port
        self.stats["channel_detections_count"] += 1
        logger.info("Channel locked onto: %s (Classical UDP: %d, Optical UDP: %d)",
                    channel.peer_b_ip, channel.classical_port, channel.optical_port)

    def detect_channel(self, background: bool = False, timeout_sec: float = 2.0) -> DetectedChannel:
        """
        Detect communication channel between the two target ESP32s.
        Uses Attacker ESP32 hardware sniffer and passive socket listener.
        """
        chan = self.detector.start_detection(background=background)
        self.detected_channel = chan
        if not background and timeout_sec > 0:
            time.sleep(min(timeout_sec, 0.8))
        return self.detected_channel

    def compute_dynamic_qber(self, sample_size: int = 32, traffic_rate: float = 0.0) -> float:
        """Compute dynamic QBER threshold for a given sample size and traffic rate."""
        q_th, _ = self.threshold_engine.compute_threshold(sample_size_n=sample_size, traffic_rate_phi=traffic_rate)
        return q_th

    def close(self):
        """Clean up threads, sockets, detectors, and hardware bridges."""
        self._stop_event.set()
        self.stop_random_attacks()
        self.stop_mitm_proxy()
        if self.detector:
            self.detector.stop_detection()
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass
        if self.esp32:
            self.esp32.disconnect()

    def _send_payload(self, packet: Dict[str, Any], port: Optional[int] = None) -> bool:
        """Send packet via UDP and optionally forward through Attacker ESP32 Wi-Fi."""
        target_port = port or self.target_classical_port
        try:
            raw_bytes = json.dumps(packet).encode("utf-8")
            self._sock.sendto(raw_bytes, (self.target_host, target_port))
            self.stats["packets_injected"] += 1
            self.stats["bytes_transmitted"] += len(raw_bytes)

            if self.esp32.is_connected:
                self.esp32.transmit_wifi_packet(raw_bytes)

            return True
        except Exception as e:
            logger.debug("Payload send error: %s", e)
            return False

    # =========================================================================
    # ATTACK VECTOR 1: FORGERY
    # =========================================================================
    def inject_forgery(
        self,
        fake_message: str = "FORGED_TRANSMISSION_FROM_ADVERSARY_EVE",
        target_role: str = "Bob",
        sender_role: str = "Alice",
        tamper_mode: str = "corrupt_mac",
    ) -> Dict[str, Any]:
        """
        ATTACK VECTOR 1: Forgery Attack.
        Modifies message payload, coordinates, and falsifies Wegman-Carter MACs
        and Quantum Digital Signatures (QDS) to test receiver integrity rejection.
        """
        # 1. Trigger hardware alarm strobe on Attacker ESP32 (GPIO 4)
        self.esp32.set_alarm(True, blink_ms=90)
        self.esp32.trigger_hardware_attack("FORGERY", param=1.0)

        # 2. Generate forged payload
        data = ForgeryAttack.generate_payload(
            fake_message=fake_message,
            target_role=target_role,
            sender_role=sender_role,
            tamper_mode=tamper_mode,
            sender_port=self.target_classical_port,
        )
        packet = data["packet"]
        summary = data["summary"]

        # 3. Transmit forged packet to target classical port
        self._send_payload(packet, port=self.target_classical_port)

        # 4. Update telemetry
        self.stats["attacks_launched"] += 1
        self.stats["forgery_attacks"] += 1
        self.stats["last_attack_type"] = "1. Forgery (MAC/Payload Falsification)"
        self.stats["last_attack_time"] = time.time()
        self.threshold_engine.record_transmission()

        # Turn off alarm after burst
        self.esp32.set_alarm(False)
        return summary

    # =========================================================================
    # ATTACK VECTOR 2: IMPERSONATION
    # =========================================================================
    def inject_impersonation(
        self,
        impersonated_role: str = "Alice",
        target_role: str = "Bob",
        message: str = "UNAUTHORIZED_COMMAND_IMPERSONATING_PEER",
        spoofed_ip: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        ATTACK VECTOR 2: Impersonation Attack.
        Eve masquerades as a legitimate ESP32 node (e.g. Alice) without holding
        valid pre-shared keys or quantum session credentials.
        """
        # 1. Trigger hardware alarm strobe on Attacker ESP32 (GPIO 4)
        self.esp32.set_alarm(True, blink_ms=110)
        self.esp32.trigger_hardware_attack("IMPERSONATION", param=1.0)

        # 2. Generate impersonation packet
        origin_ip = spoofed_ip or (self.detected_channel.peer_a_ip if self.detected_channel else "192.168.4.1")
        data = ImpersonationAttack.generate_payload(
            impersonated_role=impersonated_role,
            target_role=target_role,
            message=message,
            sender_port=self.target_classical_port,
            spoofed_ip=origin_ip,
        )
        packet = data["packet"]
        summary = data["summary"]

        # 3. Transmit impersonated frame
        self._send_payload(packet, port=self.target_classical_port)

        # 4. Update telemetry
        self.stats["attacks_launched"] += 1
        self.stats["impersonation_attacks"] += 1
        self.stats["last_attack_type"] = "2. Impersonation (Spoofed Peer Identity)"
        self.stats["last_attack_time"] = time.time()
        self.threshold_engine.record_transmission()

        self.esp32.set_alarm(False)
        return summary

    # =========================================================================
    # ATTACK VECTOR 3: QUANTUM CHANNEL MANIPULATION
    # =========================================================================
    def inject_quantum_channel_manipulation(
        self,
        message: str = "Quantum channel tampered in-flight",
        disturbance_rate: float = 0.35,
        target_role: str = "Bob",
        sender_role: str = "Alice",
    ) -> Dict[str, Any]:
        """
        ATTACK VECTOR 3: Quantum Channel Manipulation Attack.
        Tampers directly with the optical fiber link:
        - Injects conjugate basis measurement disturbance (state collapse).
        - Injects qubit phase flips and flips Pauli reconciliation coordinates (c0, c1).
        - Injects high QBER (> Q_th) to cause immediate transmission abort.
        """
        # 1. Trigger hardware alarm strobe on Attacker ESP32 (GPIO 4)
        self.esp32.set_alarm(True, blink_ms=75)
        self.esp32.trigger_hardware_attack("QUANTUM", param=disturbance_rate)

        # 2. Get hardware TRNG from ESP32 for genuine physical entropy injection
        trng = self.esp32.get_trng_bytes(64)

        # 3. Calculate dynamic Hoeffding threshold for comparison
        dyn_q_th, _ = self.threshold_engine.compute_threshold(sample_size_n=48)

        # 4. Generate quantum + classical attack frames
        data = QuantumChannelManipulationAttack.generate_payload(
            message=message,
            disturbance_rate=disturbance_rate,
            target_role=target_role,
            sender_role=sender_role,
            sender_classical_port=self.target_classical_port,
            sender_optical_port=self.target_optical_port,
            trng_bytes=trng,
            dynamic_q_th=dyn_q_th,
        )
        classical_packet = data["classical_packet"]
        optical_packet = data["optical_packet"]
        summary = data["summary"]

        # 5. Dispatch optical burst to optical UDP port
        try:
            raw_opt = json.dumps(optical_packet).encode("utf-8")
            self._sock.sendto(raw_opt, (self.target_host, self.target_optical_port))
            self.stats["packets_injected"] += 1
            self.stats["bytes_transmitted"] += len(raw_opt)
        except Exception as ex:
            logger.debug("Optical burst injection error: %s", ex)

        # 6. Dispatch classical coordination packet to classical UDP port
        self._send_payload(classical_packet, port=self.target_classical_port)

        # 7. Update telemetry
        self.stats["attacks_launched"] += 1
        self.stats["quantum_manipulation_attacks"] += 1
        self.stats["last_attack_type"] = "3. Quantum Channel Manipulation"
        self.stats["last_injected_qber"] = summary["injected_qber"]
        self.stats["last_attack_time"] = time.time()
        self.threshold_engine.record_transmission()

        self.esp32.set_alarm(False)
        return summary

    # Compatibility aliases
    def inject_qber_disturbance(self, message: str = "Compromised Quantum State", disturbance_rate: float = 0.35, **kwargs) -> Dict[str, Any]:
        """Backward-compatibility alias for Attack 3: Quantum Channel Manipulation."""
        return self.inject_quantum_channel_manipulation(message=message, disturbance_rate=disturbance_rate)

    def inject_pauli_tampering(self, message: str = "Tampered Pauli bits", flip_ratio: float = 0.35, **kwargs) -> Dict[str, Any]:
        """Backward-compatibility alias for Attack 3: Quantum Channel Manipulation (Pauli focus)."""
        return self.inject_quantum_channel_manipulation(message=message, disturbance_rate=flip_ratio)

    def inject_replay(self, target_role: str = "Bob") -> Dict[str, Any]:
        """Replay attack (sub-vector of Impersonation)."""
        return self.inject_impersonation(impersonated_role="Alice (Stale Replay)", target_role=target_role, message="STALE_REPLAY_FRAME")

    def inject_jamming_burst(self, packet_count: int = 20, delay: float = 0.04) -> Dict[str, Any]:
        """Jamming burst attack (entropy flood on detected channel)."""
        self.esp32.set_alarm(True, blink_ms=50)
        sent = 0
        for i in range(packet_count):
            noise = self.esp32.get_trng_bytes(64)
            pkt = {"type": "JAMMING_BURST", "index": i, "noise": noise.hex(), "ts": time.time()}
            self._send_payload(pkt, port=self.target_classical_port)
            sent += 1
            time.sleep(delay)
        self.esp32.set_alarm(False)
        return {"success": True, "attack": "jamming", "packets_sent": sent, "expected_outcome": "CORRUPTED / DROPPED"}

    def tamper_qubit_frame(self, raw_frame_bytes: bytes, error_rate: float = 0.5) -> bytes:
        """Directly tamper with raw optical qubit frames in flight."""
        try:
            data = json.loads(raw_frame_bytes.decode("utf-8"))
            if "payload" in data and isinstance(data["payload"], list):
                tampered = []
                for bit in data["payload"]:
                    tampered.append(1 - bit if random.random() < error_rate else bit)
                data["payload"] = tampered
                data["qubit_tampered"] = True
            if "c0" in data and random.random() < error_rate:
                data["c0"] = 1 - data["c0"]
            if "c1" in data and random.random() < error_rate:
                data["c1"] = 1 - data["c1"]
            return json.dumps(data).encode("utf-8")
        except Exception:
            return raw_frame_bytes

    def attack_once(self, attack_type: Union[str, int, AttackType] = "quantum", rate: float = 0.35, message: Optional[str] = None) -> Dict[str, Any]:
        """Execute a single attack burst from the 3 attack categories."""
        raw_key = str(attack_type).lower() if not isinstance(attack_type, AttackType) else attack_type.value

        if isinstance(attack_type, (str, int)):
            try:
                atk_enum = AttackType.from_string(str(attack_type))
            except ValueError:
                atk_enum = AttackType.QUANTUM_CHANNEL_MANIPULATION
        else:
            atk_enum = attack_type

        if atk_enum == AttackType.FORGERY:
            msg = message or "Adversary Forged Data Payload"
            res = self.inject_forgery(fake_message=msg)
            res["success"] = True
            res["attack_type"] = "forgery"
            return res
        elif atk_enum == AttackType.IMPERSONATION:
            msg = message or "Impersonated Handshake Frame"
            res = self.inject_impersonation(message=msg)
            res["success"] = True
            res["attack_type"] = "impersonation"
            return res
        elif atk_enum == AttackType.QUANTUM_CHANNEL_MANIPULATION:
            msg = message or "Quantum Optical Fiber Interception"
            res = self.inject_quantum_channel_manipulation(message=msg, disturbance_rate=rate)
            res["success"] = True
            if raw_key in ("tamper", "tampering"):
                res["attack_type"] = "tamper"
            elif raw_key == "qber":
                res["attack_type"] = "qber"
            else:
                res["attack_type"] = "quantum_channel_manipulation"
            return res
        else:
            res = self.inject_quantum_channel_manipulation(disturbance_rate=rate)
            res["success"] = True
            return res

    # =========================================================================
    # AUTOMATED RANDOMIZED ATTACK ENGINE
    # =========================================================================
    def start_random_attacks(
        self,
        min_interval: float = 6.0,
        max_interval: float = 18.0,
        disturbance_rate: float = 0.35,
    ) -> bool:
        """
        Start background daemon thread that randomly attacks the detected communication
        channel in between chats using the 3 attack types:
        1. Forgery
        2. Impersonation
        3. Quantum Channel Manipulation
        """
        if self.auto_attack_enabled:
            return True

        self.auto_attack_min_interval = min_interval
        self.auto_attack_max_interval = max_interval
        self.auto_attack_rate = disturbance_rate
        self.auto_attack_enabled = True
        self._stop_event.clear()

        def random_attack_loop():
            logger.info("Random attack daemon started on detected channel (%s).", self.target_host)
            while not self._stop_event.is_set():
                sleep_sec = random.uniform(self.auto_attack_min_interval, self.auto_attack_max_interval)
                for _ in range(int(sleep_sec * 10)):
                    if self._stop_event.is_set():
                        break
                    time.sleep(0.1)

                if self._stop_event.is_set():
                    break

                # Randomly pick 1 of the 3 canonical attack types
                chosen_attack = random.choice([
                    AttackType.FORGERY,
                    AttackType.IMPERSONATION,
                    AttackType.QUANTUM_CHANNEL_MANIPULATION,
                ])

                try:
                    if chosen_attack == AttackType.FORGERY:
                        res = self.inject_forgery(
                            fake_message="Automated random forgery attack in-between chats",
                            tamper_mode="corrupt_mac",
                        )
                        self._render_auto_attack_notification(
                            "1. Forgery Attack",
                            f"Fake Message: '{res['fake_message'][:28]}...' | MAC Corrupted"
                        )
                    elif chosen_attack == AttackType.IMPERSONATION:
                        res = self.inject_impersonation(
                            impersonated_role="Alice",
                            message="Automated random peer identity takeover attempt",
                        )
                        self._render_auto_attack_notification(
                            "2. Impersonation Attack",
                            f"Spoofing: {res['impersonated_role']} ➔ {res['target_role']}"
                        )
                    elif chosen_attack == AttackType.QUANTUM_CHANNEL_MANIPULATION:
                        res = self.inject_quantum_channel_manipulation(
                            message="Automated quantum optical state disturbance",
                            disturbance_rate=self.auto_attack_rate,
                        )
                        self._render_auto_attack_notification(
                            "3. Quantum Channel Manipulation",
                            f"Injected QBER: {res['injected_qber']*100:.1f}% (Q_th: {res['target_dynamic_threshold']*100:.2f}%)"
                        )

                    self.stats["auto_attacks_count"] += 1
                except Exception as e:
                    logger.debug("Random attack cycle error: %s", e)

        self._auto_thread = threading.Thread(target=random_attack_loop, daemon=True, name="EveRandomAttacker")
        self._auto_thread.start()
        return True

    def stop_random_attacks(self):
        """Halt background random attack daemon."""
        self.auto_attack_enabled = False
        self._stop_event.set()
        if self._auto_thread and self._auto_thread.is_alive():
            self._auto_thread.join(timeout=1.5)
        self._auto_thread = None

    def _render_auto_attack_notification(self, attack_name: str, detail: str):
        """Render notification line when an automated attack fires."""
        if self.console and HAS_RICH:
            self.console.print(
                f"[dim #718096]╭─[/dim #718096] [bold #FF6B6B]⚡ RANDOM ATTACK FIRED:[/bold #FF6B6B] "
                f"[bold white]{attack_name}[/bold white] [dim]({detail})[/dim] "
                f"[bold #ED8936]➔ Channel: {self.target_host}:{self.target_classical_port}[/bold #ED8936]"
            )
        else:
            print(f"[RANDOM ATTACK FIRED] {attack_name} ({detail}) -> {self.target_host}:{self.target_classical_port}")

    # =========================================================================
    # TRANSPARENT MITM PROXY
    # =========================================================================
    def start_mitm_proxy(
        self,
        listen_classical_port: int = 9887,
        listen_optical_port: int = 9886,
        tamper_mode: str = "selective",
    ) -> bool:
        """Start transparent Man-in-the-Middle (MITM) proxy server."""
        if self._proxy_running:
            return True

        self._proxy_running = True

        def proxy_loop():
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                sock.bind(("0.0.0.0", listen_classical_port))
                sock.settimeout(0.5)
            except Exception as e:
                logger.error("MITM proxy bind error: %s", e)
                return

            if self.console and HAS_RICH:
                self.console.print(
                    f"[bold green]✔ MITM Proxy listening on 0.0.0.0:{listen_classical_port} ➔ Forwarding to {self.target_host}:{self.target_classical_port}[/bold green]"
                )

            while self._proxy_running:
                try:
                    data, addr = sock.recvfrom(65535)
                    self.stats["captured_packets"].append({"time": time.time(), "src": addr, "bytes": len(data)})

                    modified_data = data
                    if tamper_mode != "pass":
                        try:
                            pkt = json.loads(data.decode("utf-8"))
                            if "payload" in pkt and isinstance(pkt["payload"], dict):
                                pkt["payload"]["eve_intercepted"] = True
                                if "text" in pkt["payload"]:
                                    pkt["payload"]["text"] = "[TAMPERED BY EVE] " + pkt["payload"]["text"]
                                modified_data = json.dumps(pkt).encode("utf-8")
                        except Exception:
                            pass

                    self._sock.sendto(modified_data, (self.target_host, self.target_classical_port))
                except socket.timeout:
                    continue
                except Exception as ex:
                    logger.debug("MITM forward exception: %s", ex)
                    break

            try:
                sock.close()
            except Exception:
                pass

        self._proxy_thread = threading.Thread(target=proxy_loop, daemon=True, name="EveMitmProxy")
        self._proxy_thread.start()
        return True

    def stop_mitm_proxy(self):
        """Stop MITM proxy."""
        self._proxy_running = False
        if self._proxy_thread and self._proxy_thread.is_alive():
            self._proxy_thread.join(timeout=1.0)
        self._proxy_thread = None

    def render_dashboard(self):
        """Render Claude Code styled banner & dashboard."""
        q_th, _ = self.threshold_engine.compute_threshold(sample_size_n=64)
        render_claude_banner(
            target_host=self.target_host,
            target_classical_port=self.target_classical_port,
            target_optical_port=self.target_optical_port,
            esp_connected=self.esp32.is_connected,
            esp_port=self.esp32.port,
            dyn_q_th=q_th,
            auto_attack_enabled=self.auto_attack_enabled,
            detected_channel=self.detected_channel,
            console=self.console,
        )

    # =========================================================================
    # INTERACTIVE CLAUDE CODE TUI SESSION
    # =========================================================================
    def run_interactive(self):
        """Run interactive Claude Code styled TUI session."""
        self.render_dashboard()

        while True:
            try:
                if self.console and HAS_RICH:
                    self.console.print("[dim #718096]╭─[/dim #718096] [bold #FF6B6B]qattack[/bold #FF6B6B] [dim]· QuSec Channel Adversary[/dim]")
                    user_input = input("╰─ ❯ ").strip()
                else:
                    user_input = input("qattack > ").strip()
            except (KeyboardInterrupt, EOFError):
                break

            if not user_input:
                continue

            parts = user_input.split()
            cmd = parts[0].lower()

            if cmd in ("/exit", "/quit", "exit", "quit"):
                if self.console and HAS_RICH:
                    self.console.print("[yellow]Shutting down QAttack adversary session...[/yellow]")
                break

            elif cmd in ("/help", "help", "?"):
                print_help(self.console)

            elif cmd in ("/clear", "clear", "cls"):
                os.system("clear" if os.name != "nt" else "cls")
                self.render_dashboard()

            elif cmd in ("/detect", "detect"):
                if self.console and HAS_RICH:
                    self.console.print("[cyan]🔍 Scanning network interfaces and Attacker ESP32 for communication channel...[/cyan]")
                chan = self.detect_channel(background=False, timeout_sec=1.5)
                render_channel_card(
                    {
                        "Peer A (Sender)": chan.peer_a_ip,
                        "Peer B (Receiver)": chan.peer_b_ip,
                        "Classical UDP Port": chan.classical_port,
                        "Optical UDP Port": chan.optical_port,
                        "Channel Link Medium": chan.link_type,
                        "Detection Source": chan.source_detection,
                        "Packets Intercepted": chan.packet_count,
                        "Status": "LOCKED & ARMED FOR ATTACK",
                    },
                    self.console,
                )

            elif cmd in ("/channel", "channel"):
                chan = self.detected_channel or self.detector._get_fallback_channel()
                render_channel_card(
                    {
                        "Peer A IP": chan.peer_a_ip,
                        "Peer B IP": chan.peer_b_ip,
                        "Classical Port": chan.classical_port,
                        "Optical Port": chan.optical_port,
                        "Link Type": chan.link_type,
                        "Detection Method": chan.source_detection,
                        "Packets Captured": chan.packet_count,
                        "Protocols": ", ".join(chan.detected_protocols) if chan.detected_protocols else "QUSEC_UDP",
                    },
                    self.console,
                )

            elif cmd == "/attack":
                if len(parts) < 2:
                    if self.console and HAS_RICH:
                        self.console.print(
                            "[bold red]Usage: /attack <1|2|3|forgery|impersonation|quantum> [param][/bold red]\n"
                            "[dim]1. Forgery  2. Impersonation  3. Quantum Channel Manipulation[/dim]"
                        )
                    continue

                atk_arg = parts[1].lower()

                if atk_arg in ("1", "forgery", "forge"):
                    msg = " ".join(parts[2:]) if len(parts) > 2 else "Adversary Forged Message Payload"
                    res = self.inject_forgery(fake_message=msg)
                    render_attack_card(
                        "1. Forgery Attack",
                        {
                            "Injected Payload": res["fake_message"],
                            "Target Peer": res["target_role"],
                            "Forged MAC Tag": res["forged_mac"],
                            "Expected Target Outcome": res["expected_outcome"],
                            "Hardware Alert": "GPIO 4 LED Strobed on Attacker ESP32",
                        },
                        self.console,
                    )
                elif atk_arg in ("2", "impersonation", "impersonate", "spoof"):
                    impersonate_peer = parts[2] if len(parts) > 2 else "Alice"
                    res = self.inject_impersonation(impersonated_role=impersonate_peer)
                    render_attack_card(
                        "2. Impersonation Attack",
                        {
                            "Impersonated Peer": res["impersonated_role"],
                            "Target Receiver": res["target_role"],
                            "Claimed ESP32 ID": res["claimed_sender_id"],
                            "Expected Target Outcome": res["expected_outcome"],
                            "Hardware Alert": "GPIO 4 LED Strobed on Attacker ESP32",
                        },
                        self.console,
                    )
                elif atk_arg in ("3", "quantum", "qber", "manipulation", "tamper"):
                    rate = float(parts[2]) if len(parts) > 2 else 0.35
                    res = self.inject_quantum_channel_manipulation(disturbance_rate=rate)
                    render_attack_card(
                        "3. Quantum Channel Manipulation",
                        {
                            "Injected QBER": f"{res['injected_qber']*100:.2f}%",
                            "Dynamic Q_th Threshold": f"{res['target_dynamic_threshold']*100:.2f}%",
                            "Disturbed Decoy Errors": f"{res['disturbed_errors']} / {res['conclusive_mu']}",
                            "Flipped Pauli Coords": res["flipped_pauli_coords"],
                            "Expected Target Outcome": res["expected_outcome"],
                            "Hardware Alert": "GPIO 4 LED Strobed on Attacker ESP32",
                        },
                        self.console,
                    )
                elif atk_arg in ("jam", "jamming"):
                    res = self.inject_jamming_burst(packet_count=15)
                    render_attack_card("Jamming Burst", res, self.console)
                elif atk_arg == "replay":
                    res = self.inject_replay()
                    render_attack_card("Replay Attack", res, self.console)
                else:
                    if self.console and HAS_RICH:
                        self.console.print(f"[bold red]Unknown attack: '{atk_arg}'. Choose 1 (Forgery), 2 (Impersonation), or 3 (Quantum).[/bold red]")

            elif cmd == "/random":
                if len(parts) < 2:
                    status = "ON" if self.auto_attack_enabled else "OFF"
                    if self.console and HAS_RICH:
                        self.console.print(f"[cyan]Random attack daemon is currently: [bold]{status}[/bold][/cyan]")
                        self.console.print("[dim]Usage: /random <on|off> [min_seconds] [max_seconds][/dim]")
                    continue

                mode = parts[1].lower()
                if mode in ("on", "start", "enable"):
                    min_sec = float(parts[2]) if len(parts) > 2 else 6.0
                    max_sec = float(parts[3]) if len(parts) > 3 else 18.0
                    self.start_random_attacks(min_interval=min_sec, max_interval=max_sec)
                    if self.console and HAS_RICH:
                        self.console.print(
                            f"[bold green]✔ Randomized In-Between Chat Attack Daemon ACTIVATED![/bold green]\n"
                            f"[dim white]Randomly firing (1. Forgery, 2. Impersonation, 3. Quantum) every {min_sec:.0f}–{max_sec:.0f}s.[/dim white]"
                        )
                else:
                    self.stop_random_attacks()
                    if self.console and HAS_RICH:
                        self.console.print("[yellow]Random in-between chat attack daemon DEACTIVATED.[/yellow]")

            elif cmd == "/target":
                if len(parts) < 2:
                    if self.console and HAS_RICH:
                        self.console.print(f"[cyan]Target Host: {self.target_host} | Classical: {self.target_classical_port} | Optical: {self.target_optical_port}[/cyan]")
                    continue
                self.target_host = parts[1]
                if len(parts) > 2:
                    self.target_classical_port = int(parts[2])
                if len(parts) > 3:
                    self.target_optical_port = int(parts[3])
                if self.console and HAS_RICH:
                    self.console.print(f"[green]✔ Target coordinates set to {self.target_host} (Classical:{self.target_classical_port}, Optical:{self.target_optical_port})[/green]")

            elif cmd == "/threshold":
                q_th, proof = self.threshold_engine.compute_threshold(sample_size_n=64)
                render_attack_card(
                    "Dynamic QBER Threshold Proof",
                    {
                        "Auto-Adjusted Q_th": f"{q_th:.4f} ({q_th*100:.2f}%)",
                        "Baseline Error (Q0)": f"{proof['q_baseline']*100:.2f}% (Optical Glass)",
                        "Traffic Rate (Phi)": f"{proof['traffic_rate_phi']:.2f} msgs/sec",
                        "Raman Traffic Offset": f"{proof['delta_traffic']*100:.2f}%",
                        "Hoeffding Margin (eps)": f"{proof['hoeffding_eps']*100:.2f}% (n={proof['sample_size_n']})",
                        "Stat Uncertainty (Delta)": f"{proof['delta_stat']*100:.2f}% (delta=0.001)",
                        "Formula": "Q_th(n, Phi) = min(0.110, max(0.035, Q0 + alpha*Phi + beta*eps))",
                    },
                    self.console,
                )

            elif cmd == "/hardware":
                if self.esp32.is_connected:
                    if self.console and HAS_RICH:
                        self.console.print(f"[green]✔ Attacker ESP32 active on {self.esp32.port} ({self.esp32.description})[/green]")
                else:
                    if self.console and HAS_RICH:
                        self.console.print("[yellow]Probing USB ports for Attacker ESP32...[/yellow]")
                    success = self.esp32.auto_detect_and_connect()
                    if success and self.console and HAS_RICH:
                        self.console.print(f"[bold green]✔ Attacker ESP32 connected on {self.esp32.port}![/bold green]")
                    elif self.console and HAS_RICH:
                        self.console.print("[red]No ESP32 detected on serial ports. Running in software simulation mode.[/red]")

            elif cmd == "/stats":
                render_attack_card(
                    "QAttack Adversary Telemetry",
                    {
                        "Total Attacks Launched": self.stats["attacks_launched"],
                        "1. Forgery Attacks": self.stats["forgery_attacks"],
                        "2. Impersonation Attacks": self.stats["impersonation_attacks"],
                        "3. Quantum Manipulation Attacks": self.stats["quantum_manipulation_attacks"],
                        "Random Background Attacks": self.stats["auto_attacks_count"],
                        "Packets Injected": self.stats["packets_injected"],
                        "Bytes Transmitted": f"{self.stats['bytes_transmitted']} bytes",
                        "Last Attack Dispatched": self.stats["last_attack_type"],
                        "Last Injected QBER": f"{self.stats['last_injected_qber']*100:.2f}%",
                        "Channel Detections": self.stats["channel_detections_count"],
                    },
                    self.console,
                )

            elif cmd == "/mitm":
                if len(parts) < 2:
                    status = "ACTIVE" if self._proxy_running else "STOPPED"
                    if self.console and HAS_RICH:
                        self.console.print(f"[cyan]MITM Proxy status: [bold]{status}[/bold][/cyan]")
                        self.console.print("[dim]Usage: /mitm <start|stop> [listen_port][/dim]")
                    continue

                sub_cmd = parts[1].lower()
                if sub_cmd in ("start", "on"):
                    port = int(parts[2]) if len(parts) > 2 else 9887
                    self.start_mitm_proxy(listen_classical_port=port)
                else:
                    self.stop_mitm_proxy()
                    if self.console and HAS_RICH:
                        self.console.print("[yellow]MITM Proxy halted.[/yellow]")

            else:
                if self.console and HAS_RICH:
                    self.console.print(f"[dim red]Unknown command: '{user_input}'. Type [bold cyan]/help[/bold cyan] for guidance.[/dim red]")

        self.close()


# Backward compatibility alias
QuSecAttacker = QAttack
