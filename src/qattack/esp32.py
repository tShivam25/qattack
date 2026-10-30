"""
QuSec Attacker — Hardware ESP32 Microcontroller Interface (qattack.esp32).

Handles USB serial communication with the 3rd ESP32 board (Eve / Attacker node):
- Promiscuous packet sniffing & channel detection between the two target ESP32s.
- True Hardware Random Number Generation (TRNG) via internal esp_random().
- High-intensity threat strobe LED (GPIO 4) control during active attacks.
- Raw wireless Wi-Fi and UDP injection triggers.
"""

import os
import time
import json
import logging
from typing import Optional, Dict, Any, List

logger = logging.getLogger("qattack.esp32")

DEFAULT_BAUD_RATE = 115200

try:
    import serial
    import serial.tools.list_ports
    HAS_SERIAL = True
except ImportError:
    HAS_SERIAL = False


class AttackerESP32Device:
    """Hardware controller for the Attacker's dedicated ESP32 microcontroller (Eve)."""

    def __init__(self, port: Optional[str] = None, baudrate: int = DEFAULT_BAUD_RATE, timeout: float = 1.0):
        self.port = port
        self.baudrate = baudrate
        self.timeout = timeout
        self._serial: Optional[Any] = None
        self.is_connected = False
        self.firmware_version = "Unknown"
        self.role = "ATTACKER"
        self.description = "ESP32 Attacker Board"

    @property
    def connected(self) -> bool:
        """Compatibility property."""
        return self.is_connected

    def auto_detect_and_connect(self, preferred_port: Optional[str] = None) -> bool:
        """Scan serial ports and connect to the Attacker ESP32 board."""
        if not HAS_SERIAL:
            logger.warning("pyserial is not installed. ESP32 hardware bridge disabled.")
            return False

        target_port = preferred_port or self.port
        if not target_port:
            try:
                ports = list(serial.tools.list_ports.comports())
                for p in ports:
                    p_desc = (p.description or "").lower()
                    p_hw = (p.hwid or "").lower()
                    if any(x in p_desc or x in p_hw for x in ("ch340", "cp210", "ftdi", "usb serial", "esp32")):
                        target_port = p.device
                        break
                if not target_port and ports:
                    for p in ports:
                        if "usb" in p.device.lower():
                            target_port = p.device
                            break
            except Exception as e:
                logger.debug("Port scanning error: %s", e)

        if not target_port:
            logger.info("No ESP32 board detected. Running in software emulation mode.")
            return False

        try:
            self._serial = serial.Serial(target_port, self.baudrate, timeout=self.timeout)
            time.sleep(1.8)  # Allow ESP32 boot sequence
            self.port = target_port
            self.is_connected = True

            # Query firmware identification
            resp = self.send_command("PING")
            if resp and isinstance(resp, dict):
                self.firmware_version = resp.get("firmware", resp.get("fw", "v2.5-ATTACKER"))
                self.description = resp.get("device", "ESP32-Attacker")

            logger.info("Attacker ESP32 connected on %s (%s)", self.port, self.description)
            return True
        except Exception as e:
            logger.warning("Failed to connect to ESP32 on %s: %s", target_port, e)
            self.is_connected = False
            self._serial = None
            return False

    def disconnect(self):
        """Safely close serial connection."""
        if self._serial:
            try:
                self.set_alarm(False)
                self._serial.close()
            except Exception:
                pass
            self._serial = None
        self.is_connected = False

    def send_command(self, cmd: str) -> Optional[Any]:
        """Send a formatted text command to the Attacker ESP32."""
        if not self.is_connected or not self._serial:
            return None
        try:
            self._serial.write(f"{cmd.strip()}\n".encode("utf-8"))
            self._serial.flush()
            line = self._serial.readline().decode("utf-8", errors="replace").strip()
            if not line:
                return None
            try:
                return json.loads(line)
            except Exception:
                return {"raw": line}
        except Exception as e:
            logger.debug("Serial command '%s' failed: %s", cmd, e)
            return None

    def get_trng_bytes(self, num_bytes: int = 32) -> bytes:
        """Fetch true hardware random bytes from ESP32 esp_random() generator."""
        if self.is_connected:
            resp = self.send_command(f"RNG {num_bytes}")
            if isinstance(resp, dict) and "hex" in resp:
                try:
                    return bytes.fromhex(resp["hex"])
                except Exception:
                    pass
        return os.urandom(num_bytes)

    def get_hardware_entropy(self, num_bytes: int = 32) -> bytes:
        """Alias for get_trng_bytes."""
        return self.get_trng_bytes(num_bytes)

    def set_alarm(self, enable: bool = True, blink_ms: int = 100) -> bool:
        """Control Attacker ESP32 attack blast LED (GPIO 4)."""
        if not self.is_connected:
            return False
        cmd = f"ALARM {'1' if enable else '0'} {blink_ms}"
        resp = self.send_command(cmd)
        return bool(resp and isinstance(resp, dict) and resp.get("status") == "OK")

    def detect_channel(self) -> Optional[Dict[str, Any]]:
        """Ask ESP32 to report detected communication channel between the other two ESP32s."""
        if not self.is_connected:
            return None
        resp = self.send_command("DETECT")
        if resp and isinstance(resp, dict):
            return resp
        return None

    def trigger_hardware_attack(self, attack_name: str, param: float = 0.35) -> bool:
        """Signal Attacker ESP32 to assist with physical attack execution."""
        if not self.is_connected:
            return False
        cmd = f"ATTACK {attack_name.upper()} {param}"
        resp = self.send_command(cmd)
        return bool(resp and isinstance(resp, dict) and resp.get("status") == "OK")

    def transmit_wifi_packet(self, packet_bytes: bytes) -> bool:
        """Transmit packet wirelessly via ESP32 Wi-Fi relay (TX command)."""
        if not self.is_connected:
            return False
        hex_data = packet_bytes.hex()
        resp = self.send_command(f"TX {hex_data}")
        return bool(resp and isinstance(resp, dict) and resp.get("status") == "OK")

    def set_target(self, ip: str, port: int) -> bool:
        """Configure target IP and port on Attacker ESP32."""
        if not self.is_connected:
            return False
        resp = self.send_command(f"SET_TARGET {ip} {port}")
        return bool(resp and isinstance(resp, dict) and resp.get("status") == "OK")

    def set_sniffer(self, enable: bool = True) -> bool:
        """Toggle promiscuous packet sniffer on Attacker ESP32."""
        if not self.is_connected:
            return False
        resp = self.send_command(f"SNIFF {'1' if enable else '0'}")
        return bool(resp and isinstance(resp, dict) and resp.get("status") == "OK")
