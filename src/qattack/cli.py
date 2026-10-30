"""
Command-Line Interface for the QAttack Library (qattack).
"""

import sys
import json
import argparse
from qattack.attacker import (
    QAttack,
    DEFAULT_CLASSICAL_PORT,
    DEFAULT_OPTICAL_PORT,
)


def main():
    parser = argparse.ArgumentParser(
        prog="qattack",
        description="QAttack — QuSec Communication Channel Attacker (Eve - Claude Code TUI)",
    )
    parser.add_argument("--target-host", default="127.0.0.1", help="Target Receiver IP (default: 127.0.0.1 or 192.168.4.2)")
    parser.add_argument("--target-classical-port", type=int, default=DEFAULT_CLASSICAL_PORT, help="Target classical UDP port (default: 9877, or 9879)")
    parser.add_argument("--target-optical-port", type=int, default=DEFAULT_OPTICAL_PORT, help="Target optical UDP port (default: 9876, or 9878)")
    parser.add_argument("--esp32-port", help="Attacker ESP32 serial port (e.g. COM5 or /dev/ttyUSB*)")
    parser.add_argument("--sim", action="store_true", help="Force software simulation mode (no physical ESP32)")
    parser.add_argument("--detect", action="store_true", help="Detect communication channel between the two ESP32s and exit")
    parser.add_argument(
        "--attack",
        choices=["1", "2", "3", "forgery", "impersonation", "quantum", "tamper", "qber", "replay", "jam"],
        help="Execute a specific attack from the 3 attack categories non-interactively",
    )
    parser.add_argument("--random", action="store_true", help="Launch directly into automated random attack mode")
    parser.add_argument("--message", default="Injected Adversary Transmission", help="Message payload for attack")
    parser.add_argument("--rate", type=float, default=0.35, help="Disturbance / flip error rate (default: 0.35)")

    args = parser.parse_args()

    attacker = QAttack(
        target_host=args.target_host,
        target_classical_port=args.target_classical_port,
        target_optical_port=args.target_optical_port,
        esp32_port=args.esp32_port,
        force_simulation=args.sim,
        auto_detect=True,
    )

    if args.detect:
        chan = attacker.detect_channel(background=False, timeout_sec=1.5)
        print(json.dumps(chan.to_dict(), indent=2))
        attacker.close()
        sys.exit(0)

    if args.attack:
        res = attacker.attack_once(attack_type=args.attack, rate=args.rate, message=args.message)
        print(json.dumps(res, indent=2))
        attacker.close()
        sys.exit(0)

    if args.random:
        attacker.start_random_attacks(min_interval=6.0, max_interval=16.0, disturbance_rate=args.rate)

    attacker.run_interactive()


if __name__ == "__main__":
    main()
