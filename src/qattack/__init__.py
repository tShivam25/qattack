"""
QAttack (qusec-attacker) — Threat Vector Demonstration & Adversary Framework for QuSec.
"""

from qattack.attacker import QAttack, QuSecAttacker, StandaloneDynamicThresholdEngine
from qattack.attacks import AttackType, ForgeryAttack, ImpersonationAttack, QuantumChannelManipulationAttack
from qattack.detector import ChannelDetector, DetectedChannel
from qattack.esp32 import AttackerESP32Device
from qattack.cli import main

__version__ = "0.2.0"
__all__ = [
    "QAttack",
    "QuSecAttacker",
    "AttackType",
    "ForgeryAttack",
    "ImpersonationAttack",
    "QuantumChannelManipulationAttack",
    "ChannelDetector",
    "DetectedChannel",
    "AttackerESP32Device",
    "StandaloneDynamicThresholdEngine",
    "main",
]
