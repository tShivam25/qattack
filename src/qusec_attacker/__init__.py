"""
QuSec Attacker — Compatibility wrapper forwarding to qattack.
"""

from qattack import (
    QAttack,
    QuSecAttacker,
    AttackType,
    ForgeryAttack,
    ImpersonationAttack,
    QuantumChannelManipulationAttack,
    ChannelDetector,
    DetectedChannel,
    AttackerESP32Device,
    StandaloneDynamicThresholdEngine,
    main,
    __version__,
)

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
