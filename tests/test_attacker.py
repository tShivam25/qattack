"""
Unit Tests for standalone qusec-attacker library.
"""

import json
import pytest
from qusec_attacker import QuSecAttacker, AttackerESP32Device


def test_attacker_standalone_tampering():
    attacker = QuSecAttacker(
        target_host="127.0.0.1",
        target_classical_port=9877,
        target_optical_port=9876,
        force_simulation=True,
    )

    # 1. TRNG fallback
    assert attacker.esp.connected is False
    rand = attacker.esp.get_hardware_entropy(16)
    assert len(rand) == 16
    assert isinstance(rand, bytes)

    # 2. Dynamic threshold calculation
    q_th = attacker.compute_dynamic_qber(sample_size=64, traffic_rate=5.0)
    assert 0.035 <= q_th <= 0.110

    # 3. Qubit frame tampering
    raw_frame = json.dumps({"payload": [1, 0, 1, 0], "c0": 0, "c1": 1}).encode("utf-8")
    tampered = attacker.tamper_qubit_frame(raw_frame, error_rate=1.0)
    tampered_dict = json.loads(tampered.decode("utf-8"))
    assert tampered_dict.get("qubit_tampered") is True

    # 4. Attack once
    res = attacker.attack_once(attack_type="tamper", rate=0.30)
    assert res["success"] is True
    assert res["attack_type"] == "tamper"

    attacker.close()
