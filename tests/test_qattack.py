"""
Comprehensive Unit Tests for the QAttack Python Library (qattack).
Tests channel detection, the 3 attack vectors, random attack loop, and compatibility.
"""

import json
import time
import pytest
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
)


def test_imports_and_compatibility():
    """Verify primary and backward-compatible symbols are cleanly exportable."""
    assert QAttack is QuSecAttacker
    assert AttackType.FORGERY.value == "forgery"
    assert AttackType.IMPERSONATION.value == "impersonation"
    assert AttackType.QUANTUM_CHANNEL_MANIPULATION.value == "quantum_channel_manipulation"


def test_dynamic_threshold_engine():
    """Verify Hoeffding margin and dynamic threshold calculation."""
    engine = StandaloneDynamicThresholdEngine(baseline_q0=0.010, alpha_traffic=0.012)
    q_th, proof = engine.compute_threshold(sample_size_n=32, traffic_rate_phi=5.0)

    assert 0.035 <= q_th <= 0.110
    assert proof["q_baseline"] == 0.010
    assert proof["sample_size_n"] == 32
    assert proof["hoeffding_eps"] > 0
    assert proof["q_threshold"] == q_th


def test_channel_detector_and_packet_sniffing():
    """Verify ChannelDetector can discover and lock onto communication channel."""
    detector = ChannelDetector(
        default_target_ip="192.168.4.2",
        default_classical_port=9877,
        default_optical_port=9876,
    )
    chan = detector.start_detection(background=True)
    assert chan is not None
    assert chan.peer_b_ip == "192.168.4.2"
    assert chan.classical_port == 9877

    # Simulate packet arrival from Alice to Bob
    synthetic_qusec_packet = json.dumps({
        "type": "TELEPORT_MESSAGE",
        "sender": "Alice",
        "recipient_ip": "192.168.4.2",
        "payload": {"bob_qubits": [1, 0, 1]},
    }).encode("utf-8")

    detector._process_sniffed_packet(
        data=synthetic_qusec_packet,
        src_ip="192.168.4.1",
        src_port=54321,
        listen_port=9877,
    )

    locked = detector.current_channel
    assert locked.peer_a_ip == "192.168.4.1"
    assert locked.peer_b_ip == "192.168.4.2"
    assert locked.packet_count >= 1
    assert locked.is_locked is True

    detector.stop_detection()


def test_attack_vector_1_forgery():
    """Verify Attack 1: Forgery falsifies MAC and payload."""
    attacker = QAttack(
        target_host="127.0.0.1",
        target_classical_port=9877,
        target_optical_port=9876,
        force_simulation=True,
    )

    res = attacker.inject_forgery(fake_message="FORGED_PAYLOAD_TEST", target_role="Bob")
    assert res["attack_type"] == "forgery"
    assert "FORGED_PAYLOAD_TEST" in res["fake_message"]
    assert "INVALID_FORGED_WEGMAN_CARTER_MAC" in res["forged_mac"]
    assert "AUTHENTICATION FORGERY DETECTED" in res["expected_outcome"]
    assert attacker.stats["forgery_attacks"] == 1

    attacker.close()


def test_attack_vector_2_impersonation():
    """Verify Attack 2: Impersonation masquerades as legitimate peer."""
    attacker = QAttack(
        target_host="127.0.0.1",
        target_classical_port=9877,
        target_optical_port=9876,
        force_simulation=True,
    )

    res = attacker.inject_impersonation(impersonated_role="Alice", target_role="Bob")
    assert res["attack_type"] == "impersonation"
    assert res["impersonated_role"] == "Alice"
    assert res["target_role"] == "Bob"
    assert "IMPERSONATION DETECTED" in res["expected_outcome"]
    assert attacker.stats["impersonation_attacks"] == 1

    attacker.close()


def test_attack_vector_3_quantum_channel_manipulation():
    """Verify Attack 3: Quantum Channel Manipulation injects state disturbance exceeding Q_th."""
    attacker = QAttack(
        target_host="127.0.0.1",
        target_classical_port=9877,
        target_optical_port=9876,
        force_simulation=True,
    )

    res = attacker.inject_quantum_channel_manipulation(disturbance_rate=0.40)
    assert res["attack_type"] == "quantum_channel_manipulation"
    assert res["injected_qber"] > 0.0
    assert res["target_dynamic_threshold"] > 0.0
    assert "QUANTUM CHANNEL TAMPERING DETECTED" in res["expected_outcome"]
    assert attacker.stats["quantum_manipulation_attacks"] == 1

    attacker.close()


def test_attack_once_dispatcher():
    """Verify attack_once accepts string, int, and enum for all 3 attacks."""
    attacker = QAttack(target_host="127.0.0.1", force_simulation=True)

    r1 = attacker.attack_once(attack_type="1")
    assert r1["attack_type"] == "forgery"

    r2 = attacker.attack_once(attack_type="impersonation")
    assert r2["attack_type"] == "impersonation"

    r3 = attacker.attack_once(attack_type=AttackType.QUANTUM_CHANNEL_MANIPULATION, rate=0.30)
    assert r3["attack_type"] == "quantum_channel_manipulation"

    assert attacker.stats["attacks_launched"] == 3
    attacker.close()


def test_random_attack_daemon():
    """Verify background random attack thread fires and shuts down cleanly."""
    attacker = QAttack(target_host="127.0.0.1", force_simulation=True)

    # Set very fast interval for testing
    started = attacker.start_random_attacks(min_interval=0.1, max_interval=0.3)
    assert started is True
    assert attacker.auto_attack_enabled is True

    # Allow daemon to fire at least one attack
    time.sleep(0.7)
    assert attacker.stats["auto_attacks_count"] >= 1
    assert attacker.stats["attacks_launched"] >= 1

    attacker.stop_random_attacks()
    assert attacker.auto_attack_enabled is False
    attacker.close()


def test_qubit_frame_tampering():
    """Verify raw qubit frame bit flipping."""
    attacker = QAttack(force_simulation=True)
    raw = json.dumps({"payload": [0, 0, 0, 0], "c0": 0, "c1": 0}).encode("utf-8")
    tampered_bytes = attacker.tamper_qubit_frame(raw, error_rate=1.0)
    tampered = json.loads(tampered_bytes.decode("utf-8"))

    assert tampered["payload"] == [1, 1, 1, 1]
    assert tampered["qubit_tampered"] is True
    assert tampered["c0"] == 1
    assert tampered["c1"] == 1

    attacker.close()
