"""
QuSec Attacker — Threat Vector Definitions and Attack Generators (qattack).

Defines the 3 canonical attack types:
1. Forgery: Tampering with message contents and falsifying MAC/signatures.
2. Impersonation: Spoofing legitimate peer identity (Alice/Bob/ESP32).
3. Quantum Channel Manipulation: Eavesdropping, conjugate basis disturbance,
   qubit phase/bit flips, and QBER injection exceeding dynamic threshold.
"""

import time
import uuid
import random
import enum
from typing import Dict, Any, List, Optional, Tuple


class AttackType(enum.Enum):
    FORGERY = "forgery"
    IMPERSONATION = "impersonation"
    QUANTUM_CHANNEL_MANIPULATION = "quantum_channel_manipulation"

    @classmethod
    def from_string(cls, name: str) -> "AttackType":
        s = name.strip().lower()
        if s in ("1", "forgery", "forge", "mac", "tamper_mac"):
            return cls.FORGERY
        elif s in ("2", "impersonation", "impersonate", "spoof", "identity"):
            return cls.IMPERSONATION
        elif s in ("3", "quantum", "quantum_channel_manipulation", "qber", "intercept_resend", "pauli"):
            return cls.QUANTUM_CHANNEL_MANIPULATION
        raise ValueError(f"Unknown attack type: '{name}'. Valid: forgery, impersonation, quantum_channel_manipulation")


def string_to_bits(text: str) -> List[int]:
    """Convert a UTF-8 string into a list of binary bits (0 or 1)."""
    raw_bytes = text.encode("utf-8")
    bits = []
    for b in raw_bytes:
        for i in range(8):
            bits.append((b >> (7 - i)) & 1)
    return bits


def bits_to_string(bits: List[int]) -> str:
    """Convert a list of binary bits back to a string."""
    byte_vals = bytearray()
    for i in range(0, len(bits), 8):
        chunk = bits[i:i + 8]
        if len(chunk) < 8:
            break
        val = 0
        for b in chunk:
            val = (val << 1) | b
        byte_vals.append(val)
    return byte_vals.decode("utf-8", errors="replace")


class ForgeryAttack:
    """
    ATTACK TYPE 1: Forgery Attack.
    Tampers with in-transit classical message payloads, coordinates, and falsifies
    authentication tags (Wegman-Carter MAC or Quantum Digital Signatures QDS)
    without knowing the underlying one-time authentication key.
    """

    @staticmethod
    def generate_payload(
        fake_message: str = "FORGED_TRANSMISSION_ADVERSARY_EVE",
        target_role: str = "Bob",
        sender_role: str = "Alice",
        tamper_mode: str = "corrupt_mac",
        sender_port: int = 9877,
    ) -> Dict[str, Any]:
        msg_id = f"atk_forge_{uuid.uuid4().hex[:8]}"
        data_bits = string_to_bits(fake_message)
        bit_count = len(data_bits)

        # Classical coordination frame containing forged data
        classical_payload = {
            "msg_id": msg_id,
            "sender_role": f"{sender_role} (FORGED)",
            "recipient": target_role,
            "text": fake_message,
            "c0_bits": [0, 1] * (bit_count // 2 + 1),
            "c1_bits": [1, 0] * (bit_count // 2 + 1),
            "bob_qubits": [1, 1] * (bit_count // 2 + 1),
            "data_bit_count": bit_count,
            "test_indices": [bit_count + 1, bit_count + 2],
            "test_values": [1, 0],
            "test_bases": ["Z", "Z"],
            "decoy_types": ["mu", "mu"],
            "sender_classical_port": sender_port,
            "attack": {
                "active": True,
                "type": AttackType.FORGERY.value,
                "vector": "Payload / Wegman-Carter MAC Falsification",
                "timestamp": time.time(),
            },
            "quantum_signature": f"FORGED_QDS_SIGNATURE_{uuid.uuid4().hex[:16]}",
            "encrypted_payload": f"FORGED_CIPHERTEXT_{uuid.uuid4().hex[:32]}",
        }

        # Forged or corrupted MAC
        if tamper_mode == "corrupt_mac":
            mac_tag = f"INVALID_FORGED_WEGMAN_CARTER_MAC_{uuid.uuid4().hex[:16]}"
        elif tamper_mode == "zeroed_mac":
            mac_tag = "00000000000000000000000000000000"
        else:
            mac_tag = f"CORRUPTED_{uuid.uuid4().hex[:24]}"

        packet = {
            "type": "TELEPORT_MESSAGE",
            "sender": f"eve_forger_spoofing_{sender_role.lower()}",
            "payload": classical_payload,
            "mac": mac_tag,
            "forgery_meta": {
                "tampered_fields": ["text", "mac", "quantum_signature"],
                "target_node": target_role,
            },
        }

        result_summary = {
            "attack_type": AttackType.FORGERY.value,
            "display_title": "1. Forgery Attack",
            "msg_id": msg_id,
            "fake_message": fake_message,
            "target_role": target_role,
            "forged_mac": mac_tag,
            "expected_outcome": "REJECTED (AUTHENTICATION FORGERY DETECTED: INVALID WEGMAN-CARTER MAC / SIGNATURE MISMATCH)",
        }
        return {"packet": packet, "summary": result_summary}


class ImpersonationAttack:
    """
    ATTACK TYPE 2: Impersonation Attack.
    Eve masquerades as a trusted peer (e.g., Alice/ESP32-1 to Bob/ESP32-2)
    by injecting spoofed node credentials, fraudulent handshake requests,
    or claiming an established quantum session without authentic pre-shared keys.
    """

    @staticmethod
    def generate_payload(
        impersonated_role: str = "Alice",
        target_role: str = "Bob",
        message: str = "UNAUTHORIZED_COMMAND_IMPERSONATING_PEER",
        sender_port: int = 9877,
        spoofed_ip: str = "192.168.4.1",
    ) -> Dict[str, Any]:
        msg_id = f"atk_imp_{uuid.uuid4().hex[:8]}"
        stale_nonce = f"stale_nonce_{uuid.uuid4().hex[:12]}"

        # Craft an impersonated packet claiming to be Alice
        impersonated_payload = {
            "msg_id": msg_id,
            "sender_role": impersonated_role,  # Claims legitimate role
            "recipient": target_role,
            "text": message,
            "session_id": f"sess_spoofed_{uuid.uuid4().hex[:8]}",
            "sender_node_id": f"ESP32_{impersonated_role}_GENUINE",
            "spoofed_origin_ip": spoofed_ip,
            "nonce": stale_nonce,
            "data_bit_count": len(message) * 8,
            "c0_bits": [1, 0, 1, 0] * 8,
            "c1_bits": [0, 1, 0, 1] * 8,
            "bob_qubits": [1, 1, 1, 1] * 8,
            "sender_classical_port": sender_port,
            "attack": {
                "active": True,
                "type": AttackType.IMPERSONATION.value,
                "impersonated_entity": impersonated_role,
                "spoofed_credentials": True,
                "timestamp": time.time(),
            },
        }

        packet = {
            "type": "TELEPORT_MESSAGE",
            "sender": impersonated_role,  # Impersonating header
            "payload": impersonated_payload,
            "mac": f"UNVERIFIED_IMPERSONATED_KEY_MAC_{uuid.uuid4().hex[:16]}",
            "auth_header": {
                "claimed_identity": impersonated_role,
                "verified_by_kdf": False,
                "adversary_injected": True,
            },
        }

        result_summary = {
            "attack_type": AttackType.IMPERSONATION.value,
            "display_title": "2. Impersonation Attack",
            "msg_id": msg_id,
            "impersonated_role": impersonated_role,
            "target_role": target_role,
            "injected_message": message,
            "claimed_sender_id": f"ESP32_{impersonated_role}_GENUINE",
            "expected_outcome": "REJECTED (IMPERSONATION DETECTED: UNAUTHORIZED SENDER IDENTITY / FAILED PEER AUTHENTICATION)",
        }
        return {"packet": packet, "summary": result_summary}


class QuantumChannelManipulationAttack:
    """
    ATTACK TYPE 3: Quantum Channel Manipulation Attack.
    Tampers with the optical fiber link between the two ESP32s:
    - Eavesdrops via conjugate basis measurements (Intercept-Resend).
    - Injects phase flips, bit flips, and state decoherence into flying qubits.
    - Manipulates Pauli coordinate feed-forward classical bits (c0, c1).
    - Drives Quantum Bit Error Rate (QBER) above the dynamic Hoeffding threshold Q_th,
      forcing Alice and Bob's key-reconciliation engine to abort.
    """

    @staticmethod
    def generate_payload(
        message: str = "Quantum channel tampered in-flight",
        disturbance_rate: float = 0.35,
        target_role: str = "Bob",
        sender_role: str = "Alice",
        sender_classical_port: int = 9877,
        sender_optical_port: int = 9876,
        trng_bytes: Optional[bytes] = None,
        dynamic_q_th: float = 0.085,
    ) -> Dict[str, Any]:
        msg_id = f"atk_qcm_{uuid.uuid4().hex[:8]}"
        data_bits = string_to_bits(message)
        data_count = len(data_bits)
        num_test = max(16, int(data_count * 0.40))
        total_qubits = data_count + num_test

        if not trng_bytes or len(trng_bytes) < total_qubits:
            # Fallback or synthetic TRNG
            trng_bytes = bytes([random.randint(0, 255) for _ in range(total_qubits + 32)])

        c0_bits = []
        c1_bits = []
        bob_qubits = []
        test_indices = list(range(data_count, total_qubits))
        test_values = []
        test_bases = []
        decoy_types = []

        for i in range(total_qubits):
            c0 = (trng_bytes[i % len(trng_bytes)] >> 2) & 1
            c1 = (trng_bytes[i % len(trng_bytes)] >> 5) & 1
            c0_bits.append(c0)
            c1_bits.append(c1)
            decoy_types.append("mu" if i % 2 == 0 else "nu")

            original_bit = 1 if (c0 ^ c1) else 0

            # State disturbance via conjugate basis measurement
            if random.random() < disturbance_rate:
                bob_bit = 1 - original_bit  # Bit flipped by measurement collapse
            else:
                bob_bit = original_bit

            bob_qubits.append(bob_bit)
            if i in test_indices:
                test_values.append(original_bit)
                test_bases.append("Z")

        # Classical Pauli coordinate tampering in flight
        flipped_pauli = 0
        for i in range(len(c0_bits)):
            if random.random() < (disturbance_rate * 0.6):
                if random.random() < 0.5:
                    c0_bits[i] = 1 - c0_bits[i]
                else:
                    c1_bits[i] = 1 - c1_bits[i]
                flipped_pauli += 1

        # Calculate injected QBER on test decoy states
        conclusive_mu = 0
        disturbed_errors = 0
        for b_bit, t_val, decoy in zip(bob_qubits[data_count:], test_values, decoy_types[data_count:]):
            if decoy == "mu":
                conclusive_mu += 1
                if b_bit != t_val:
                    disturbed_errors += 1

        injected_qber = (disturbed_errors / conclusive_mu) if conclusive_mu > 0 else disturbance_rate

        # 1. Optical quantum channel frame (burst on optical UDP port)
        optical_payload = {
            "channel": "quantum_optical_fiber",
            "type": "TELEPORT_QUANTUM_BURST",
            "msg_id": msg_id,
            "ts": time.time(),
            "payload": {
                "msg_id": msg_id,
                "qubit_count": total_qubits,
                "data_qubits": data_count,
                "test_qubits": num_test,
                "basis": "Z",
                "bob_qubits": bob_qubits,
                "sender_optical_port": sender_optical_port,
                "manipulation": {
                    "eavesdropping_active": True,
                    "intercept_resend_rate": disturbance_rate,
                    "state_decoherence": True,
                },
            },
        }

        # 2. Classical coordination packet
        classical_payload = {
            "msg_id": msg_id,
            "sender_role": sender_role,
            "recipient": target_role,
            "text": message,
            "c0_bits": c0_bits,
            "c1_bits": c1_bits,
            "bob_qubits": bob_qubits,
            "data_bit_count": data_count,
            "test_indices": test_indices,
            "test_values": test_values,
            "test_bases": test_bases,
            "decoy_types": decoy_types,
            "sender_classical_port": sender_classical_port,
            "attack": {
                "active": True,
                "type": AttackType.QUANTUM_CHANNEL_MANIPULATION.value,
                "injected_qber": injected_qber,
                "disturbance_rate": disturbance_rate,
                "flipped_pauli_bits": flipped_pauli,
                "timestamp": time.time(),
            },
        }

        classical_packet = {
            "type": "TELEPORT_MESSAGE",
            "sender": "eve_quantum_adversary",
            "payload": classical_payload,
            "mac": f"EVE_OPTICAL_MANIPULATION_{uuid.uuid4().hex[:16]}",
        }

        result_summary = {
            "attack_type": AttackType.QUANTUM_CHANNEL_MANIPULATION.value,
            "display_title": "3. Quantum Channel Manipulation",
            "msg_id": msg_id,
            "injected_qber": injected_qber,
            "target_dynamic_threshold": dynamic_q_th,
            "disturbance_rate": disturbance_rate,
            "flipped_pauli_coords": flipped_pauli,
            "disturbed_errors": disturbed_errors,
            "conclusive_mu": conclusive_mu,
            "expected_outcome": f"REJECTED (QUANTUM CHANNEL TAMPERING DETECTED: QBER {injected_qber*100:.1f}% > Q_th {dynamic_q_th*100:.2f}%)",
        }

        return {
            "classical_packet": classical_packet,
            "optical_packet": optical_payload,
            "summary": result_summary,
        }
