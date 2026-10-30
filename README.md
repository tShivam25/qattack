# ⚡ QAttack (`qattack`)
### QuSec Adversary Engine, Communication Channel Sniffer & Threat Vector Framework (Eve)

`qattack` is an independent Python library and Claude Code styled TUI console designed to demonstrate real-world adversarial attacks against quantum-secured communication links established by `qusec`.

---

## 🌐 Testbed Topology

```
   ┌─────────────────────────────────────────────────────────────┐
   │             OPTICAL FIBER LINK VIA ETHERNET                 │
   │           Classical UDP: 9877  |  Optical UDP: 9876         │
   └──────────────────────────────┬──────────────────────────────┘
                                  │
         ┌────────────────────────┴────────────────────────┐
         ▼                                                 ▼
┌──────────────────┐                             ┌──────────────────┐
│ Laptop A (Alice) │                             │  Laptop B (Bob)  │
│  + ESP32 Node 1  │                             │  + ESP32 Node 2  │
└──────────────────┘                             └──────────────────┘
         ▲                                                 ▲
         │                                                 │
         └───────────── [COMMUNICATION CHANNEL] ───────────┘
                                  ▲
                         Tampered & Detected By
                                  │
                   ┌──────────────────────────────┐
                   │    Laptop C (Attacker / Eve)  │
                   │    Running `qattack` Library │
                   │              +               │
                   │   Attacker ESP32 (Node 3)    │
                   │  - GPIO 4 Threat Strobe LED  │
                   │  - Promiscuous Sniffer       │
                   │  - Hardware TRNG Generator   │
                   └──────────────────────────────┘
```

---

## 🚀 Key Features

1. **Automated Channel Detection:**
   - Detects the active communication channel between Laptop A/ESP32-1 and Laptop B/ESP32-2.
   - Automatically sniffs in-flight packets, captures target IP and UDP ports (classical: 9877, optical: 9876), and locks onto the link.
   - Hardware-assisted detection via the 3rd Attacker ESP32 promiscuous sniffer.

2. **The 3 Canonical Attack Vectors:**
   - **1. Forgery:** Modifies in-transit classical message payloads, corrupts Wegman-Carter universal hash MAC tags, and falsifies Quantum Digital Signatures (QDS).
     * *Expected Outcome:* `REJECTED (AUTHENTICATION FORGERY DETECTED: INVALID WEGMAN-CARTER MAC / SIGNATURE MISMATCH)`
   - **2. Impersonation:** Spoofs legitimate peer identities (posing as Alice or Bob) and injects fraudulent handshake/command frames without authentic quantum pre-shared keys.
     * *Expected Outcome:* `REJECTED (IMPERSONATION DETECTED: UNAUTHORIZED SENDER IDENTITY / FAILED PEER AUTHENTICATION)`
   - **3. Quantum Channel Manipulation:** Directly tampers with the optical fiber link. Intercepts flying qubits in conjugate bases (state collapse), injects phase flips & bit flips into quantum state vectors, manipulates Pauli coordinate reconciliation corrections ($c_0, c_1$), and drives QBER above the dynamic threshold $Q_{th}$.
     * *Expected Outcome:* `REJECTED (QUANTUM CHANNEL TAMPERING DETECTED: QBER EXCEEDS DYNAMIC THRESHOLD)`

3. **Randomized In-Between Chat Auto-Attacks:**
   - Background daemon thread that randomly launches one of the 3 attack types at random intervals (e.g. every 6–18 seconds) during live chat exchanges.
   - Strobes the Attacker ESP32's high-intensity GPIO 4 alarm LED during each attack blast.

4. **Claude Code Styled TUI:**
   - Rounded border aesthetic, real-time status card, amber/coral accents, and interactive `╰─ ❯ ` prompt.

5. **Hardware Attacker ESP32 Bridge:**
   - Direct USB serial connection (115200 baud).
   - Hardware True Random Number Generation (`esp_random()`).
   - High-intensity threat strobe indicator on **GPIO 4**.

---

## 📦 Installation

```bash
cd qusec-attacker
pip install -e .
```

Both `qattack` and `qusec-attacker` commands are registered and available globally in your environment.

---

## 💻 Usage

### 1. Launch Interactive Claude Code TUI Console
```bash
# Connect to target receiver with automatic channel detection:
qattack --target-host 192.168.4.2

# Software simulation mode (no physical Attacker ESP32 connected):
qattack --target-host 127.0.0.1 --sim
```

### 2. Interactive Slash Commands Inside the TUI
- `/detect` — Scan and detect the communication channel between the two ESP32s
- `/channel` — Inspect current detected channel properties (IPs, ports, link medium)
- `/attack <1|2|3|forgery|impersonation|quantum> [param]` — Trigger a specific attack blast:
  * `/attack 1` or `/attack forgery [msg]` — Forgery Attack
  * `/attack 2` or `/attack impersonation [peer]` — Impersonation Attack
  * `/attack 3` or `/attack quantum [rate]` — Quantum Channel Manipulation Attack
- `/random <on|off> [min_sec] [max_sec]` — Toggle automated in-between chat randomized attacks
- `/threshold` — Inspect live dynamic Hoeffding QBER mathematical proof
- `/hardware` — Probe or reconnect Attacker ESP32 board
- `/stats` — View cumulative attack telemetry
- `/target <ip> [classical_port] [optical_port]` — Manually override target coordinates
- `/mitm <start|stop> [port]` — Start transparent packet sniffer / proxy
- `/help` — Display command palette
- `/exit`, `/quit` — Shut down session

### 3. Non-Interactive CLI Execution
```bash
# Channel Detection:
qattack --sim --detect

# Attack 1: Forgery
qattack --sim --attack 1 --message "Tampered Bank Transfer Payload"

# Attack 2: Impersonation
qattack --sim --attack 2 --message "Unauthorized Rogue Node Command"

# Attack 3: Quantum Channel Manipulation
qattack --sim --attack 3 --rate 0.40

# Launch directly into background randomized attack daemon:
qattack --sim --random
```

---

## 🐍 Python Library API

```python
from qattack import QAttack, AttackType

# Initialize attacker
attacker = QAttack(target_host="192.168.4.2", auto_detect=True)

# 1. Detect channel between the 2 ESP32s
chan = attacker.detect_channel()
print("Detected channel:", chan)

# 2. Attack 1: Forgery
res1 = attacker.inject_forgery(fake_message="Forged message")

# 3. Attack 2: Impersonation
res2 = attacker.inject_impersonation(impersonated_role="Alice")

# 4. Attack 3: Quantum Channel Manipulation
res3 = attacker.inject_quantum_channel_manipulation(disturbance_rate=0.35)

# 5. Automated randomized attack daemon
attacker.start_random_attacks(min_interval=6.0, max_interval=18.0)

# Close cleanly
attacker.close()
```

---

## ⚡ ESP32 Attacker Firmware

The dedicated Arduino C++ firmware is located at:
`firmware/esp32_attacker/esp32_attacker.ino`

### Hardware Pin Mapping:
- **GPIO 2:** Primary Status / Link LED (Onboard Blue LED — Solid when connected, pulses on serial commands)
- **GPIO 4:** Adversary Attack Blast Indicator LED (Strobes rapidly at 70–110ms during active attack bursts)
- **USB-Serial:** 115200 baud

### Flashing Instructions:
1. Open `firmware/esp32_attacker/esp32_attacker.ino` in Arduino IDE.
2. Select Board: **ESP32 Dev Module**.
3. Connect the 3rd ESP32 (Attacker Node) to the 3rd laptop via USB.
4. Select the corresponding serial port (`/dev/ttyUSB*` or `COM*`).
5. Click **Upload**.
