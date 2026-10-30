/*
 * QuSec Dedicated Attacker ESP32 Firmware (Eve - Adversary Node)
 * ==============================================================
 * Specialized firmware for the 3rd ESP32 connected to the Attacker's Laptop (qattack).
 *
 * Testbed Environment:
 * - 2 Communicating Laptops (Alice & Bob) connected with ESP32s and Optical Fiber Link via Ethernet.
 * - 3rd Laptop running `qattack` Python library connected to this Attacker ESP32 via USB Serial.
 *
 * Responsibilities:
 * 1. Communication Channel Detection:
 *    - Sniffs packets between the two legitimate ESP32s (Laptop A & Laptop B).
 *    - Identifies target IP, ports (classical UDP 9877, optical UDP 9876), and packet cadence.
 * 2. 3 Attack Execution Modes (Hardware assisted):
 *    - Mode 1: FORGERY (Wegman-Carter MAC & Payload Falsification)
 *    - Mode 2: IMPERSONATION (Spoofed peer identity & unauthorized node injection)
 *    - Mode 3: QUANTUM CHANNEL MANIPULATION (Qubit disturbance & optical burst tampering)
 * 3. Hardware True Random Number Generation (TRNG) via internal esp_random()
 *    utilizing thermal noise and RF phase jitter.
 * 4. Hardware Visual Indicator:
 *    - GPIO 2: Primary Status / Link LED (Solid when connected).
 *    - GPIO 4: High-intensity Adversary Attack Blast Indicator LED (Strobes rapidly during active tampering).
 * 5. High-speed USB-Serial command interface (115200 baud).
 *
 * Hardware Pin Assignments:
 * - GPIO 2: Primary Status / Link LED (Onboard Blue LED)
 * - GPIO 4: Adversary Attack Blast Indicator LED
 */

#include <WiFi.h>
#include <WiFiUdp.h>
#include <esp_system.h>
#include <esp_wifi.h>

#define FIRMWARE_VERSION "3.0.0-QATTACK"
#define BAUD_RATE 115200
#define DEFAULT_CLASSICAL_PORT 9877
#define DEFAULT_OPTICAL_PORT   9876

// Hardware Pin Assignments
#define LED_STATUS_PIN 2   // Primary status LED (GPIO 2 onboard)
#define LED_ALARM_PIN  4   // Adversary Attack Blast LED (GPIO 4)

// Wi-Fi Configuration for dual mode / promiscuous link
const char* AP_SSID = "QuSec_ESP32_QuantumNet";
const char* AP_PASS = "QuantumSecure2026!";

WiFiUDP udp;
IPAddress targetIP(192, 168, 4, 2); // Default target is Bob (Receiver ESP32)
IPAddress sourceIP(192, 168, 4, 1); // Default detected sender is Alice (Sender ESP32)
int targetPort = DEFAULT_CLASSICAL_PORT;
int opticalPort = DEFAULT_OPTICAL_PORT;

// Attack Alert LED State (Non-blocking)
bool attackLedActive = false;
unsigned long lastAttackBlink = 0;
int attackBlinkInterval = 90; // Default 90ms rapid strobe
bool attackLedLevel = false;

// Statistics & Channel Detection State
unsigned long packetsInjected = 0;
unsigned long packetsSniffed = 0;
unsigned long trngBytesGenerated = 0;
unsigned long forgeryAttacks = 0;
unsigned long impersonationAttacks = 0;
unsigned long quantumAttacks = 0;
bool snifferActive = false;
bool channelLocked = false;

// Promiscuous Sniffer Callback
void wifiPromiscuousCallback(void* buf, wifi_promiscuous_pkt_type_t type) {
  if (!snifferActive) return;
  wifi_promiscuous_pkt_t* pkt = (wifi_promiscuous_pkt_t*)buf;
  int len = pkt->rx_ctrl.sig_len;
  if (len > 0 && len <= 128) {
    packetsSniffed++;
    Serial.print("SNIFF ");
    Serial.print(len);
    Serial.print(" ");
    for (int i = 0; i < min(len, 32); i++) {
      char hexBuf[3];
      sprintf(hexBuf, "%02x", pkt->payload[i]);
      Serial.print(hexBuf);
    }
    Serial.println();
  }
}

void initAttackerWiFi() {
  WiFi.disconnect(true);
  delay(100);

  // Connect as Station to QuSec network to intercept and inject
  WiFi.mode(WIFI_STA);
  WiFi.begin(AP_SSID, AP_PASS);

  udp.begin(DEFAULT_CLASSICAL_PORT);
}

void setup() {
  Serial.begin(BAUD_RATE);
  delay(300);

  pinMode(LED_STATUS_PIN, OUTPUT);
  pinMode(LED_ALARM_PIN, OUTPUT);

  digitalWrite(LED_STATUS_PIN, HIGH); // Status ON
  digitalWrite(LED_ALARM_PIN, LOW);   // Attack LED OFF initially

  initAttackerWiFi();

  // Announce Attacker firmware ready
  Serial.println("{\"status\":\"READY\",\"firmware\":\"" FIRMWARE_VERSION "\",\"role\":\"QATTACK_EVE\",\"attack_pin\":4,\"status_pin\":2}");
}

void handleAttackerCommand(String cmd);

void loop() {
  // 1. Process serial commands from Laptop QAttack Python library
  if (Serial.available() > 0) {
    String cmd = Serial.readStringUntil('\n');
    cmd.trim();
    if (cmd.length() > 0) {
      handleAttackerCommand(cmd);
    }
  }

  // 2. Passive UDP Channel Sniffer (Detects traffic between the 2 target ESP32s)
  int packetSize = udp.parsePacket();
  if (packetSize > 0) {
    packetsSniffed++;
    IPAddress remoteIP = udp.remoteIP();
    int remotePort = udp.remotePort();

    // Lock onto detected communication channel
    if (!channelLocked || remoteIP != targetIP) {
      sourceIP = remoteIP;
      channelLocked = true;
    }

    char packetBuffer[2048];
    int len = udp.read(packetBuffer, 2047);
    if (len > 0) {
      packetBuffer[len] = 0;
      Serial.print("RX ");
      Serial.println(packetBuffer);

      // Brief status blink on received packet
      digitalWrite(LED_STATUS_PIN, LOW);
      delay(3);
      digitalWrite(LED_STATUS_PIN, HIGH);
    }
  }

  // 3. Non-blocking Blinking of Attack Blast LED (GPIO 4)
  if (attackLedActive) {
    unsigned long now = millis();
    if (now - lastAttackBlink >= (unsigned long)attackBlinkInterval) {
      lastAttackBlink = now;
      attackLedLevel = !attackLedLevel;
      digitalWrite(LED_ALARM_PIN, attackLedLevel ? HIGH : LOW);
    }
  } else {
    digitalWrite(LED_ALARM_PIN, LOW);
  }
}

void handleAttackerCommand(String cmd) {
  if (cmd == "PING") {
    String out = "{\"status\":\"PONG\",\"role\":\"QATTACK_EVE\",\"fw\":\"" FIRMWARE_VERSION "\"";
    out += ",\"attack_led\":" + String(attackLedActive ? "true" : "false") + "}";
    Serial.println(out);
  }
  else if (cmd == "DETECT") {
    // Return currently detected communication channel between the two target ESP32s
    String out = "{\"status\":\"OK\"";
    out += ",\"channel_detected\":" + String(channelLocked ? "true" : "false");
    out += ",\"source_ip\":\"" + sourceIP.toString() + "\"";
    out += ",\"target_ip\":\"" + targetIP.toString() + "\"";
    out += ",\"target_port\":" + String(targetPort);
    out += ",\"optical_port\":" + String(opticalPort);
    out += ",\"packets_sniffed\":" + String(packetsSniffed);
    out += ",\"link\":\"Optical Fibre via Ethernet\"}";
    Serial.println(out);
  }
  else if (cmd.startsWith("ATTACK")) {
    // Execute one of the 3 attack modes: ATTACK <FORGERY|IMPERSONATION|QUANTUM> [param]
    int spaceIdx = cmd.indexOf(' ');
    String args = (spaceIdx > 0) ? cmd.substring(spaceIdx + 1) : "";
    args.trim();

    String atkType = "QUANTUM";
    float param = 0.35;
    int subSpace = args.indexOf(' ');
    if (subSpace > 0) {
      atkType = args.substring(0, subSpace);
      param = args.substring(subSpace + 1).toFloat();
    } else if (args.length() > 0) {
      atkType = args;
    }
    atkType.toUpperCase();

    // Trigger high-intensity alarm strobe
    attackLedActive = true;
    attackBlinkInterval = 70;

    if (atkType.startsWith("FORGE") || atkType == "1") {
      forgeryAttacks++;
      // Inject forged frame via UDP
      udp.beginPacket(targetIP, targetPort);
      udp.print("{\"type\":\"TELEPORT_MESSAGE\",\"sender\":\"eve_forged\",\"mac\":\"INVALID_FORGED_WEGMAN_CARTER_MAC\",\"payload\":{\"text\":\"FORGED_ATTACK_BURST\"}}");
      udp.endPacket();
      packetsInjected++;
      Serial.println("{\"status\":\"OK\",\"attack\":\"FORGERY\",\"target_ip\":\"" + targetIP.toString() + "\",\"forgery_count\":" + String(forgeryAttacks) + "}");
    }
    else if (atkType.startsWith("IMP") || atkType == "2") {
      impersonationAttacks++;
      // Inject impersonation frame claiming Alice identity
      udp.beginPacket(targetIP, targetPort);
      udp.print("{\"type\":\"TELEPORT_MESSAGE\",\"sender\":\"Alice\",\"spoofed\":true,\"payload\":{\"sender_role\":\"Alice (Spoofed)\",\"text\":\"UNAUTHORIZED_IMPERSONATED_COMMAND\"}}");
      udp.endPacket();
      packetsInjected++;
      Serial.println("{\"status\":\"OK\",\"attack\":\"IMPERSONATION\",\"target_ip\":\"" + targetIP.toString() + "\",\"impersonation_count\":" + String(impersonationAttacks) + "}");
    }
    else {
      // Quantum Channel Manipulation
      quantumAttacks++;
      // Inject optical burst on optical port
      udp.beginPacket(targetIP, opticalPort);
      udp.print("{\"channel\":\"quantum_optical\",\"type\":\"TELEPORT_QUANTUM_BURST\",\"manipulation\":true,\"disturbance\":" + String(param, 3) + "}");
      udp.endPacket();
      packetsInjected++;
      Serial.println("{\"status\":\"OK\",\"attack\":\"QUANTUM_CHANNEL_MANIPULATION\",\"target_ip\":\"" + targetIP.toString() + "\",\"optical_port\":" + String(opticalPort) + ",\"quantum_count\":" + String(quantumAttacks) + "}");
    }

    // Auto clear alarm after 400ms in background
    delay(40);
    attackLedActive = false;
  }
  else if (cmd.startsWith("RNG")) {
    // Hardware True Random Number Generation: "RNG <bytes>"
    int numBytes = 32;
    int spaceIdx = cmd.indexOf(' ');
    if (spaceIdx > 0) {
      numBytes = cmd.substring(spaceIdx + 1).toInt();
      if (numBytes <= 0 || numBytes > 256) numBytes = 32;
    }

    String hexOut = "";
    for (int i = 0; i < numBytes; i++) {
      uint8_t r = (uint8_t)(esp_random() & 0xFF);
      char buf[3];
      sprintf(buf, "%02x", r);
      hexOut += buf;
    }
    trngBytesGenerated += numBytes;
    Serial.println("{\"status\":\"OK\",\"hex\":\"" + hexOut + "\",\"bytes\":" + String(numBytes) + "}");
  }
  else if (cmd.startsWith("ALARM ") || cmd.startsWith("ATTACK_LED ")) {
    // Control Attack LED (GPIO 4): "ALARM 1 [blink_ms]" or "ALARM 0"
    int spaceIdx = cmd.indexOf(' ');
    String arg = cmd.substring(spaceIdx + 1);
    arg.trim();

    if (arg.startsWith("1") || arg.startsWith("true") || arg.startsWith("ON")) {
      attackLedActive = true;
      int subSpace = arg.indexOf(' ');
      if (subSpace > 0) {
        int customInterval = arg.substring(subSpace + 1).toInt();
        if (customInterval >= 30 && customInterval <= 2000) {
          attackBlinkInterval = customInterval;
        }
      } else {
        attackBlinkInterval = 90;
      }
      Serial.println("{\"status\":\"OK\",\"attack_led\":\"ACTIVE\",\"pin\":4,\"blink_ms\":" + String(attackBlinkInterval) + "}");
    } else {
      attackLedActive = false;
      attackLedLevel = false;
      digitalWrite(LED_ALARM_PIN, LOW);
      Serial.println("{\"status\":\"OK\",\"attack_led\":\"CLEARED\",\"pin\":4}");
    }
  }
  else if (cmd.startsWith("TX ")) {
    // Transmit attack payload wirelessly: "TX <data>"
    String data = cmd.substring(3);
    udp.beginPacket(targetIP, targetPort);
    udp.print(data);
    udp.endPacket();
    packetsInjected++;
    Serial.println("{\"status\":\"OK\",\"tx_bytes\":" + String(data.length()) + ",\"total_injected\":" + String(packetsInjected) + "}");
  }
  else if (cmd.startsWith("SET_TARGET ")) {
    // "SET_TARGET <ip> [port] [optical_port]"
    int space1 = cmd.indexOf(' ');
    int space2 = cmd.indexOf(' ', space1 + 1);
    int space3 = (space2 > 0) ? cmd.indexOf(' ', space2 + 1) : -1;

    String ipStr = "";
    if (space2 > 0) {
      ipStr = cmd.substring(space1 + 1, space2);
      if (space3 > 0) {
        targetPort = cmd.substring(space2 + 1, space3).toInt();
        opticalPort = cmd.substring(space3 + 1).toInt();
      } else {
        targetPort = cmd.substring(space2 + 1).toInt();
      }
    } else {
      ipStr = cmd.substring(space1 + 1);
    }
    targetIP.fromString(ipStr);
    channelLocked = true;
    Serial.println("{\"status\":\"OK\",\"target_ip\":\"" + targetIP.toString() + "\",\"classical_port\":" + String(targetPort) + ",\"optical_port\":" + String(opticalPort) + "}");
  }
  else if (cmd.startsWith("SNIFF ")) {
    String arg = cmd.substring(6);
    arg.trim();
    if (arg == "1" || arg == "true" || arg == "on") {
      snifferActive = true;
      esp_wifi_set_promiscuous(true);
      esp_wifi_set_promiscuous_rx_cb(&wifiPromiscuousCallback);
      Serial.println("{\"status\":\"OK\",\"sniffer\":\"ACTIVE\"}");
    } else {
      snifferActive = false;
      esp_wifi_set_promiscuous(false);
      Serial.println("{\"status\":\"OK\",\"sniffer\":\"DISABLED\"}");
    }
  }
  else if (cmd == "STATUS") {
    String out = "{\"status\":\"ONLINE\",\"role\":\"QATTACK_EVE\",\"firmware\":\"" FIRMWARE_VERSION "\"";
    out += ",\"ip\":\"" + WiFi.localIP().toString() + "\"";
    out += ",\"source_ip\":\"" + sourceIP.toString() + "\"";
    out += ",\"target_ip\":\"" + targetIP.toString() + "\"";
    out += ",\"target_port\":" + String(targetPort);
    out += ",\"optical_port\":" + String(opticalPort);
    out += ",\"packets_injected\":" + String(packetsInjected);
    out += ",\"packets_sniffed\":" + String(packetsSniffed);
    out += ",\"forgery_attacks\":" + String(forgeryAttacks);
    out += ",\"impersonation_attacks\":" + String(impersonationAttacks);
    out += ",\"quantum_attacks\":" + String(quantumAttacks);
    out += ",\"trng_bytes\":" + String(trngBytesGenerated);
    out += ",\"alarm\":" + String(attackLedActive ? "true" : "false") + "}";
    Serial.println(out);
  }
  else {
    Serial.println("{\"status\":\"ERR\",\"msg\":\"Unknown qattack command\"}");
  }
}
