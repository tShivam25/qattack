"""
Claude Code TUI aesthetic components for the QAttack Library (qattack.tui).
Provides elegant rounded borders, status badges, and terminal styling matching Claude Code.
"""

from typing import Dict, Any, Optional

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    from rich import box
    HAS_RICH = True
except ImportError:
    HAS_RICH = False


def get_console() -> Optional[Any]:
    return Console() if HAS_RICH else None


def render_claude_banner(
    target_host: str,
    target_classical_port: int,
    target_optical_port: int,
    esp_connected: bool,
    esp_port: Optional[str],
    dyn_q_th: float,
    auto_attack_enabled: bool,
    detected_channel: Optional[Any] = None,
    console: Optional[Any] = None,
):
    """Render Claude Code styled banner and status dashboard."""
    if not HAS_RICH or not console:
        print("=== QAttack (QuSec Attacker) Console ===")
        print(f"Target: {target_host} (Classical: {target_classical_port}, Optical: {target_optical_port})")
        print(f"Dynamic Q_th: {dyn_q_th*100:.2f}% | Random Attacks: {'ENABLED' if auto_attack_enabled else 'OFF'}")
        if detected_channel:
            print(f"Channel: {detected_channel}")
        return

    banner_text = Text()
    banner_text.append("⚡ QATTACK ", style="bold #FF6B6B")
    banner_text.append("· QuSec Communication Channel Attacker · Claude Code TUI\n", style="dim white")
    banner_text.append(
        "Dual-ESP32 Optical Fiber Link Detection & 3 Active Attack Vectors:\n"
        "  1. Forgery  2. Impersonation  3. Quantum Channel Manipulation\n",
        style="italic #A0AEC0",
    )

    status_table = Table(box=box.ROUNDED, show_header=False, padding=(0, 1), border_style="#4A5568")
    status_table.add_column("Key1", style="bold #E2E8F0")
    status_table.add_column("Val1", style="bold #63B3ED")
    status_table.add_column("Key2", style="bold #E2E8F0")
    status_table.add_column("Val2", style="bold #63B3ED")

    hw_badge = f"[bold green]Connected ({esp_port})[/bold green]" if esp_connected else "[dim yellow]Simulated (Software)[/dim yellow]"
    auto_badge = "[bold red]ACTIVE (In-Between Chats)[/bold red]" if auto_attack_enabled else "[dim white]DISABLED[/dim white]"

    chan_desc = "Listening for traffic..."
    if detected_channel:
        chan_desc = f"{detected_channel.peer_a_ip} ➔ {detected_channel.peer_b_ip} ({detected_channel.link_type[:24]}...)"

    status_table.add_row("Target Host:", target_host, "Attacker ESP32:", hw_badge)
    status_table.add_row("Classical UDP:", str(target_classical_port), "Dynamic Q_th:", f"{dyn_q_th*100:.2f}% (Hoeffding Proof)")
    status_table.add_row("Optical UDP:", str(target_optical_port), "Random Attacks:", auto_badge)
    status_table.add_row("Detected Link:", chan_desc, "Attack Vectors:", "[bold #FF6B6B]1.Forge 2.Impersonate 3.Quantum[/bold #FF6B6B]")

    panel = Panel(
        status_table,
        title=banner_text,
        title_align="left",
        border_style="#E06C75",
        box=box.ROUNDED,
        padding=(1, 2),
    )
    console.print(panel)
    console.print("[dim #718096]Type [bold cyan]/help[/bold cyan] for commands, [bold cyan]/detect[/bold cyan] to scan channel, or [bold cyan]/attack <1|2|3>[/bold cyan] to execute.[/dim #718096]\n")


def render_attack_card(title: str, details: Dict[str, Any], console: Optional[Any] = None):
    """Render a Claude Code styled results card for launched attacks."""
    if not HAS_RICH or not console:
        print(f"\n--- {title} ---")
        for k, v in details.items():
            print(f"  {k}: {v}")
        print("------------------\n")
        return

    table = Table(box=box.ROUNDED, show_header=False, border_style="#E06C75", padding=(0, 1))
    table.add_column("Param", style="bold #ED8936", width=28)
    table.add_column("Value", style="bold white")

    for k, v in details.items():
        table.add_row(k, str(v))

    panel = Panel(
        table,
        title=f"[bold #FF6B6B]⚡ {title}[/bold #FF6B6B]",
        subtitle="[bold red]ATTACK BLAST DISPATCHED TO COMMUNICATION CHANNEL[/bold red]",
        border_style="#E06C75",
        box=box.ROUNDED,
        padding=(0, 1),
    )
    console.print(panel)


def render_channel_card(channel_info: Dict[str, Any], console: Optional[Any] = None):
    """Render a card displaying detected communication channel between the two ESP32s."""
    if not HAS_RICH or not console:
        print("\n=== Detected Communication Channel ===")
        for k, v in channel_info.items():
            print(f"  {k}: {v}")
        print("======================================\n")
        return

    table = Table(box=box.ROUNDED, show_header=False, border_style="#38B2AC", padding=(0, 1))
    table.add_column("Property", style="bold #4FD1C5", width=26)
    table.add_column("Details", style="bold white")

    for k, v in channel_info.items():
        table.add_row(k, str(v))

    panel = Panel(
        table,
        title="[bold #38B2AC]🔍 Detected ESP32 Communication Channel[/bold #38B2AC]",
        subtitle="[bold green]CHANNEL LOCKED & READY FOR ADVERSARIAL INJECTION[/bold green]",
        border_style="#38B2AC",
        box=box.ROUNDED,
        padding=(0, 1),
    )
    console.print(panel)


def print_help(console: Optional[Any] = None):
    """Render Claude Code command palette."""
    if not HAS_RICH or not console:
        print("""
QAttack Command Palette:
  /attack <1|2|3|forgery|impersonation|quantum> [param] - Launch specific attack
  /detect                                                - Scan & detect channel between the 2 ESP32s
  /random <on|off> [min_sec] [max_sec]                  - Toggle randomized automated attacks
  /channel                                              - View detected channel parameters
  /target <ip> [classical_port] [optical_port]          - Manually configure target coordinates
  /threshold                                            - Inspect live dynamic mathematical Q_th
  /hardware                                             - Probe / reconnect Attacker ESP32 board
  /stats                                                - View attack telemetry
  /mitm <start|stop> [port]                             - Start/stop transparent packet proxy
  /clear                                                - Clear terminal screen
  /exit, /quit                                          - Exit QAttack
""")
        return

    tbl = Table(box=box.ROUNDED, border_style="#4A5568", title="[bold #63B3ED]QAttack (QuSec Attacker) Commands[/bold #63B3ED]")
    tbl.add_column("Command", style="bold #E06C75", width=36)
    tbl.add_column("Description", style="white")

    tbl.add_row("/attack 1, /attack forgery [msg]", "Attack 1: Forgery (Wegman-Carter MAC & Payload Tampering)")
    tbl.add_row("/attack 2, /attack impersonation [peer]", "Attack 2: Impersonation (Spoof Alice/Bob node identity)")
    tbl.add_row("/attack 3, /attack quantum [rate]", "Attack 3: Quantum Channel Manipulation (QBER > Q_th)")
    tbl.add_row("/detect", "Detect communication channel between the two ESP32s")
    tbl.add_row("/random on [min] [max]", "Activate random attack daemon (fires 1 of 3 attacks randomly)")
    tbl.add_row("/random off", "Deactivate random attack daemon")
    tbl.add_row("/channel", "Display currently locked channel (IPs, ports, link type)")
    tbl.add_row("/target <ip> [c_port] [opt]", "Manually set target receiver IP & port coordinates")
    tbl.add_row("/threshold", "Compute live finite-key & traffic-adapted threshold proof")
    tbl.add_row("/hardware", "Check status or reconnect Attacker ESP32 USB hardware")
    tbl.add_row("/stats", "Display cumulative attack telemetry for all 3 vectors")
    tbl.add_row("/mitm start [port]", "Start transparent hardware MITM proxy & sniffer")
    tbl.add_row("/clear", "Clear terminal screen")
    tbl.add_row("/exit, /quit", "Shut down QAttack session")

    console.print(tbl)
