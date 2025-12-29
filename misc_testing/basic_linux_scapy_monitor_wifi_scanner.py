import sys
import os
from scapy.all import *

# 1. CHECK FOR SUDO
if os.geteuid() != 0:
    print("\n[!] ERROR: This script requires root privileges to sniff raw packets.")
    print("    Please run with: sudo python script_name.py\n")
    sys.exit(1)


def packet_handler(pkt):
    # Only process Beacon frames
    if not pkt.haslayer(Dot11Beacon):
        return

    # 2. EXTRACT BASIC INFO
    ssid = pkt[Dot11Elt].info.decode(errors="ignore")
    bssid = pkt[Dot11].addr2

    # Logic for Hidden SSIDs
    if not ssid or ssid.isspace():
        display_ssid = "[HIDDEN]"
    elif ssid.strip() == "[HIDDEN]":
        display_ssid = f"SSID NAME IS ({ssid})"
    else:
        display_ssid = f"({ssid})"

    # 3. EXTRACT SIGNAL (dBm)
    # This comes from the RadioTap header added by the kernel
    try:
        rssi = pkt.dBm_AntSignal
    except AttributeError:
        rssi = "N/A"

    # 4. EXTRACT CHANNEL
    # Channel is stored in a specific IE (Information Element)
    stats = pkt[Dot11Beacon].network_stats()
    channel = stats.get("channel")

    # 5. EXTRACT DETAILED SECURITY
    # network_stats() parses the RSN and Crypto layers for us
    crypto = stats.get("crypto")
    security = " / ".join(crypto) if crypto else "OPEN"

    # 6. CHECK FOR WPS (Deep Packet Inspection)
    # We look for the Vendor Specific tag (Type 221) that matches WPS
    has_wps = "[WPS]" if pkt.haslayer(Dot11EltVendor) and b"\x00P\xf2\x04" in bytes(pkt) else ""

    # PRINT FORMATTED OUTPUT
    print(f"CH:{str(channel):>3} | {rssi:>4}dBm | {bssid} | {security:<15} {has_wps:<5} | {display_ssid}")


def start_scanner(iface):
    # 2. CHECK FOR MONITOR MODE
    # We check the 'type' file in sysfs for the interface
    try:
        with open(f"/sys/class/net/{iface}/type", "r") as f:
            # Type 802 is Monitor Mode (usually 803 or 801 for wireless)
            # A more reliable way is checking the 'uevent' or using 'iw'
            mode_output = subprocess.check_output(["iw", "dev", iface, "info"]).decode()
            if "type monitor" not in mode_output:
                print(f"\n[!] ERROR: Interface {iface} is NOT in Monitor Mode.")
                print(f"    Switch it using: sudo iw dev {iface} set monitor none\n")
                sys.exit(1)
    except Exception:
        print(f"[!] ERROR: Could not verify mode for {iface}.")
        sys.exit(1)

    print(f"\n[*] Sniffing on {iface}... Press Ctrl+C to stop.")
    print("-" * 100)
    print(f"{'CH':<3} | {'SIG':<7} | {'BSSID':<17} | {'SECURITY':<15} {'WPS':<5} | {'SSID'}")
    print("-" * 100)

    sniff(iface=iface, prn=packet_handler, store=0)


if __name__ == "__main__":
    # Change 'wlan0mon' to your monitor interface name
    target_iface = "wlan0mon"
    start_scanner(target_iface)