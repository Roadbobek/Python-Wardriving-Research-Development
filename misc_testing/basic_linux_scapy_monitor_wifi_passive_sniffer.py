import sys
import os
from scapy.all import *
from scapy.layers.dot11 import Dot11Beacon, Dot11, Dot11Elt


# CHECK FOR SUDO
if os.geteuid() != 0:
    print("\n[!] ERROR: This script requires root privileges to sniff raw packets.")
    print("    Please run with: sudo python script_name.py\n")
    sys.exit(1)


def packet_handler(pkt):
    # Only process Beacon frames
    if not pkt.haslayer(Dot11Beacon):
        return

    # EXTRACT BASIC INFO
    ssid = pkt[Dot11Elt].info.decode(errors="ignore")
    bssid = pkt[Dot11].addr2

    # EXTRACT BAND & FREQUENCY
    if pkt.haslayer(Dot11Beacon):
        # Extract frequency from the RadioTap layer
        # .ChannelFrequency is a standard field in the RadioTap header
        try:
            freq = pkt.ChannelFrequency
            if 2400 <= freq <= 2500:
                band = "2.4GHz"
            elif 5000 <= freq <= 5900:
                band = "5GHz"
            else:
                band = f"{freq}MHz"  # For 6GHz or unusual frequencies
        except AttributeError:
            band = "Unknown"

    # SSID FORMATTING
    if not ssid or ssid.isspace():
        display_ssid = "[HIDDEN]"
    elif ssid.strip() == "[HIDDEN]":
        display_ssid = f"SSID NAME IS ({ssid})"
    else:
        display_ssid = f"({ssid})"

    # EXTRACT SIGNAL STRENGTH (dBm)
    # This comes from the RadioTap header added by the kernel
    try:
        rssi = pkt.dBm_AntSignal
    except AttributeError:
        rssi = "N/A"

    # EXTRACT CHANNEL
    # Channel is stored in a specific IE (Information Element)
    stats = pkt[Dot11Beacon].network_stats()
    channel = stats.get("channel")

    # EXTRACT DETAILED SECURITY
    # network_stats() parses the RSN and Crypto layers for us
    crypto = stats.get("crypto")
    security = " / ".join(crypto) if crypto else "OPEN"

    # CHECK FOR WPS (Deep Packet Inspection)
    #  Check for the Vendor Specific Element (ID 221) that matches WPS
    #  00:50:f2:04 is the hex signature for Microsoft/WPS

    # Solution 1 (fastest)
    #  The 'info' field of the Beacon layer contains all the IEs
    #  This is faster than bytes(pkt) because it's a smaller search area
    has_wps = "[WPS]" if b"\x00P\xf2\x04" in pkt.getlayer(Dot11Beacon).payload.original else ""

    # Solution 2
    #  The 'bytes(pkt)' converts the whole packet to hex and looks for the WPS hex string
    # has_wps = "[WPS]" if b"\x00P\xf2\x04" in bytes(pkt) else ""

    # Solution 3
    #  has_wps = ""
    #  if pkt.haslayer(Dot11Elt):
    #      p = pkt[Dot11Elt]
    #      while isinstance(p, Dot11Elt):
    #          if p.ID == 221 and b"\x00P\xf2\x04" in p.info:
    #              has_wps = "[WPS]"
    #              break
    #          p = p.payload

    # PRINT FORMATTED OUTPUT
    print(f"CH:{str(channel):>3} | {rssi:>4}dBm | {bssid} | {security:<15} {has_wps:<5} | {band}/{freq:<8} | {display_ssid}")

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
    print(f"{'CH':<3} | {'SIG':<7} | {'BSSID':<17} | {'SECURITY':<15} {'WPS':<5} | {'BAND/FREQ':<8} | {'SSID'}")
    print("-" * 100)

    sniff(iface=iface, prn=packet_handler, store=0)


if __name__ == "__main__":
    # Change 'wlan0mon' to your monitor interface name
    target_iface = "wlan0mon"
    start_scanner(target_iface)
