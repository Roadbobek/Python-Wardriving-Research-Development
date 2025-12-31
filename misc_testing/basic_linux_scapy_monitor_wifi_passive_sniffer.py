import sys
import os
import logging

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import *
from scapy.layers.dot11 import Dot11Beacon, Dot11, Dot11Elt


# CHECK FOR SUDO
if os.geteuid() != 0:
    print("\n[!] ERROR: This script requires root privileges to sniff raw packets.")
    print("    Please run with: sudo python script_name.py\n")
    sys.exit(1)


def channel_hopper(interface, channels):
    while True:
        for channel in channels:
            subprocess.run(["iw", "dev", interface, "set", "channel", str(channel)],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            # os.system(f"iw dev {interface} set channel {channel}")
            time.sleep(0.1) # Hop every 100ms


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
    print(f"CH:{channel:>3} | {rssi:>4}dBm | {bssid} | {security:<12} {has_wps:<2} | {band}/{freq}{"MHz":<4} | {display_ssid}")


def start_scanner(iface):
    # CHECK FOR MONITOR MODE
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
    print(f"{'CH':<6} | {'SIG':<7} | {'BSSID':<17} | {'SECURITY':<10} {'WPS':<4} | {'BAND / FREQ':<15} | {'SSID'}")
    print("-" * 100)

    while True:
        try:
            sniff(iface=iface, prn=packet_handler, store=0)
        except KeyboardInterrupt:
            print(print("\n[!] Stopping sniffer... cleaning up."))
            os._exit(0)
            # sys.exit(0)
        except Exception:
            # If the socket fails during a channel hop, wait 50ms and restart
            time.sleep(0.05)
            continue


if __name__ == "__main__":
    # Change 'wlan0mon' to your monitor interface name!
    target_iface = "wlan0mon"

    # 802.11 / WiFi Channels List
    essential_2p4ghz_channels = (1, 6, 11)
    essential_5ghz_unii1_channels = (36, 40, 44, 48)
    essential_5ghz_unii3_channels = (149, 153, 157, 161)
    all_2p4ghz_channels = (1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13)
    all_5ghz_channels = (36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144, 149, 153, 157, 161, 165)

    # CHANNEL SETTING FOR CHANNEL HOPPER

    # channels = essential_2p4ghz_channels + essential_5ghz_unii1_channels + essential_5ghz_unii3_channels # All essential 2.4GHz & 5GHz channels
    channels = all_2p4ghz_channels + all_5ghz_channels # All 2.4GHz & 5GHz channels

    # START CHANNEL HOPPER IN ITS OWN THREAD
    hopper_thread = threading.Thread(target=channel_hopper, args=(target_iface, channels), daemon=True)
    hopper_thread.start()

    # START THE PACKET HANDLER
    start_scanner(target_iface)

