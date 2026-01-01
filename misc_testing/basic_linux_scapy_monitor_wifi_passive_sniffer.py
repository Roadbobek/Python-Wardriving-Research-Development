import os
import sys
import platform
import shutil
import logging
import threading
import subprocess
import time
from datetime import datetime
from scapy.all import *
from scapy.layers.dot11 import Dot11Beacon, Dot11, Dot11Elt


# PRE RUN CHECKS
def check_environment():
    # CHECK OS, Linux only
    if platform.system() != "Linux":
        print("[!] ERROR: This script requires a Linux-based OS (Kali, Arch, Ubuntu, etc).")
        sys.exit(1)

    # CHECK FOR ROOT, (Required for Scapy / Monitor mode)
    if os.geteuid() != 0:
        print("[!] ERROR: This script must be run as root (sudo).")
        sys.exit(1)

    # 3. CHECK FOR THE 'iw' UTILITY, (Required for the channel hopper)
    if shutil.which("iw") is None:
        print("[!] ERROR: The 'iw' tool is missing. Install it with: sudo apt install iw")
        sys.exit(1)

# RUN PRE RUN CHECKS
check_environment()


# FOLDER AND FILE SETUP
log_folder = "wardrive_results"
# Generates a unique name: wardrive_20260101_133367.txt
session_time = datetime.now().strftime("%Y%m%d_%H%M%S")
log_filename = f"wardrive_{session_time}.txt"
log_path = os.path.join(log_folder, log_filename)

# Create the folder if it doesn't exist
if not os.path.exists(log_folder):
    os.makedirs(log_folder)

# [>] Regular data flow (DEPRECATED), [*] Other information, [!] Errors

# LOGGING CONFIGURATION
logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
    handlers=[
        logging.FileHandler(log_path),
        logging.StreamHandler(sys.stdout)
    ]
)

# Level	    Rank	Purpose
# DEBUG	    10	    Super detailed "behind the scenes" info.
# INFO	    20	    Normal operation (e.g., "Found a router").
# WARNING	30	    Something weird happened, but we can keep going.
# ERROR	    40	    Something broke (e.g., "WiFi card disconnected").
# CRITICAL	50	    Total failure. The script is stopping.

# If this project expands more, I should make all [X] symbols and (Y) timestamps handled by the logging system.


# Silence the Scapy error we get when channel hopping, due to the socket getting nothing
#  Define the filter
class NoneTypeFilter(logging.Filter):
    def filter(self, record):
        # Return False if the error message contains 'NoneType'
        # This is the specific "blip" caused by channel hopping
        return "NoneType" not in record.getMessage()

# Apply it to Scapy's runtime logger
scapy_log = logging.getLogger("scapy.runtime")
scapy_log.setLevel(logging.ERROR) # Let actual errors through
scapy_log.addFilter(NoneTypeFilter()) # But block the NoneType ones

# Silence all Scapy runtime errors, bad logic
# logging.getLogger("scapy.runtime").setLevel(logging.ERROR)


# # CHECK IF RUNNING ON LINUX
# if platform.system() != "Linux":
#     print("\n[!] ERROR: This script must be ran on Linux.")
#     sys.exit(1)
#
#
# # CHECK FOR SUDO
# if os.geteuid() != 0:
#     print("\n[!] ERROR: This script requires root privileges to sniff raw packets.")
#     print("    Please run with: sudo python script_name.py\n")
#     sys.exit(1)


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

    # PACKET TIMESTAMP
    ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]

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

    # EXTRACT CHANNEL BACKUP, If channel is None, calculate it from Frequency
    if channel is None:
        try:
            freq = pkt.ChannelFrequency
            if freq == 2484:
                channel = 14
            elif 2407 <= freq <= 2477:
                channel = (freq - 2407) // 5 + 1
            elif 5000 <= freq <= 5895:
                channel = (freq - 5000) // 5
            else:
                channel = "???"
        except AttributeError:
            channel = "???"

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

    # LOG FORMATTED OUTPUT TO CLI & FILE
    # Standardized Output (Matches Header exactly)
    output = (
        f"({ts}) | "  # 13 chars
        f"{str(channel):>3} | "  # 3 chars
        f"{str(rssi):>4} dBm | "  # 8 chars total (4 + 1 space + 3)
        f"{bssid:<17} | "  # 17 chars
        f"{security[:18]:<18} "  # 18 chars
        f"{has_wps:<5} | "  # 5 chars
        f"{band[:4]:>4}/{str(freq) + 'MHz':<10} | "  # 15 chars (4 + 1 + 10)
        f"{display_ssid}"  # SSID
    )
    logging.info(output)

    # Legacy output
    # output = f"[>] ({ts}) | CH:{channel:>3} | {rssi:>4}dBm | {bssid} | {security:<12} {has_wps:<2} | {band}/{freq}{'MHz':<4} | {display_ssid}"
    # logging.info(output)

    # # PRINT FORMATTED OUTPUT, use logging.info() instead
    # print(f"[>] ({datetime.now().strftime("%H:%M:%S.%f")[:-3]}) | CH:{channel:>3} | {rssi:>4}dBm | {bssid} | {security:<12} {has_wps:<2} | {band}/{freq}{"MHz":<4} | {display_ssid}")

# Column,       Width,   Alignment,     Logic
# Time,         13,      Left (<),      Fits (HH:MM:SS.ms)
# CH,           3,       Right (>),     "Aligns ""6"" under ""157"""
# SIG,          7,       Right (>),     "Fits ""-100 dBm"""
# BSSID,        17,      Left (<),      Standard MAC length
# Security,     18,      Left (<),      Fits WPA2/PSK / AES
# WPS,          5,       Left (<),      Fits [WPS]


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

    # Get time with milliseconds
    # %f is microseconds (6 digits), so we take the first 3 for milliseconds
    # ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]

    # LOG START MESSAGE TO CLI & FILE
    logging.info(f"\n[*] ({datetime.now().strftime("%H:%M:%S.%f")[:-3]}) Sniffing on {iface}... Press Ctrl+C to stop.")
    logging.info(f"[*] Saving logs to: {log_path}")
    logging.info("-" * 112)

    # Standardized Header (Total: 112 chars)
    header = (
        f"{'TIME':<13} | {'CH':<3} | {'SIG':<8} | {'BSSID':<17} | "
        f"{'SECURITY':<18} {'WPS':<5} | {'BAND/FREQ':<15} | {'SSID'}"
    )
    logging.info(header)
    logging.info("-" * 112)

    # Legacy header
    # logging.info(
    #     f"{'CH':<6} | {'SIG':<7} | {'BSSID':<17} | {'SECURITY':<15} {'WPS':<4} | {'BAND / FREQ':<15} | {'SSID'}")
    # logging.info("-" * 106)

    # PRINT START MESSAGE, use logging.info() instead
    # print(f"\n[*] ({datetime.now().strftime("%H:%M:%S.%f")[:-3]}) Sniffing on {iface}... Press Ctrl+C to stop.")
    # print("-" * 100)
    # print(f"{'CH':<6} | {'SIG':<7} | {'BSSID':<17} | {'SECURITY':<10} {'WPS':<4} | {'BAND / FREQ':<15} | {'SSID'}")
    # print("-" * 100)

    # HANDLE KEYBOARD INTERRUPT, HANDLE SNIFFER SOCKET ERROR DURING CHANNEL HOP, HANDLE OTHER ERRORS
    try:
        while True:
            try:
                sniff(iface=iface, prn=packet_handler, store=0, timeout=1)
            except Exception as e:
                if "NoneType" not in str(e):
                    logging.error(f"[!] Sniffer error: {e}")
                time.sleep(0.05) # 50ms sleep
                continue
    except KeyboardInterrupt:
        logging.info(f"\n[*] ({datetime.now().strftime("%H:%M:%S.%f")[:-3]}) Stopping sniffer... cleaning up.")
        os._exit(0)

    # HANDLE KEYBOARD INTERRUPT, HANDLE SNIFFER SOCKET ERROR DURING CHANNEL HOP, HANDLE OTHER ERRORS, legacy logic
    # try:
    #     while True:
    #         try:
    #             sniff(iface=iface, prn=packet_handler, store=0)
    #         except Exception:
    #             # If the socket fails during a channel hop, wait 50ms and restart
    #             time.sleep(0.05)
    #             continue
    # except KeyboardInterrupt:
    #     print(f"\n[!] ({datetime.now().strftime("%H:%M:%S.%f")[:-3]}) Stopping sniffer... cleaning up.")
    #     sys.exit(0)
    #     # os._exit(0)


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
