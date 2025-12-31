import os
import sys
import logging
import threading
import subprocess
import time
from datetime import datetime
from scapy.all import *
from scapy.layers.dot11 import Dot11Beacon, Dot11, Dot11Elt

# --- FOLDER AND FILE SETUP ---
log_folder = "wardrive_results"
# Generates a unique name: wardrive_20231027_143005.txt
session_time = datetime.now().strftime("%Y%m%d_%H%M%S")
log_filename = f"wardrive_{session_time}.txt"
log_path = os.path.join(log_folder, log_filename)

# Create the folder if it doesn't exist
if not os.path.exists(log_folder):
    os.makedirs(log_folder)

# --- LOGGING CONFIGURATION ---
logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
    handlers=[
        logging.FileHandler(log_path),
        logging.StreamHandler(sys.stdout)
    ]
)


# --- SCAPY ERROR FILTERING ---
class NoneTypeFilter(logging.Filter):
    def filter(self, record):
        return "NoneType" not in record.getMessage()


scapy_log = logging.getLogger("scapy.runtime")
scapy_log.setLevel(logging.ERROR)
scapy_log.addFilter(NoneTypeFilter())

# CHECK FOR SUDO
if os.geteuid() != 0:
    print("\n[!] ERROR: This script requires root privileges.")
    sys.exit(1)


def channel_hopper(interface, channels):
    while True:
        for channel in channels:
            subprocess.run(["iw", "dev", interface, "set", "channel", str(channel)],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(0.1)


def packet_handler(pkt):
    if not pkt.haslayer(Dot11Beacon):
        return

    # EXTRACT INFO
    ssid = pkt[Dot11Elt].info.decode(errors="ignore")
    bssid = pkt[Dot11].addr2

    try:
        freq = pkt.ChannelFrequency
        band = "2.4GHz" if 2400 <= freq <= 2500 else "5GHz" if 5000 <= freq <= 5900 else f"{freq}MHz"
    except AttributeError:
        band, freq = "Unknown", "???"

    display_ssid = "[HIDDEN]" if not ssid or ssid.isspace() else f"({ssid})"

    try:
        rssi = pkt.dBm_AntSignal
    except AttributeError:
        rssi = "N/A"

    stats = pkt[Dot11Beacon].network_stats()
    channel = stats.get("channel")
    crypto = stats.get("crypto")
    security = " / ".join(crypto) if crypto else "OPEN"
    has_wps = "[WPS]" if b"\x00P\xf2\x04" in pkt.getlayer(Dot11Beacon).payload.original else ""

    # TIMESTAMP
    ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]

    # LOGGING
    output = f"[>] ({ts}) | CH:{channel:>3} | {rssi:>4}dBm | {bssid} | {security:<12} {has_wps:<2} | {band}/{freq}{'MHz':<4} | {display_ssid}"
    logging.info(output)


def start_scanner(iface):
    try:
        mode_output = subprocess.check_output(["iw", "dev", iface, "info"]).decode()
        if "type monitor" not in mode_output:
            logging.info(f"\n[!] ERROR: Interface {iface} is NOT in Monitor Mode.")
            sys.exit(1)
    except Exception:
        logging.info(f"[!] ERROR: Could not verify mode for {iface}.")
        sys.exit(1)

    ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
    logging.info(f"\n[*] ({ts}) Sniffing on {iface}... Press Ctrl+C to stop.")
    logging.info(f"[*] Saving logs to: {log_path}")
    logging.info("-" * 110)
    logging.info(
        f"{'CH':<6} | {'SIG':<7} | {'BSSID':<17} | {'SECURITY':<15} {'WPS':<4} | {'BAND / FREQ':<15} | {'SSID'}")
    logging.info("-" * 110)

    try:
        while True:
            try:
                sniff(iface=iface, prn=packet_handler, store=0, timeout=1)
            except Exception as e:
                if "NoneType" not in str(e):
                    logging.error(f"[*] Sniffer glitch: {e}")
                time.sleep(0.05)
                continue
    except KeyboardInterrupt:
        ts_exit = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        logging.info(f"\n[!] ({ts_exit}) Stopping sniffer... cleaning up.")
        os._exit(0)


if __name__ == "__main__":
    target_iface = "wlan0mon"

    essential_2p4ghz_channels = (1, 6, 11)
    essential_5ghz_unii1_channels = (36, 40, 44, 48)
    essential_5ghz_unii3_channels = (149, 153, 157, 161)
    all_2p4ghz_channels = (1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13)
    all_5ghz_channels = (36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144, 149, 153, 157, 161, 165)

    channels = all_2p4ghz_channels + all_5ghz_channels

    hopper_thread = threading.Thread(target=channel_hopper, args=(target_iface, channels), daemon=True)
    hopper_thread.start()

    start_scanner(target_iface)