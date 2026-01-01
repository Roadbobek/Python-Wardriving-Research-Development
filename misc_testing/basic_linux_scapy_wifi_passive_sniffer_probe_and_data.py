# Basic script to scan for probe requests and activity in data frames.

from scapy.all import *
from scapy.layers.dot11 import Dot11Beacon, Dot11, Dot11Elt, Dot11ProbeReq, RadioTap


def channel_hopper(interface, channels):
    while True:
        for channel in channels:
            subprocess.run(["iw", "dev", interface, "set", "channel", str(channel)],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            # os.system(f"iw dev {interface} set channel {channel}")
            time.sleep(0.1) # Hop every 100ms


def packet_handler(pkt):
    # Try to get Frequency from RadioTap first (Works for ALL frames)
    freq = "???"
    band = "???"
    channel = "???"

    if pkt.haslayer(RadioTap):
        try:
            freq = pkt[RadioTap].ChannelFrequency
            if 2400 <= freq <= 2500:
                band = "2.4GHz"
                # Math for 2.4GHz
                channel = 14 if freq == 2484 else (freq - 2407) // 5 + 1
            elif 5000 <= freq <= 6000:
                band = "5GHz"
                # Math for 5GHz
                channel = (freq - 5000) // 5
        except AttributeError:
            pass

    # 1. Capture Probes
    if pkt.haslayer(Dot11ProbeReq):
        client_mac = pkt.addr2
        requested_ssid = pkt.info.decode(errors="ignore") or "[Any]"
        print(f"[*] [{band}/{freq}MHz | CH: {channel}] PROBE: Client {client_mac} is looking for '{requested_ssid}'")

    # 2. Capture Data Frames (Activity)
    elif pkt.haslayer(Dot11) and pkt.type == 2:
        # Determine Client vs AP
        bssid = pkt.addr3
        client = pkt.addr1 if pkt.addr2 == bssid else pkt.addr2

        if client and client != "ff:ff:ff:ff:ff:ff":
            print(f"[*] [{band}/{freq}MHz | CH: {channel}] ACTIVE: Client {client} is talking to AP {bssid}")


# 802.11 / WiFi Channels List
essential_2p4ghz_channels = (1, 6, 11)
essential_5ghz_unii1_channels = (36, 40, 44, 48)
essential_5ghz_unii3_channels = (149, 153, 157, 161)
all_2p4ghz_channels = (1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13)
all_5ghz_channels = (36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144, 149, 153, 157, 161, 165)

# CHANNEL SETTING FOR CHANNEL HOPPER
# channels = essential_2p4ghz_channels + essential_5ghz_unii1_channels + essential_5ghz_unii3_channels # All essential 2.4GHz & 5GHz channels
channels = all_2p4ghz_channels + all_5ghz_channels # All 2.4GHz & 5GHz channels

# Change 'wlan0mon' to your monitor interface name!
target_iface = "wlan0mon"

# START CHANNEL HOPPER IN ITS OWN THREAD
hopper_thread = threading.Thread(target=channel_hopper, args=(target_iface, channels), daemon=True)
hopper_thread.start()

try:
    while True:
        try:
            sniff(iface=target_iface, prn=packet_handler, store=0, timeout=1) # START SNIFFING PACKETS
        except Exception as e:
            if "NoneType" not in str(e):
                print(f"[!] Sniffer error: {e}")
            time.sleep(0.05)  # 50ms sleep
            continue
except KeyboardInterrupt:
    print("Stopping sniffer... cleaning up.")
    os._exit(0)
