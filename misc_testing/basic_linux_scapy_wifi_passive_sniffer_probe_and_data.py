# Basic script to scan for probe requests and activity in data frames.

from scapy.all import *
from scapy.layers.dot11 import Dot11Beacon, Dot11, Dot11Elt, Dot11ProbeReq


def channel_hopper(interface, channels):
    while True:
        for channel in channels:
            subprocess.run(["iw", "dev", interface, "set", "channel", str(channel)],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            # os.system(f"iw dev {interface} set channel {channel}")
            time.sleep(0.1) # Hop every 100ms


def packet_handler(pkt):
    # 1. Capture Probes (For example, a phones looking for Wi-Fi)
    if pkt.haslayer(Dot11ProbeReq):
        client_mac = pkt.addr2
        requested_ssid = pkt.info.decode(errors="ignore") or "[Any]"

        # EXTRACT BAND & FREQUENCY
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
            band = "???"

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

        print(f"[*] [{band}/{freq}MHz | CH: {channel}] PROBE: Client {client_mac} is looking for '{requested_ssid}'")

    # 2. Capture Client-to-AP Activity (Actual traffic)
    elif pkt.haslayer(Dot11) and pkt.type == 2: # Type 2 is Data
        # addr1 = Receiver, addr2 = Transmitter, addr3 = BSSID
        # We look for packets where addr1 or addr2 is a client
        client = pkt.addr1 if pkt.addr2 == pkt.addr3 else pkt.addr2
        ap = pkt.addr3

        # EXTRACT BAND & FREQUENCY
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
            band = "???"

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

        if client != "ff:ff:ff:ff:ff:ff": # Ignore broadcasts
            print(f"[*] [{band}/{freq}MHz | CH: {channel}] ACTIVE: Client {client} is talking to AP {ap}")


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
