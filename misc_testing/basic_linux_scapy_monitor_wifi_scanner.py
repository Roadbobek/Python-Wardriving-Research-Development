from scapy.all import *

# This set keeps track of MACs we've already seen so we don't spam the screen
processed_aps = set()


def handle_packet(pkt):
    # Check if the packet is an 802.11 Beacon frame (Type 0, Subtype 8)
    if pkt.haslayer(Dot11Beacon):
        bssid = pkt[Dot11].addr2  # The MAC address of the router

        if bssid not in processed_aps:
            processed_aps.add(bssid)

            # Extract the SSID (Network Name)
            ssid = pkt[Dot11Elt].info.decode(errors="ignore")
            if not ssid:
                ssid = "[HIDDEN NETWORK]"

            # Extract Signal Strength from the Radiotap Header
            # Note: Not all Wi-Fi cards report this correctly to Scapy
            rssi = pkt.dBm_AntSignal if hasattr(pkt, 'dBm_AntSignal') else "N/A"

            print(f"New AP Found: {ssid:<20} | MAC: {bssid} | Signal: {rssi}dBm")


def start_sniffer(interface):
    print(f"--- Sniffing on {interface} (Passive) ---")
    # store=0 tells Scapy not to keep packets in RAM (prevents memory leak)
    sniff(iface=interface, prn=handle_packet, store=0)


if __name__ == "__main__":
    # Change 'wlan0mon' to your specific monitor interface name
    start_sniffer("wlan0mon")