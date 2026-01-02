#!/usr/bin/env python3
import os
import sys
import time
import signal
import logging
import platform
import shutil
import subprocess
import multiprocessing
import queue
from datetime import datetime
from collections import Counter

# Scapy Imports
from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11ProbeReq, Dot11Elt, Dot11Deauth, Dot11AssoReq, Dot11ReassoReq, RadioTap

# ==============================================================================
# CONFIGURATION & CONSTANTS
# ==============================================================================

INTERFACE = "wlan0mon"  # Default interface
LOG_FOLDER = "wardrive_results"
SESSION_TIME = datetime.now().strftime("%Y%m%d_%H%M%S")
LOG_FILENAME = f"wardrive_{SESSION_TIME}.txt"
LOG_PATH = os.path.join(LOG_FOLDER, LOG_FILENAME)
MANUF_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "manuf")

# Channel Lists
HIGH_TRAFFIC_CHANNELS = [1, 6, 11, 36, 48, 149, 161]
ALL_2G_CHANNELS = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13]
ALL_5G_CHANNELS = [
    36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 
    132, 136, 140, 144, 149, 153, 157, 161, 165
]
ALL_CHANNELS = ALL_2G_CHANNELS + ALL_5G_CHANNELS

# Logging Configuration
logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
    handlers=[
        logging.FileHandler(LOG_PATH),
        logging.StreamHandler(sys.stdout)
    ]
)

# Silence Scapy
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# Global Event for Signal Handling
stop_event = None

# ==============================================================================
# PRE-RUN CHECKS
# ==============================================================================

def check_environment():
    """Verifies Root, Linux, and Monitor Mode."""
    if platform.system() != "Linux":
        print("[!] ERROR: This script requires a Linux-based OS.")
        sys.exit(1)

    if os.geteuid() != 0:
        print("[!] ERROR: This script must be run as root (sudo).")
        sys.exit(1)

    if shutil.which("iw") is None:
        print("[!] ERROR: The 'iw' tool is missing. Install it with: sudo apt install iw")
        sys.exit(1)

    # Check for monitor mode
    try:
        mode_output = subprocess.check_output(["iw", "dev", INTERFACE, "info"]).decode()
        if "type monitor" not in mode_output:
            print(f"[!] ERROR: Interface {INTERFACE} is NOT in Monitor Mode.")
            print(f"    Switch it using: sudo iw dev {INTERFACE} set monitor none")
            sys.exit(1)
    except subprocess.CalledProcessError:
        print(f"[!] ERROR: Interface {INTERFACE} not found.")
        sys.exit(1)

    if not os.path.exists(LOG_FOLDER):
        os.makedirs(LOG_FOLDER)

# ==============================================================================
# HELPER FUNCTIONS
# ==============================================================================

freq_to_channel_cache = {}

def get_channel_from_freq(freq):
    """Calculates channel number from frequency using math and caching."""
    if freq in freq_to_channel_cache:
        return freq_to_channel_cache[freq]

    channel = "???"
    if 2400 <= freq <= 2500:
        if freq == 2484:
            channel = 14
        else:
            # Freq = 2407 + 5n => n = (Freq - 2407) / 5
            channel = (freq - 2407) // 5
    elif 5000 <= freq <= 6000:
        # Freq = 5000 + 5n => n = (Freq - 5000) / 5
        channel = (freq - 5000) // 5
    
    freq_to_channel_cache[freq] = channel
    return channel

def load_oui_database(path):
    """Parses the Wireshark manuf file into a lookup dictionary."""
    oui_db = {}
    if not os.path.exists(path):
        print(f"[!] WARNING: OUI database not found at {path}")
        return {}
        
    try:
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                
                parts = line.split(maxsplit=2)
                if len(parts) < 2:
                    continue
                    
                oui_str = parts[0]
                # Prefer long name (3rd col) over short name (2nd col)
                name = parts[2] if len(parts) > 2 else parts[1]
                
                mask = None
                if '/' in oui_str:
                    p, m = oui_str.split('/')
                    prefix_str = p
                    mask = int(m)
                else:
                    prefix_str = oui_str
                    
                clean_hex = prefix_str.replace(':', '').replace('-', '').replace('.', '')
                try:
                    val = int(clean_hex, 16)
                except ValueError:
                    continue
                
                bits_len = len(clean_hex) * 4
                if mask is None:
                    mask = bits_len
                
                # Adjust val to match the mask
                if bits_len > mask:
                    val = val >> (bits_len - mask)
                    
                # We index by the first 6 hex chars (24 bits)
                if mask < 24:
                    continue
                    
                if len(clean_hex) < 6:
                    continue
                    
                key = clean_hex[:6].upper()
                
                if key not in oui_db:
                    oui_db[key] = []
                
                oui_db[key].append((mask, val, name))
        
        # Sort candidates by mask length descending (longest match first)
        for k in oui_db:
            oui_db[k].sort(key=lambda x: x[0], reverse=True)
            
        print(f"[*] Loaded {len(oui_db)} OUI prefixes from database.")
        return oui_db
        
    except Exception as e:
        print(f"[!] Error loading OUI database: {e}")
        return {}

# Global cache for vendors to avoid re-parsing and re-searching
vendor_cache = {}

def get_vendor(mac, oui_db=None):
    """Resolves OUI to Vendor using the provided database with caching."""
    if not mac: return "Unknown"
    
    # Check cache first
    if mac in vendor_cache:
        return vendor_cache[mac]
        
    mac_upper = mac.upper()
    result = mac_upper[:8] # Default fallback
    
    if oui_db:
        clean_mac = mac_upper.replace(":", "").replace("-", "").replace(".", "")
        if len(clean_mac) == 12:
            prefix = clean_mac[:6]
            if prefix in oui_db:
                # Check candidates
                mac_int = int(clean_mac, 16)
                for mask, val, name in oui_db[prefix]:
                    if (mac_int >> (48 - mask)) == val:
                        result = name
                        break
    
    # Cache the result
    vendor_cache[mac] = result
    return result

def get_security_mode(pkt):
    """
    Parses Scapy's crypto set into a precise security mode string.
    Uses Scapy's built-in network_stats() for robust parsing.
    """
    try:
        stats = pkt[Dot11Beacon].network_stats()
        crypto = stats.get("crypto")
        
        if not crypto:
            return "OPEN"
            
        # Join the set into a string like "WPA2/PSK" or "WPA2/SAE"
        # Scapy returns a set of strings, e.g., {'WPA2', 'PSK'}
        # We want to format this nicely.
        
        # Common combinations mapping
        if "WPA2" in crypto and "PSK" in crypto and "SAE" in crypto:
             return "WPA2/WPA3 Mixed"
        if "WPA2" in crypto and "SAE" in crypto:
            return "WPA3-SAE"
        if "WPA2" in crypto and "PSK" in crypto:
            return "WPA2-PSK"
        if "WPA2" in crypto and "EAP" in crypto:
            return "WPA2-Enterprise"
        if "WPA" in crypto and "PSK" in crypto:
            return "WPA-PSK"
        if "WPA" in crypto and "EAP" in crypto:
            return "WPA-Enterprise"
        if "WEP" in crypto:
            return "WEP"
        if "OWE" in crypto:
            return "WPA3-OWE"
            
        # Fallback: join all detected tags to ensure we never return "UNKNOWN" if data exists
        return "/".join(sorted(crypto))
        
    except Exception:
        return "UNKNOWN"

# ==============================================================================
# PROCESS A: CATCHER
# ==============================================================================

def catcher(packet_queue, interface, stop_event):
    """Captures packets and pushes them to the queue."""
    # Filter: Management frames (Beacons, Probes, Assoc, Deauth) or Data frames
    # type 0 = mgt, type 2 = data
    bpf_filter = "type mgt or type data"
    
    def handler(pkt):
        try:
            # Use non-blocking put to avoid hanging if queue is full
            packet_queue.put(bytes(pkt), block=False) 
        except queue.Full:
            pass # Drop packet if queue is full to prevent RAM explosion
        except Exception:
            pass

    # Loop ensures sniffer restarts if the interface resets or driver crashes
    while not stop_event.is_set():
        try:
            # Timeout allows the loop to check stop_event periodically
            sniff(iface=interface, prn=handler, store=0, filter=bpf_filter, timeout=2)
        except Exception as e:
            # If interface goes down momentarily, wait a bit before retrying
            time.sleep(1)

# ==============================================================================
# PROCESS B: PROCESSOR
# ==============================================================================

def processor(packet_queue, stop_event, stats_queue):
    """Processes packets from the queue, parses them, and logs results."""
    
    # Load OUI Database
    oui_db = load_oui_database(MANUF_FILE)
    
    # seen_devices structure:
    # { "KEY": {"last_seen": timestamp, "rssi": int} }
    seen_devices = {}
    
    # Statistics Aggregation
    # We store data per-device to ensure exact counts (not packet counts)
    stats = {
        "ap_data": {},      # BSSID -> {security, band, vendor, ssid, wps, portal}
        "client_data": {},  # MAC -> {vendor, probes}
        "activity": {},     # MAC -> {packets, last_time}
        "start_time": time.time()
    }
    
    # Print Header
    header = (
        f"{'TIME':<12} | {'TYPE':<6} | {'CH':<3} | {'RSSI':<4} | "
        f"{'BSSID / SOURCE':<17} | {'SSID / INFO':<30} | {'SECURITY / EXTRA'}"
    )
    logging.info("-" * 120)
    logging.info(header)
    logging.info("-" * 120)

    while not stop_event.is_set():
        try:
            # Non-blocking get with timeout to allow checking stop_event
            raw_pkt = packet_queue.get(timeout=0.5)
        except multiprocessing.queues.Empty: 
            continue
        except queue.Empty: 
            continue

        try:
            # Reconstruct packet from bytes (CPU intensive but keeps Catcher fast)
            pkt = RadioTap(raw_pkt)
        except Exception:
            continue

        # 1. Extract RadioTap Metadata
        try:
            freq = pkt.ChannelFrequency
            rssi = pkt.dBm_AntSignal
        except AttributeError:
            continue

        channel = get_channel_from_freq(freq)
        ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        
        # Determine Band
        band = "Unknown"
        if 2400 <= freq <= 2500:
            band = "2.4GHz"
        elif 5000 <= freq <= 6000:
            band = "5GHz"
        
        # Ensure Dot11 layer exists
        if not pkt.haslayer(Dot11):
            continue
            
        dot11 = pkt[Dot11]
        type_val = dot11.type
        
        # 2. Packet Logic Handlers
        
        # --- BEACONS ---
        if pkt.haslayer(Dot11Beacon):
            bssid = dot11.addr2
            ssid = pkt[Dot11Elt].info.decode(errors="ignore") if pkt.haslayer(Dot11Elt) else ""
            
            # Improved Hidden SSID Detection (Check for empty string OR null bytes)
            if not ssid or ssid.strip() == "" or ssid.replace("\x00", "") == "":
                ssid = "[HIDDEN]"
            
            # Security Parsing (Exact)
            # Use the robust Scapy network_stats() method directly on the packet
            security_mode = get_security_mode(pkt)
            
            # WPS Detection
            # Check for the Vendor Specific Element (ID 221) that matches WPS
            # 00:50:f2:04 is the hex signature for Microsoft/WPS
            # FASTEST METHOD: Search raw bytes directly to avoid object overhead
            has_wps = False
            if b"\x00P\xf2\x04" in raw_pkt:
                has_wps = True
            
            # Captive Portal Heuristic (WISPr)
            has_portal = False
            if b"WISPr" in raw_pkt:
                has_portal = True
            
            # Update AP Stats (Overwrites existing to keep latest info)
            vendor = get_vendor(bssid, oui_db)
            stats["ap_data"][bssid] = {
                "ssid": ssid,
                "security": security_mode,
                "band": band,
                "vendor": vendor,
                "wps": has_wps,
                "portal": has_portal
            }
            
            extra = f"{security_mode}"
            if has_wps: extra += " [WPS]"
            if has_portal: extra += " [PORTAL]"
            
            # Log Logic
            key = f"BEACON_{bssid}"
            should_log = False
            
            if key not in seen_devices:
                should_log = True
            else:
                last_data = seen_devices[key]
                time_diff = time.time() - last_data["last_seen"]
                rssi_diff = abs(rssi - last_data["rssi"])
                
                if time_diff > 60 or rssi_diff > 5:
                    should_log = True
            
            if should_log:
                seen_devices[key] = {"last_seen": time.time(), "rssi": rssi}
                # Add vendor to the log output
                logging.info(f"{ts:<12} | {'BEACON':<6} | {str(channel):<3} | {rssi:<4} | {bssid:<17} | {ssid:<30} | {extra} | {vendor}")

        # --- PROBES ---
        elif pkt.haslayer(Dot11ProbeReq):
            client_mac = dot11.addr2
            
            # Update Client Stats
            vendor = get_vendor(client_mac, oui_db)
            if client_mac not in stats["client_data"]:
                stats["client_data"][client_mac] = {"vendor": vendor, "probes": set()}
            
            requested_ssid = ""
            if pkt.haslayer(Dot11Elt):
                try:
                    requested_ssid = pkt[Dot11Elt].info.decode(errors="ignore")
                except AttributeError:
                    pass
            
            if not requested_ssid:
                requested_ssid = "[BROADCAST]"
            else:
                stats["client_data"][client_mac]["probes"].add(requested_ssid)
            
            key = f"PROBE_{client_mac}_{requested_ssid}"
            
            should_log = False
            if key not in seen_devices:
                should_log = True
            else:
                if time.time() - seen_devices[key]["last_seen"] > 60:
                    should_log = True
            
            if should_log:
                seen_devices[key] = {"last_seen": time.time(), "rssi": rssi}
                logging.info(f"{ts:<12} | {'PROBE':<6} | {str(channel):<3} | {rssi:<4} | {client_mac:<17} | {requested_ssid:<30} | Searching | {vendor}")

        # --- ASSOCIATION REQUESTS ---
        elif pkt.haslayer(Dot11AssoReq) or pkt.haslayer(Dot11ReassoReq):
            client_mac = dot11.addr2
            bssid = dot11.addr1 # AP being associated with
            
            vendor = get_vendor(client_mac, oui_db)
            if client_mac not in stats["client_data"]:
                stats["client_data"][client_mac] = {"vendor": vendor, "probes": set()}
            
            subtype = "ASSOC" if pkt.haslayer(Dot11AssoReq) else "REASSOC"
            
            key = f"{subtype}_{client_mac}_{bssid}"
            
            should_log = False
            if key not in seen_devices:
                should_log = True
            else:
                if time.time() - seen_devices[key]["last_seen"] > 60:
                    should_log = True
                    
            if should_log:
                seen_devices[key] = {"last_seen": time.time(), "rssi": rssi}
                logging.info(f"{ts:<12} | {subtype:<6} | {str(channel):<3} | {rssi:<4} | {client_mac:<17} | To: {bssid:<30} | Joining Network | {vendor}")

        # --- DEAUTHENTICATION ---
        elif pkt.haslayer(Dot11Deauth):
            target_mac = dot11.addr1
            ap_mac = dot11.addr2
            reason = pkt[Dot11Deauth].reason
            
            key = f"DEAUTH_{target_mac}_{ap_mac}"
            
            should_log = False
            if key not in seen_devices:
                should_log = True
            else:
                if time.time() - seen_devices[key]["last_seen"] > 5:
                    should_log = True
            
            if should_log:
                seen_devices[key] = {"last_seen": time.time(), "rssi": rssi}
                logging.info(f"{ts:<12} | {'DEAUTH':<6} | {str(channel):<3} | {rssi:<4} | {target_mac:<17} | From: {ap_mac:<30} | Reason: {reason}")

        # --- DATA FRAMES ---
        elif type_val == 2: # Data
            # Use Scapy flags for readability
            to_ds = dot11.FCfield & 0x1 != 0
            from_ds = dot11.FCfield & 0x2 != 0
            
            client = None
            ap = None
            
            if to_ds and not from_ds:
                ap = dot11.addr1
                client = dot11.addr2
            elif not to_ds and from_ds:
                client = dot11.addr1
                ap = dot11.addr2
            
            if client and ap and client != "ff:ff:ff:ff:ff:ff":
                # Activity Tracking
                if client not in stats["activity"]:
                    stats["activity"][client] = {"packets": 0, "last_time": time.time()}
                stats["activity"][client]["packets"] += 1
                stats["activity"][client]["last_time"] = time.time()
                
                # Ensure client is in client_data even if we didn't see a probe
                vendor = get_vendor(client, oui_db)
                if client not in stats["client_data"]:
                    stats["client_data"][client] = {"vendor": vendor, "probes": set()}

                key = f"DATA_{client}_{ap}"
                
                should_log = False
                if key not in seen_devices:
                    should_log = True
                else:
                    if time.time() - seen_devices[key]["last_seen"] > 60:
                        should_log = True
                
                if should_log:
                    seen_devices[key] = {"last_seen": time.time(), "rssi": rssi}
                    logging.info(f"{ts:<12} | {'DATA':<6} | {str(channel):<3} | {rssi:<4} | {client:<17} | AP: {ap:<30} | Activity | {vendor}")

    # End of loop, send stats back
    stats_queue.put(stats)

# ==============================================================================
# OPTIMIZED CHANNEL HOPPER
# ==============================================================================

def channel_hopper(interface, stop_event):
    """Hops channels with dwell time optimization."""
    while not stop_event.is_set():
        for channel in ALL_CHANNELS:
            if stop_event.is_set():
                break
            
            # Dwell Time Logic
            if channel in HIGH_TRAFFIC_CHANNELS:
                dwell = 0.25  # 250ms
            else:
                dwell = 0.05  # 50ms
            
            try:
                # Using subprocess.run is cleaner and prevents zombie processes
                subprocess.run(
                    ["iw", "dev", interface, "set", "channel", str(channel)],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )
            except Exception:
                pass
            
            time.sleep(dwell)

# ==============================================================================
# MAIN EXECUTION
# ==============================================================================

def signal_handler(sig, frame):
    print(f"\n[*] Signal received. Saving data and exiting...")
    if stop_event:
        stop_event.set()

def print_summary(stats):
    """Prints a detailed summary of the session."""
    if not stats:
        print("\n[!] No statistics available.")
        return

    duration = time.time() - stats["start_time"]
    hours, remainder = divmod(duration, 3600)
    minutes, seconds = divmod(remainder, 60)
    
    ap_data = stats.get("ap_data", {})
    client_data = stats.get("client_data", {})
    activity = stats.get("activity", {})
    
    print("\n" + "="*60)
    print(f"AIR-VANTAGE SESSION SUMMARY")
    print("="*60)
    
    # 1. Totals
    print(f"\n[+] SESSION DURATION: {int(hours)}h {int(minutes)}m {int(seconds)}s")
    print(f"[+] UNIQUE APs FOUND: {len(ap_data)}")
    print(f"[+] UNIQUE CLIENTS:   {len(client_data)}")
    
    # 2. Security Breakdown (Exact)
    print(f"\n[+] SECURITY BREAKDOWN (Networks):")
    encryption_counts = Counter(ap['security'] for ap in ap_data.values())
    total_aps = len(ap_data)
    
    if total_aps > 0:
        for enc, count in encryption_counts.most_common():
            print(f"    - {enc:<18}: {count} ({count/total_aps*100:.1f}%)")
    else:
        print("    - No AP data.")
        
    # Vulnerabilities
    wps_count = sum(1 for ap in ap_data.values() if ap['wps'])
    portal_count = sum(1 for ap in ap_data.values() if ap['portal'])
    print(f"    - WPS ENABLED:      {wps_count}")
    print(f"    - CAPTIVE PORTALS:  {portal_count}")

    # 3. Hardware / Vendors
    print(f"\n[+] TOP 5 VENDORS (APs):")
    vendor_counts = Counter(ap['vendor'] for ap in ap_data.values())
    if vendor_counts:
        for vendor, count in vendor_counts.most_common(5):
            print(f"    - {vendor:<10}: {count}")
    else:
        print("    - No data.")

    # 4. Frequency Distribution
    print(f"\n[+] BAND DISTRIBUTION (Networks):")
    band_counts = Counter(ap['band'] for ap in ap_data.values())
    if total_aps > 0:
        for band, count in band_counts.items():
            print(f"    - {band:<10}: {count} ({count/total_aps*100:.1f}%)")
    else:
        print("    - No data.")

    # 5. Activity / Top Talkers
    print(f"\n[+] TOP TALKERS (Activity):")
    if activity:
        # Sort by packet count
        sorted_talkers = sorted(activity.items(), key=lambda item: item[1]['packets'], reverse=True)[:5]
        for mac, data in sorted_talkers:
            print(f"    - {mac}: {data['packets']} packets")
    else:
        print("    - No data.")
        
    print("\n" + "="*60)
    print(f"[*] Log saved to: {LOG_PATH}")
    print("="*60 + "\n")

if __name__ == "__main__":
    # 1. Pre-run Checks
    check_environment()
    
    # 2. Setup Signal Handling
    stop_event = multiprocessing.Event()
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    print(f"[*] Starting Air-Vantage Super-Sniffer on {INTERFACE}")
    print(f"[*] Logs: {LOG_PATH}")
    
    # 3. Initialize Queue and Processes
    # Limit queue size to prevent RAM exhaustion in high-traffic areas
    packet_queue = multiprocessing.Queue(maxsize=5000)
    stats_queue = multiprocessing.Queue()
    
    # Process A: Catcher (Now includes stop_event)
    p_catcher = multiprocessing.Process(target=catcher, args=(packet_queue, INTERFACE, stop_event))
    
    # Process B: Processor
    p_processor = multiprocessing.Process(target=processor, args=(packet_queue, stop_event, stats_queue))
    
    # Channel Hopper
    p_hopper = multiprocessing.Process(target=channel_hopper, args=(INTERFACE, stop_event))
    
    # 4. Start Engines
    p_catcher.start()
    p_processor.start()
    p_hopper.start()
    
    # 5. Monitor Loop
    try:
        while not stop_event.is_set():
            time.sleep(1)
            # Check if processes are alive
            if not p_catcher.is_alive():
                print("[!] Catcher process died unexpectedly.")
                stop_event.set()
            if not p_processor.is_alive():
                print("[!] Processor process died unexpectedly.")
                stop_event.set()
    except KeyboardInterrupt:
        stop_event.set()
    
    # 6. Cleanup
    print("[*] Stopping processes...")
    p_hopper.terminate()
    p_catcher.terminate()
    
    # Wait for processor to finish and send stats
    p_processor.join(timeout=5)
    if p_processor.is_alive():
        p_processor.terminate()
    
    # Retrieve stats
    final_stats = None
    if not stats_queue.empty():
        final_stats = stats_queue.get()
    
    if final_stats:
        print_summary(final_stats)
    else:
        print("[!] Could not retrieve session statistics.")
    
    print("[*] Done.")
