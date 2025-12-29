import subprocess
import re
import time

# Global variables
scan_num = 0

def scan_wifi():
    # Netsh command to get detailed BSSID info
    cmd = "netsh wlan show networks mode=bssid"

    global scan_num
    scan_num += 1

    print(f"{'SSID':<30} | {'BSSID':<16} | {'Signal':<10}")
    print()
    print(f" Scan {scan_num} at {time.strftime('%H:%M:%S')} | Ctrl+C to stop ".center(60, '-'))

    try:
        while True:
            # Capture the output from netsh
            raw_output = subprocess.check_output(cmd, shell=True, text=True)
            scan_num += 1

            # Extract using flexible patterns
            ssids = re.findall(r"SSID \d+ : (.*)", raw_output)
            bssids = re.findall(r"BSSID \d+\s+: (.*)", raw_output)
            signals = re.findall(r"Signal\s+: (\d+)%", raw_output)

            # # DEBUG
            # print(raw_output)
            # print()
            # print(ssids)
            # print(bssids)
            # print(signals)
            # print("-" * 60)

            # Print the results
            # We use zip to pair the SSID with its BSSID and Signal
            for ssid, bssid, signal in zip(ssids, bssids, signals):
                # .strip() removes any trailing carriage returns (\r)
                print(f"{ssid.strip():<30} | {bssid.strip():<19} | {signal}%")
            print()

            if not ssids:
                print("No networks found. Is your Wi-Fi turned on?")

            print(f" Scan {scan_num} at {time.strftime('%H:%M:%S')} | Ctrl+C to stop ".center(60, '-'))

            time.sleep(5)

    except KeyboardInterrupt:
        print("\nStopping wardriver...")
    except Exception as e:
        print(f"Error occurred: {e}")


if __name__ == "__main__":
    scan_wifi()