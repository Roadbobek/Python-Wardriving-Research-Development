import subprocess
import re


def scan_managed_perfect():
    print(f"{'SSID':<20} | {'BSSID':<17} | {'SIG':<4} | {'CH':<3} | {'SECURITY'}")
    print("-" * 80)

    # We use -e no to keep MACs clean and add SECURITY to the fields
    cmd = ["nmcli", "-t", "-e", "no", "-f", "SSID,BSSID,SIGNAL,CHAN,SECURITY", "dev", "wifi", "list"]

    try:
        output = subprocess.check_output(cmd).decode("utf-8")

        for line in output.strip().split("\n"):
            if not line: continue

            # REGEX EXPLANATION:
            # ^(.*)         -> Group 1: SSID (Everything from start until the MAC)
            # :             -> A colon separator
            # ([0-9A-F:]{17}) -> Group 2: BSSID (Exactly 17 chars of Hex or Colons)
            # :             -> A colon separator
            # (\d+)         -> Group 3: Signal (Digits)
            # :             -> A colon separator
            # (\d+)         -> Group 4: Channel (Digits)
            # :             -> A colon separator
            # (.*)$         -> Group 5: Security (Everything else until the end)

            pattern = r"^(.*):([0-9A-F]{2}(?::[0-9A-F]{2}){5}):(\d+):(\d+):(.*)$"
            match = re.match(pattern, line, re.IGNORECASE)

            if match:
                ssid, bssid, signal, channel, security = match.groups()

                # If SSID is empty, it's a hidden network
                display_ssid = ssid if ssid else "[HIDDEN]"

                print(f"{display_ssid[:20]:<20} | {bssid} | {signal:>3}% | {channel:>3} | {security}")
            else:
                # If Regex fails, the line might be malformed or hidden differently
                # This handles the ':MAC:SIG:CH:SEC' case for hidden nets
                if line.startswith(':'):
                    parts = line[1:].split(':')
                    # Fallback simple parse if regex misses a weird edge case
                    print(
                        f"{'[HIDDEN]':<20} | {parts[0] + ':' + parts[1] + ':' + parts[2] + ':' + parts[3] + ':' + parts[4] + ':' + parts[5]} | {parts[6]:>3}% | ...")

    except Exception as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    scan_managed_perfect()


















# import subprocess
#
#
# def scan_managed_fixed():
#     # Adding '-e no' tells nmcli: "Don't add backslashes to the MACs"
#     cmd = ["nmcli", "-t", "-e", "no", "-f", "SSID,BSSID,SIGNAL,CHAN", "dev", "wifi", "list"]
#
#     try:
#         output = subprocess.check_output(cmd).decode("utf-8")
#
#         for line in output.strip().split("\n"):
#             if not line: continue
#
#             # rsplit(":", 3) starts from the right and only splits 3 times.
#             # This protects the SSID and BSSID even if they have colons!
#             # Fields will be: [SSID+BSSID, SIGNAL, CHAN, SECURITY]
#             parts = line.rsplit(":", 3)
#
#             # Now we just need to separate the SSID from the BSSID in parts[0].
#             # BSSID is ALWAYS the last 17 characters (XX:XX:XX:XX:XX:XX)
#             full_start = parts[0]
#
#             # If the hidden the line will start with a ':' so we check if the
#             # first character in full_start is a ':' and if it is we remove it.
#             if full_start[0] == ':':
#                 full_start = full_start[1:]
#
#             bssid = full_start[-17:]
#             ssid = full_start[:-18]  # Remove the BSSID and the colon before it
#
#             signal = parts[1]
#             channel = parts[2]
#
#             print(f"SSID: {ssid if ssid else '[HIDDEN]':<20} | MAC: {bssid} | Sig: {signal}%")
#
#     except Exception as e:
#         print(f"Error: {e}")
#
#
# scan_managed_fixed()










# import subprocess
#
#
# def scan_managed():
#     print("--- Starting Managed Mode Scan (Active) ---")
#     try:
#         # We call nmcli with specific flags:
#         # -t (terse/clean output)
#         # -f (fields we want)
#         cmd = ["nmcli", "-t", "-f", "SSID,BSSID,SIGNAL,CHAN,SECURITY", "dev", "wifi", "list"]
#
#         # Capture the output
#         result = subprocess.check_output(cmd).decode("utf-8")
#
#         # nmcli -t uses ':' as a separator
#         for line in result.strip().split("\n"):
#             if line:
#                 fields = line.split(":")
#                 # Some SSIDs might have ':' in them, so we handle that logic
#                 # For this basic script, we'll assume standard 5-field output
#                 print(f"SSID: {fields[0]:<20} | MAC: {fields[1]} | Sig: {fields[2]}% | Ch: {fields[3]}")
#
#     except Exception as e:
#         print(f"Error: Make sure NetworkManager is running. {e}")
#
#
# if __name__ == "__main__":
#     scan_managed()
