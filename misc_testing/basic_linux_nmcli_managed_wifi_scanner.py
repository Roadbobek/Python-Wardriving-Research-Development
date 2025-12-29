import subprocess


def scan_managed_fixed():
    # Adding '-e no' tells nmcli: "Don't add backslashes to the MACs"
    cmd = ["nmcli", "-t", "-e", "no", "-f", "SSID,BSSID,SIGNAL,CHAN", "dev", "wifi", "list"]

    try:
        output = subprocess.check_output(cmd).decode("utf-8")

        for line in output.strip().split("\n"):
            if not line: continue

            # rsplit(":", 3) starts from the right and only splits 3 times.
            # This protects the SSID and BSSID even if they have colons!
            # Fields will be: [SSID+BSSID, SIGNAL, CHAN, SECURITY]
            parts = line.rsplit(":", 3)

            # Now we just need to separate the SSID from the BSSID in parts[0]
            # BSSID is ALWAYS the last 17 characters (XX:XX:XX:XX:XX:XX)
            full_start = parts[0]
            bssid = full_start[-17:]
            ssid = full_start[:-18]  # Remove the BSSID and the colon before it

            signal = parts[1]
            channel = parts[2]

            print(f"SSID: {ssid if ssid else '[HIDDEN]':<20} | MAC: {bssid} | Sig: {signal}%")

    except Exception as e:
        print(f"Error: {e}")


scan_managed_fixed()















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