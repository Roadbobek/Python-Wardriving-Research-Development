import subprocess


def scan_managed():
    print("--- Starting Managed Mode Scan (Active) ---")
    try:
        # We call nmcli with specific flags:
        # -t (terse/clean output)
        # -f (fields we want)
        cmd = ["nmcli", "-t", "-f", "SSID,BSSID,SIGNAL,CHAN,SECURITY", "dev", "wifi", "list"]

        # Capture the output
        result = subprocess.check_output(cmd).decode("utf-8")

        # nmcli -t uses ':' as a separator
        for line in result.strip().split("\n"):
            if line:
                fields = line.split(":")
                # Some SSIDs might have ':' in them, so we handle that logic
                # For this basic script, we'll assume standard 5-field output
                print(f"SSID: {fields[0]:<20} | MAC: {fields[1]} | Sig: {fields[2]}% | Ch: {fields[3]}")

    except Exception as e:
        print(f"Error: Make sure NetworkManager is running. {e}")


if __name__ == "__main__":
    scan_managed()