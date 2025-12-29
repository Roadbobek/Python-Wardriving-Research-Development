#!/bin/bash
echo "Stopping monitor mode..."
sudo airmon-ng stop wlan0mon
sudo rfkill unblock wlan
sudo service NetworkManager start

# Add execute perm:
#   chmod +x kali_stop_mon.sh