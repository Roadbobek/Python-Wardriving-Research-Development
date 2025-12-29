#!/bin/bash
echo "Starting monitor mode..."
sudo airmon-ng check kill
sudo airmon-ng start wlan0

# Add execute perm:
#   chmod +x kali_start_mon.sh