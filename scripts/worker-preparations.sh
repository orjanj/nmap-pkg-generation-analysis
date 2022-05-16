#!/bin/bash
if [ "$EUID" -ne 0 ]; then
    echo "Error: Must be root to execute this commands."
    exit
fi

DISABLE_SERVICES=(snapd snapd.socket snapd.service snapd.seeded snapd.snap-repair.timer snapd.apparmor)

# Change hostname
# hostnamectl set-hostname


# Add network settings in /etc/netplan/00-installer-config.yaml

# Apply settings
# netplan apply

# Edit ssh config to only listen on management NIC

# Restart ssh

# Disable IPv6
#net.ipv6.conf.all.disable_ipv6=1
#net.ipv6.conf.default.disable_ipv6=1
#net.ipv6.conf.lo.disable_ipv6=1


sysctl -w net.ipv6.conf.all.disable_ipv6=1
sysctl -w net.ipv6.conf.default.disable_ipv6=1
sysctl -w net.ipv6.conf.lo.disable_ipv6=1

# Reload sysctl settings
sysctl -p

# Disable automatic updates
sudo sed -i -e 's/1/0/g' /etc/apt/apt.conf.d/20auto-upgrades

# Stop and disable services
for SERVICE in ${DISABLE_SERVICES[@]};
do
    sudo systemctl stop $SERVICE
    sudo systemctl disable $SERVICE
done

timedatectl set-ntp 0