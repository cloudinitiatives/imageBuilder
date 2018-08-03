#############################################################################################################
# Script Name: rhel_sysprep.sh
# Author(s): Stephen K
# Company: Cloud Initiatives Inc.
# Description: RHEL/CentOS7 Server System Preparation for Template or Image Creation
# Date Last Modified: 8-3-2018
# Version: .03
#
#############################################################################################################

# Installallation
# 1. Build virtual hardware and select VMXNET3
# 2. "Network and Hostname" - Toggle the Network card to on, and click on "General" and check the "Automatically connect to this network when it is available".
# 3. "Software Selection" - Under "Infrastructure Server", Select "Guest Agents". (Only if using the DVD iso)
# 4. "Installation Destination" - Select the virtual disk.
# 5. "Date and Time" - Set and make sure NTP is on
# 5. "Begin Installation" - Set root password.

#!/usr/bin/env bash

# YUM Update and package installations
yum update --skip-broken -y
yum install open-vm-tools yum-utils perl vim -y
if [ -f reboot.chk ]; then
    echo "\e[93mNo reboot required.  Continuing...\e[0m"
    sleep 3
else
    echo -e "\e[93mThe system needs to reboot to boot with new kernel - please rerun the script after reboot\e[0m"
    sleep 3
    touch reboot.chk
    reboot
fi

# Stop logging services
/sbin/service rsyslog stop
# systemctl stop rsyslog.service
/sbin/service auditd stop

# Remove old kernels
/bin/package-cleanup --oldkernels --count=1 -y

# Clean yum cache
/usr/bin/yum clean all -y
/bin/rm -rf /var/cache/yum

# Force logrotate to shrink logspace and remove old logs as well as truncate logs 
/usr/sbin/logrotate -f /etc/logrotate.conf
/bin/rm -f /var/log/*-???????? /var/log/*.gz
/bin/rm -f /var/log/dmesg.old
/bin/rm -rf /var/log/anaconda

/bin/cat /dev/null > /var/log/audit/audit.log
/bin/cat /dev/null > /var/log/wtmp
/bin/cat /dev/null > /var/log/lastlog
/bin/cat /dev/null > /var/log/grubby

# Remove UDEV hardware rules
/bin/rm -f /etc/udev/rules.d/70*

# Remove UUID's from ifcfg scripts
/bin/cat /etc/sysconfig/network-scripts/ifcfg-e*
/bin/sed "/UUID/d" /etc/sysconfig/network-scripts/ifcfg-e*

# Clean tmp directories
/bin/rm -rf /tmp/*
/bin/rm -rf /var/tmp/*

# Remove SSH host keys
/bin/rm -f /etc/ssh/*key*

# Remove root users shell history and do not save current BASH session
/bin/rm -f ~root/.bash_history
unset HISTFILE

# Remove root users SSH history
/bin/rm -rf ~root/.ssh/
/bin/rm -f ~root/anaconda-ks.cfg
/bin/rm -f reboot.chk

echo ""
echo ""
echo -e "\e[93mRun the following manually as they cannot be run from within a script\e[0m"
echo ""
echo -e "# \e[34mhistory -c\e[0m"
echo -e "# \e[34msys-unconfig\e[0m"
echo ""