#!/bin/bash

# Boot Safety Checker for Ubuntu Jammy (ideally)
##
# This script performs a comprehensive check of boot-critical components
# Run as root: sudo bash boot_checker.sh
##

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}This script must be run as root${NC}" 
   exit 1
fi

echo -e "${YELLOW}=== Ubuntu Jammy Boot Safety Checker ===${NC}"
echo "Running comprehensive boot checks..."

# Function to check status and print result
check_status() {
    if [ $1 -eq 0 ]; then
        echo -e "  [${GREEN}PASS${NC}] $2"
        return 0
    else
        echo -e "  [${RED}FAIL${NC}] $2 - $3"
        return 1
    fi
}

OVERALL_STATUS=0

# === Kernel checks ===
echo -e "\n${YELLOW}Checking kernel configuration:${NC}"

# Check current kernel
CURRENT_KERNEL=$(uname -r)
echo "  Current kernel: $CURRENT_KERNEL"

# Check if kernel exists in /boot
if [ -f "/boot/vmlinuz-$CURRENT_KERNEL" ]; then
    check_status 0 "Kernel image exists in /boot"
else
    check_status 1 "Kernel image missing" "Kernel file not found at /boot/vmlinuz-$CURRENT_KERNEL"
    OVERALL_STATUS=1
fi

# Check initrd exists
if [ -f "/boot/initrd.img-$CURRENT_KERNEL" ]; then
    check_status 0 "Initrd image exists"
else
    check_status 1 "Initrd image missing" "File not found at /boot/initrd.img-$CURRENT_KERNEL"
    OVERALL_STATUS=1
fi

# Check if kernel modules are available
if [ -d "/lib/modules/$CURRENT_KERNEL" ]; then
    check_status 0 "Kernel modules directory exists"
else
    check_status 1 "Kernel modules missing" "Directory not found at /lib/modules/$CURRENT_KERNEL"
    OVERALL_STATUS=1
fi

# === GRUB configuration ===
echo -e "\n${YELLOW}Checking boot configuration:${NC}"

# Check if GRUB is installed
if which grub-install >/dev/null; then
    check_status 0 "GRUB is installed"
    
    # Check grub configuration
    if [ -f "/boot/grub/grub.cfg" ]; then
        check_status 0 "GRUB configuration exists"
        
        # Check if current kernel is in GRUB config
        if grep -q "$CURRENT_KERNEL" /boot/grub/grub.cfg; then
            check_status 0 "Current kernel found in GRUB configuration"
        else
            check_status 1 "Current kernel not in GRUB config" "Run 'sudo update-grub'"
            OVERALL_STATUS=1
        fi
    else
        check_status 1 "GRUB configuration missing" "Run 'sudo update-grub'"
        OVERALL_STATUS=1
    fi
else
    check_status 1 "GRUB not installed" "Boot loader configuration could not be verified"
    OVERALL_STATUS=1
fi

# === Critical drivers check ===
echo -e "\n${YELLOW}Checking critical drivers:${NC}"

# Get root filesystem type and check if it's functioning
ROOT_FS=$(mount | grep " / " | awk '{print $5}')
# Instead of checking the module, check if we can access the filesystem
if [ -r "/etc/fstab" ] && [ -r "/etc/passwd" ]; then
    check_status 0 "Root filesystem ($ROOT_FS) is functioning properly"
else
    check_status 1 "Root filesystem issue" "Cannot read critical files on root filesystem"
    OVERALL_STATUS=1
fi

# Check disk drivers by verifying devices can be accessed
echo "  Checking disk devices..."
DISK_ISSUES=0
for disk in $(lsblk -ndo name | grep -E '^sd|^nvme|^vd'); do
    if [ -b "/dev/$disk" ] && dd if=/dev/$disk of=/dev/null bs=512 count=1 &>/dev/null; then
        echo -e "    [${GREEN}OK${NC}] Disk /dev/$disk is accessible"
    else
        echo -e "    [${RED}FAIL${NC}] Disk /dev/$disk cannot be accessed"
        DISK_ISSUES=1
    fi
done

if [ $DISK_ISSUES -eq 0 ]; then
    check_status 0 "Disk devices check passed"
else
    check_status 1 "Disk devices issue" "One or more disks cannot be accessed"
    OVERALL_STATUS=1
fi

# Check network drivers for primary interface
PRIMARY_IF=$(ip route | grep default | head -1 | awk '{print $5}')
if [ -n "$PRIMARY_IF" ]; then
    if ip link show $PRIMARY_IF | grep -q "state UP"; then
        DRIVER=$(ethtool -i $PRIMARY_IF 2>/dev/null | grep driver | cut -d: -f2 | tr -d ' ')
        if [ -n "$DRIVER" ]; then
            DRIVER_INFO=" ($DRIVER)"
        else
            DRIVER_INFO=""
        fi
        check_status 0 "Network interface $PRIMARY_IF${DRIVER_INFO} is UP"
    else
        check_status 1 "Network interface issue" "$PRIMARY_IF is not in UP state"
    fi
else
    echo "  [INFO] No primary network interface with default route found"
fi

# === System services check ===
echo -e "\n${YELLOW}Checking critical system services:${NC}"

# List of critical services - removed NetworkManager as it might not be used in all setups
CRITICAL_SERVICES=("systemd-journald" "systemd-udevd" "systemd-logind" "polkit")

for service in "${CRITICAL_SERVICES[@]}"; do
    if systemctl is-active --quiet $service; then
        check_status 0 "$service is running"
    else
        check_status 1 "$service not running" "Critical system service issue"
        OVERALL_STATUS=1
    fi
done

# Check if any networking service is running (not just NetworkManager)
if systemctl is-active --quiet NetworkManager || systemctl is-active --quiet networking || systemctl is-active --quiet systemd-networkd || ip link show | grep -q "state UP"; then
    check_status 0 "Network service or interface is active"
else
    check_status 1 "Network service issue" "No active network service detected"
    OVERALL_STATUS=1
fi

# Check systemd boot targets
if systemctl list-dependencies graphical.target &>/dev/null; then
    check_status 0 "Systemd graphical target is properly configured"
else
    check_status 1 "Systemd target issue" "Graphical target has dependency issues"
    OVERALL_STATUS=1
fi

# === Disk health check ===
echo -e "\n${YELLOW}Checking disk health:${NC}"

# Check disk space on boot partition
BOOT_USAGE=$(df -h /boot | tail -1 | awk '{print $5}' | tr -d '%')
if [ "$BOOT_USAGE" -lt 90 ]; then
    check_status 0 "Boot partition has sufficient space (${BOOT_USAGE}% used)"
else
    check_status 1 "Boot partition low on space" "${BOOT_USAGE}% used - clean old kernels"
    OVERALL_STATUS=1
fi

# Check disk space on root partition
ROOT_USAGE=$(df -h / | tail -1 | awk '{print $5}' | tr -d '%')
if [ "$ROOT_USAGE" -lt 90 ]; then
    check_status 0 "Root partition has sufficient space (${ROOT_USAGE}% used)"
else
    check_status 1 "Root partition low on space" "${ROOT_USAGE}% used - clean system"
    OVERALL_STATUS=1
fi

# Check for disk errors in journal
if journalctl -p err -b | grep -i "I/O error" > /dev/null; then
    check_status 1 "Disk I/O errors found" "Check 'journalctl -p err -b | grep -i I/O'"
    OVERALL_STATUS=1
else
    check_status 0 "No disk I/O errors in system journal"
fi

# === Update related checks ===
echo -e "\n${YELLOW}Checking update status:${NC}"

# Check if there are held packages
if apt-mark showhold | grep -q .; then
    HELD_PKGS=$(apt-mark showhold | wc -l)
    check_status 1 "Held packages found" "$HELD_PKGS packages are on hold"
    echo "  Held packages: $(apt-mark showhold)"
else
    check_status 0 "No held packages found"
fi

# Check for broken packages
if apt-get check 2>&1 | grep -q "broken packages"; then
    check_status 1 "Broken packages detected" "Run 'sudo apt --fix-broken install'"
    OVERALL_STATUS=1
else
    check_status 0 "No broken packages detected"
fi

# Check if reboot is required
if [ -f /var/run/reboot-required ]; then
    check_status 1 "System reboot required" "Updates have been installed that require a reboot"
else
    check_status 0 "No pending updates requiring reboot"
fi

# === Secure Boot Status (if applicable) ===
echo -e "\n${YELLOW}Checking Secure Boot status:${NC}"
if [ -d /sys/firmware/efi ]; then
    if mokutil --sb-state &>/dev/null; then
        SB_STATUS=$(mokutil --sb-state)
        echo "  Secure Boot is $SB_STATUS"
    else
        echo "  [INFO] Could not determine Secure Boot state"
    fi
else
    echo "  [INFO] System not booted in EFI mode, Secure Boot not applicable"
fi

# === Final Assessment ===
echo -e "\n${YELLOW}Boot safety assessment:${NC}"
if [ $OVERALL_STATUS -eq 0 ]; then
    echo -e "${GREEN}✓ All checks passed! Your system should boot and reboot safely.${NC}"
    echo "  Current kernel: $CURRENT_KERNEL"
    echo "  Root filesystem: $ROOT_FS"
    
    echo -e "\nWould you like to perform a reboot test? (y/N): "
    read -r REBOOT_TEST
    if [[ $REBOOT_TEST =~ ^[Yy]$ ]]; then
        echo "Scheduling a reboot in 1 minute..."
        echo "The system will display a message upon successful reboot."
        
        # Create a marker file to check after reboot
        MARKER="/var/tmp/boot_test_$(date +%s)"
        touch $MARKER
        
        # Add a script to run after reboot to confirm success
        cat > /etc/profile.d/boot-test-result.sh << EOF
#!/bin/bash
if [ -f $MARKER ]; then
    echo -e "\n\033[0;32m*** Boot test completed successfully! ***\033[0m"
    rm -f $MARKER
    rm -f /etc/profile.d/boot-test-result.sh
fi
EOF
        chmod +x /etc/profile.d/boot-test-result.sh
        
        # Schedule reboot
        shutdown -r +1 "Boot test reboot scheduled"
    else
        echo "Reboot test skipped."
    fi
else
    echo -e "${RED}✗ Some checks failed. Addressing the issues before rebooting is recommended.${NC}"
    echo "  Review the output above and fix any items marked as FAIL."
    echo "  Once issues are resolved, run this script again."
fi

exit $OVERALL_STATUS
