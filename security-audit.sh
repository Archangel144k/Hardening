#!/bin/bash

# quick_security_audit.sh
# Cross-distro security audit: open ports, weak passwords, outdated packages.

echo "----------------------------------------"
echo " Quick Security Audit Script"
echo "----------------------------------------"
echo "Run as root for best results."
echo

# 1. Check for Open Ports (universal)
echo "[*] Scanning for open ports (using netstat or ss)..."
if command -v netstat >/dev/null 2>&1; then
    netstat -tuln | grep LISTEN
elif command -v ss >/dev/null 2>&1; then
    ss -tuln | grep LISTEN
else
    echo "No suitable tool found (need netstat or ss)."
fi
echo

# 2. Check for Weak Passwords (universal)
echo "[*] Checking for weak passwords (empty passwords)..."
if [ "$(id -u)" -eq 0 ]; then
    awk -F: '($2 == "") {print "User " $1 " has NO password!"}' /etc/shadow
else
    echo "(Run as root to check /etc/shadow for empty passwords)"
fi
echo

# 3. Check for Outdated Packages (distro-specific)
echo "[*] Checking for outdated packages..."

if [ -f /etc/os-release ]; then
    . /etc/os-release
    DISTRO=$ID
else
    DISTRO="unknown"
fi

case "$DISTRO" in
    ubuntu|debian)
        if command -v apt >/dev/null 2>&1; then
            apt update -qq >/dev/null
            apt list --upgradable 2>/dev/null | grep -v "Listing..."
        else
            echo "apt not found; skipping package check."
        fi
        ;;
    centos|rhel|fedora)
        if command -v dnf >/dev/null 2>&1; then
            dnf check-update || echo "No updates available or dnf failed."
        elif command -v yum >/dev/null 2>&1; then
            yum check-update || echo "No updates available or yum failed."
        else
            echo "yum/dnf not found; skipping package check."
        fi
        ;;
    arch)
        if command -v pacman >/dev/null 2>&1; then
            echo "Syncing package database..."
            pacman -Sy >/dev/null
            pacman -Qu || echo "No updates available or pacman failed."
        else
            echo "pacman not found; skipping package check."
        fi
        ;;
    opensuse*|suse|sles)
        if command -v zypper >/dev/null 2>&1; then
            zypper --non-interactive refresh >/dev/null
            zypper list-updates || echo "No updates available or zypper failed."
        else
            echo "zypper not found; skipping package check."
        fi
        ;;
    *)
        echo "Unknown or unsupported distro ($DISTRO). Skipping package check."
        ;;
esac

echo
echo "----------------------------------------"
echo " Quick Security Audit Complete."
echo "----------------------------------------"
