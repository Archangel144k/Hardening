Hardening Scripts Collection

This repository provides two powerful shell scripts to improve the security and monitoring of Linux systems:

    backdoor_scanner.sh: Detects backdoors, suspicious activity, and persistence mechanisms.
    suricata-wazuh.sh: Installs and configures Suricata IDS and optionally Wazuh across multiple Linux distributions.

1. Backdoor & Suspicious Connection Detection

Script Name: backdoor_scanner.sh
Version: 2.0
Purpose: Comprehensive detection of backdoors, unauthorized remote connections, and persistence mechanisms on Linux systems.
Last Updated: 2025-06-01
🔍 Features

    Network Analysis
        Lists active connections & listening ports
        Detects high-risk ports (e.g., 4444, 31337)
        Flags unusual outbound connections
    Process Inspection
        Finds suspicious processes (reverse shells, miners)
        Reports high CPU usage
        Detects hidden/deleted binaries
    Persistence Checks
        Audits cron jobs & startup services (rc.d, systemd, etc.)
        Checks for profile/rc file modifications
    Authentication Security
        Audits SSH configuration and keys
    File System Analysis
        Finds SUID/SGID binaries
        World-writable files
        Recently modified files (last 2 days)
    Log Analysis
        Reports failed/accepted SSH logins
        Suspicious command history
    Security Tools Integration
        Runs rootkit checks (rkhunter, chkrootkit)
        Reports SELinux/AppArmor status

Usage
bash

chmod +x backdoor_scanner.sh
sudo ./backdoor_scanner.sh

2. Suricata & Wazuh Installer

Script Name: suricata-wazuh.sh
Purpose: Installs and configures Suricata (an open source IDS/IPS) and optionally Wazuh (security monitoring) on various Linux distributions.
Features:

    Automatic OS Detection: Supports multiple Linux distributions (Debian, Ubuntu, CentOS, etc.)
    Suricata Installation & Configuration: Sets up Suricata with recommended settings
    Optional Wazuh Agent Setup: Installs/configures Wazuh if selected by user
    Service Management: Ensures services are enabled and started
    Idempotent: Safe to re-run for updating/reconfiguring

Usage
bash

chmod +x suricata-wazuh.sh
sudo ./suricata-wazuh.sh

    Script will prompt for options and handle installation/configuration automatically.

Requirements

    Root privileges (sudo or run as root)
    Internet access for installing packages

Disclaimer

Use these scripts at your own risk. Test in a safe environment before deploying to production.
License

MIT
