Backdoor & Suspicious Connection Detection Script
Script Name: backdoor_scanner.sh
Version: 2.0
Purpose: Comprehensive detection of backdoors, unauthorized remote connections, and persistence mechanisms on Linux systems.
Last Updated: 2025-06-01

🔍 Features
Network Analysis

Active connections & listening ports

High-risk port detection (4444, 31337, etc.)

Unusual outbound connections

Process Inspection

Suspicious processes (reverse shells, miners)

High CPU usage

Hidden processes (deleted binaries)

Persistence Checks

Cron jobs & startup services

Autostart locations (rc.d, systemd, etc.)

Profile/rc file modifications

Authentication Security

SSH configuration audit

Unauthorized SSH keys

File System Analysis

SUID/SGID binaries

World-writable files

Recently modified files (last 2 days)

Log Analysis

Failed/accepted SSH logins

Suspicious command history

Security Tools Integration

Rootkit scans (rkhunter, chkrootkit)

MAC status (SELinux/AppArmor)
