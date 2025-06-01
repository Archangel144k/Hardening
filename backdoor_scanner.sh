#!/bin/bash

# Enhanced Backdoor and Suspicious Connection Detection Script
# Requires sudo privileges for full functionality
# Version 2.0 - Security Enhanced

# Configuration
OUTPUT_FILE="backdoor_scan_$(date +%Y%m%d_%H%M%S).txt"
TMP_DIR="/tmp/backdoor_scan"
MAX_LOG_LINES=200  # Limit log output length
HIGH_RISK_PORTS="4444|5555|6666|7777|31337|1337|65000"  # Common backdoor ports
SUSPICIOUS_PATTERNS="(bash -i|nc -e|/dev/tcp|/dev/udp|socat |mkfifo |php -r|python -c|perl -e)"

# Create temporary workspace
mkdir -p "$TMP_DIR"
trap 'rm -rf "$TMP_DIR"' EXIT

# Initialize critical findings list
critical_findings=()

{
echo "=== ENHANCED BACKDOOR & REMOTE CONNECTION SCAN REPORT ==="
echo "Timestamp: $(date)"
echo "Hostname: $(hostname)"
echo "User: $(whoami)"
echo "OS: $(grep PRETTY_NAME /etc/os-release | cut -d= -f2)"
echo "---------------------------------------------------------"

# Section 1: Network Analysis
echo -e "\n[1] NETWORK ANALYSIS"
echo "====================="

echo -e "\n[+] Active Connections (ss):"
sudo ss -tulnp | grep -Ev '127.0.0.1|::1|0.0.0.0' | tee "$TMP_DIR/active_conns.txt"
[[ -s "$TMP_DIR/active_conns.txt" ]] && critical_findings+=("Suspicious network connections found")

echo -e "\n[+] Listening Ports (high risk):"
sudo ss -tuln | grep -E "$HIGH_RISK_PORTS" | tee "$TMP_DIR/high_risk_ports.txt"
[[ -s "$TMP_DIR/high_risk_ports.txt" ]] && critical_findings+=("High-risk ports in use")

echo -e "\n[+] Unusual Outbound Connections:"
sudo lsof -i -nP | grep ESTABLISHED | awk '{print $1,$5,$8,$9}' | sort | uniq | tee "$TMP_DIR/outbound_conns.txt"

# Section 2: Process Inspection
echo -e "\n\n[2] PROCESS ANALYSIS"
echo "====================="

echo -e "\n[+] Suspicious Processes:"
ps aux | grep -E "$SUSPICIOUS_PATTERNS" | grep -v grep | tee "$TMP_DIR/suspicious_processes.txt"
[[ -s "$TMP_DIR/suspicious_processes.txt" ]] && critical_findings+=("Suspicious processes detected")

echo -e "\n[+] High CPU Processes:"
ps aux --sort=-%cpu | head -n 10 | awk '{print $2,$3,$11}' | tee "$TMP_DIR/cpu_processes.txt"

echo -e "\n[+] Hidden Processes:"
sudo ls -la /proc/*/exe 2>/dev/null | grep deleted | tee "$TMP_DIR/hidden_processes.txt"
[[ -s "$TMP_DIR/hidden_processes.txt" ]] && critical_findings+=("Hidden processes detected")

# Section 3: Persistence Mechanisms
echo -e "\n\n[3] PERSISTENCE CHECKS"
echo "========================"

echo -e "\n[+] Cron Jobs:"
echo "System Crontab:"; sudo crontab -l 2>/dev/null
echo -e "\nUser Crontabs:"; sudo ls /var/spool/cron/crontabs/ 2>/dev/null

echo -e "\n[+] Startup Services:"
sudo systemctl list-unit-files --state=enabled --no-pager | tee "$TMP_DIR/enabled_services.txt"

echo -e "\n[+] Autostart Locations:"
ls -la /etc/init.d/ /etc/rc*.d/ ~/.config/autostart/ /Library/LaunchAgents/ /Library/LaunchDaemons/ 2>/dev/null

echo -e "\n[+] Profile Files:"
grep -sHv '^#' /etc/profile /etc/bash.bashrc /etc/zsh/zshrc ~/.bashrc ~/.zshrc ~/.profile | grep -E '(curl |wget |chmod |sh -c)' | tee "$TMP_DIR/suspicious_profiles.txt"
[[ -s "$TMP_DIR/suspicious_profiles.txt" ]] && critical_findings+=("Suspicious profile entries")

# Section 4: Authentication Security
echo -e "\n\n[4] AUTHENTICATION CHECKS"
echo "==========================="

echo -e "\n[+] SSH Configuration:"
sudo grep -iE '(PermitRootLogin|AllowUsers|Port|PasswordAuthentication|PermitEmptyPasswords)' /etc/ssh/sshd_config | tee "$TMP_DIR/ssh_config.txt"

echo -e "\n[+] SSH Keys:"
find / -name authorized_keys 2>/dev/null | while read f; do 
    echo ">> $f"; 
    grep -v '^#' "$f" 2>/dev/null; 
done | tee "$TMP_DIR/ssh_keys.txt"

# Section 5: File System Analysis
echo -e "\n\n[5] FILE SYSTEM ANALYSIS"
echo "========================="

echo -e "\n[+] SUID/SGID Files:"
sudo find / -type f \( -perm -4000 -o -perm -2000 \) -exec ls -la {} \; 2>/dev/null | grep -vE '/snap/|/usr/lib|/usr/bin' | tee "$TMP_DIR/suid_files.txt"

echo -e "\n[+] World-Writable Files:"
sudo find / -xdev -type f -perm -0002 ! -path "/proc/*" ! -path "/sys/*" -exec ls -la {} \; 2>/dev/null | tee "$TMP_DIR/world_writable.txt"

echo -e "\n[+] Recent Modified Files (last 2 days):"
sudo find / -type f -mtime -2 ! -path "/proc/*" ! -path "/sys/*" ! -path "/tmp/*" ! -path "/var/tmp/*" -exec ls -la {} \; 2>/dev/null | tee "$TMP_DIR/recent_files.txt"

# Section 6: Log Analysis
echo -e "\n\n[6] LOG ANALYSIS"
echo "================"

echo -e "\n[+] SSH Auth Logs:"
sudo tail -n $MAX_LOG_LINES /var/log/auth.log /var/log/secure 2>/dev/null | grep -E '(Failed|Accepted)' | tee "$TMP_DIR/ssh_logs.txt"

echo -e "\n[+] Command History:"
for user_home in /home/* /root; do
    history_file="$user_home/.bash_history"
    [ -f "$history_file" ] && {
        echo ">> $history_file"
        grep -E "$SUSPICIOUS_PATTERNS" "$history_file"
    }
done | tee "$TMP_DIR/suspicious_history.txt"
[[ -s "$TMP_DIR/suspicious_history.txt" ]] && critical_findings+=("Suspicious command history")

# Section 7: Security Tools
echo -e "\n\n[7] SECURITY TOOLS"
echo "=================="

echo -e "\n[+] Rootkit Checks:"
command -v rkhunter >/dev/null && sudo rkhunter --check --sk 2>/dev/null | grep -i 'warning\|infected'
command -v chkrootkit >/dev/null && sudo chkrootkit 2>/dev/null | grep -i 'infected\|warning'

echo -e "\n[+] SELinux/AppArmor:"
sestatus 2>/dev/null || aa-status 2>/dev/null

# Critical Findings Summary
echo -e "\n\n[!] CRITICAL FINDINGS SUMMARY"
echo "=============================="
if [ ${#critical_findings[@]} -eq 0 ]; then
    echo "No critical findings detected"
else
    for finding in "${critical_findings[@]}"; do
        echo " - [CRITICAL] $finding"
    done
    echo -e "\n[!] IMMEDIATE INVESTIGATION REQUIRED FOR ABOVE FINDINGS!"
fi

echo -e "\n=== SCAN COMPLETE ==="
echo "Full report saved to: $OUTPUT_FILE"
} | tee "$OUTPUT_FILE"

# Final cleanup
rm -rf "$TMP_DIR"
