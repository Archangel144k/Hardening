#!/usr/bin/env python3
"""
SECURITY LOG ANALYZER BOT
Automated real-time monitoring of system logs for security events
Designed for cybersecurity portfolios - demonstrates Linux security automation
"""

import re
from collections import defaultdict, deque
import time
import os

# ========================
# SECURITY CONFIGURATION
# ========================
LOG_FILE = "/var/log/syslog"  # Primary log file to monitor (Ubuntu/Debian)
# For RHEL/CentOS use: "/var/log/messages"

# Security thresholds - adjust based on your environment
ALERT_THRESHOLDS = {
    'ssh_failures': 5,        # Max failed SSH attempts per IP before alert
    'port_scan_window': 60,    # Time window for port scan detection (seconds)
    'port_scan_min_ports': 5,  # Minimum unique ports to trigger port scan alert
}

# Critical system files to monitor for unauthorized changes
CRITICAL_FILES = [
    "/etc/passwd",    # User account database
    "/etc/shadow",    # Encrypted password storage
    "/etc/sudoers",   # Sudo permissions configuration
    "/etc/crontab"    # Scheduled tasks configuration
]

# ========================
# DETECTION ENGINE
# ========================
class LogAnalyzer:
    def __init__(self):
        """Initialize tracking systems and patterns"""
        # SSH brute-force tracking: {ip: failure_count}
        self.ssh_tracker = defaultdict(int)
        
        # Port scan tracking: {ip: deque((port, timestamp))}
        self.port_scan_tracker = defaultdict(lambda: deque(maxlen=50))
        
        # File position tracking for log rotation handling
        self.last_pos = 0
        
        # Regex patterns for log parsing
        self.patterns = {
            # Failed SSH authentication attempts
            'ssh_fail': re.compile(r'Failed password for .* from (\S+) port \d+'),
            
            # Successful SSH logins (for resetting failure counters)
            'ssh_success': re.compile(r'Accepted password for .* from (\S+) port \d+'),
            
            # Sudo privilege escalations
            'sudo_cmd': re.compile(r'session opened for user (\w+) by (\w+)'),
            
            # Critical file modifications (generic pattern)
            'file_mod': re.compile(r'(\w+)\[\d+\]: (.+?) \| .*?file=(.*?)( |$)'),
            
            # New process executions
            'new_process': re.compile(r'Started process (\d+) .*command=\'(.*?)\''),
            
            # Port scan detection (UFW firewall blocks)
            'port_scan': re.compile(r'\[UFW BLOCK\] .*?SRC=(\S+) DST=(\S+) .*?DPT=(\d+)')
        }
        
        # Alert storage for current detection cycle
        self.alerts = []
        
        # Security alert log file
        self.alert_log = "/var/log/security_alerts.log"
        
        print(f"[*] Starting security monitor for {LOG_FILE}")
        print(f"[*] Tracking {len(CRITICAL_FILES)} critical files")
        print("[*] Detection thresholds:")
        print(f"    SSH Failures: {ALERT_THRESHOLDS['ssh_failures']}")
        print(f"    Port Scan: {ALERT_THRESHOLDS['port_scan_min_ports']} ports in {ALERT_THRESHOLDS['port_scan_window']}s")

    def _tail_log(self):
        """
        Read new log entries since last check
        Handles log rotation by resetting file position if file shrinks
        """
        try:
            # Get current file size
            file_size = os.path.getsize(LOG_FILE)
            
            # Handle log rotation (file smaller than last position)
            if file_size < self.last_pos:
                self.last_pos = 0
                
            with open(LOG_FILE, 'r') as f:
                f.seek(self.last_pos)
                new_lines = f.readlines()
                self.last_pos = f.tell()
            return new_lines
        except FileNotFoundError:
            print(f"[ERROR] Log file not found: {LOG_FILE}")
            return []
        except Exception as e:
            print(f"[ERROR] Log read failure: {str(e)}")
            return []

    def _check_ssh_bruteforce(self, ip):
        """
        Detect SSH brute-force attempts
        Tracks consecutive failures and triggers alert on threshold
        Resets counter on successful login
        """
        self.ssh_tracker[ip] += 1
        
        # Threshold check
        if self.ssh_tracker[ip] >= ALERT_THRESHOLDS['ssh_failures']:
            self.alerts.append(
                f"BRUTE-FORCE ALERT: {ip} failed SSH "
                f"{self.ssh_tracker[ip]} times"
            )
            # Reset counter after alert
            self.ssh_tracker[ip] = 0

    def _check_port_scan(self, ip, port, timestamp):
        """
        Detect port scanning patterns
        Tracks unique port access attempts within time window
        """
        # Record scan attempt
        self.port_scan_tracker[ip].append((port, timestamp))
        
        # Get all recent scan attempts from this IP
        ports = [p for p, t in self.port_scan_tracker[ip]]
        unique_ports = len(set(ports))
        
        # Calculate time window for recent scans
        time_window = time.time() - ALERT_THRESHOLDS['port_scan_window']
        recent_scans = [t for p, t in self.port_scan_tracker[ip] if t > time_window]
        
        # Threshold check (unique ports and scan frequency)
        if (unique_ports >= ALERT_THRESHOLDS['port_scan_min_ports'] and 
            len(recent_scans) > ALERT_THRESHOLDS['port_scan_min_ports']):
            self.alerts.append(
                f"PORT SCAN DETECTED: {ip} probed {unique_ports} ports "
                f"in {len(recent_scans)} attempts"
            )
            # Clear tracker after detection
            self.port_scan_tracker[ip].clear()

    def _log_alert(self, alert):
        """Record alerts to security log file"""
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] {alert}\n"
        
        try:
            with open(self.alert_log, "a") as f:
                f.write(log_entry)
        except Exception as e:
            print(f"[ERROR] Alert logging failed: {str(e)}")

    def analyze(self):
        """Main analysis loop - processes log entries in real-time"""
        print("[*] Starting security monitoring...")
        print("[*] Press Ctrl+C to exit\n")
        
        try:
            while True:
                # Get new log entries
                new_lines = self._tail_log()
                current_time = time.time()
                
                # Process each new log entry
                for line in new_lines:
                    # 1. SSH FAILURE DETECTION
                    if match := self.patterns['ssh_fail'].search(line):
                        ip = match.group(1)
                        self._check_ssh_bruteforce(ip)
                    
                    # 2. SSH SUCCESS (reset failure counter)
                    elif match := self.patterns['ssh_success'].search(line):
                        ip = match.group(1)
                        self.ssh_tracker[ip] = 0  # Reset on successful auth
                    
                    # 3. PORT SCAN DETECTION
                    elif match := self.patterns['port_scan'].search(line):
                        ip, _, port = match.groups()
                        self._check_port_scan(ip, port, current_time)
                    
                    # 4. CRITICAL FILE MODIFICATION
                    elif any(file in line for file in CRITICAL_FILES):
                        # Extract filename from log entry
                        filename = next((f for f in CRITICAL_FILES if f in line), "UNKNOWN")
                        self.alerts.append(
                            f"CRITICAL FILE MODIFIED: {filename} - {line.strip()[:100]}..."
                        )
                    
                    # 5. SUSPICIOUS SUDO USAGE
                    elif match := self.patterns['sudo_cmd'].search(line):
                        user, executor = match.groups()
                        # Alert on non-admin users accessing root
                        if user == 'root' and executor not in ['admin', 'sudo']:
                            self.alerts.append(
                                f"UNPRIVILEGED SUDO: {executor} elevated to root"
                            )
                    
                    # 6. MALICIOUS PROCESS DETECTION
                    elif match := self.patterns['new_process'].search(line):
                        pid, cmd = match.groups()
                        # Detect reverse shells and crypto miners
                        if "bash -i" in cmd or "xmr" in cmd.lower():
                            self.alerts.append(
                                f"SUSPICIOUS PROCESS: PID={pid} CMD='{cmd}'"
                            )
                
                # Process and log alerts
                for alert in self.alerts:
                    print(f"[!] SECURITY ALERT: {alert}")
                    self._log_alert(alert)
                
                # Clear alerts for next cycle
                self.alerts.clear()
                
                # Monitoring interval
                time.sleep(5)
                
        except KeyboardInterrupt:
            print("\n[!] Monitoring stopped by user")
        except Exception as e:
            print(f"[CRITICAL] Analysis failed: {str(e)}")

# ========================
# MAIN EXECUTION
# ========================
if __name__ == "__main__":
    # Initialize analyzer
    analyzer = LogAnalyzer()
    
    # Start monitoring
    analyzer.analyze()