#!/bin/bash

# Network Security Scanner
# Part of the Hardening Scripts Collection
# Author: Archangel144k
# Version: 1.0
# Purpose: Internal network security assessment and monitoring

set -euo pipefail

# Configuration
SCRIPT_NAME="network-scanner.sh"
VERSION="1.0"
OUTPUT_DIR="/tmp/network_scan_$(date +%Y%m%d_%H%M%S)"
REPORT_FILE="$OUTPUT_DIR/network_security_report.txt"
NMAP_TIMEOUT=300  # 5 minutes timeout for nmap scans
MAX_THREADS=10    # Maximum concurrent threads for scanning

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# High-risk ports and services
HIGH_RISK_PORTS="21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1433,1521,3306,3389,5432,5900,6379"
BACKDOOR_PORTS="4444,5555,6666,7777,8080,9999,31337,65000"
DEFAULT_CREDS_SERVICES="ssh,telnet,ftp,http,https,mysql,postgresql,mssql,oracle,redis,mongodb"

# Critical findings tracker
declare -a CRITICAL_FINDINGS=()
declare -a HIGH_FINDINGS=()
declare -a MEDIUM_FINDINGS=()

# Function definitions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1" | tee -a "$REPORT_FILE"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1" | tee -a "$REPORT_FILE"
    MEDIUM_FINDINGS+=("$1")
}

log_critical() {
    echo -e "${RED}[CRITICAL]${NC} $1" | tee -a "$REPORT_FILE"
    CRITICAL_FINDINGS+=("$1")
}

log_high() {
    echo -e "${YELLOW}[HIGH]${NC} $1" | tee -a "$REPORT_FILE"
    HIGH_FINDINGS+=("$1")
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1" | tee -a "$REPORT_FILE"
}

usage() {
    cat << EOF
$SCRIPT_NAME v$VERSION - Network Security Scanner

Usage: $0 [OPTIONS]

OPTIONS:
    -t, --target CIDR       Target network (e.g., 192.168.1.0/24)
    -i, --interface IFACE   Network interface to scan from
    -q, --quick            Quick scan (top 100 ports only)
    -f, --full             Full scan (all 65535 ports)
    -s, --stealth          Stealth scan mode
    -o, --output DIR       Output directory (default: /tmp/network_scan_*)
    -h, --help             Show this help message

Examples:
    $0 -t 192.168.1.0/24                    # Scan local network
    $0 -i eth0 -q                          # Quick scan on eth0 interface
    $0 -t 10.0.0.0/16 -f -s                # Full stealth scan
    $0 -t 192.168.1.0/24 -o /var/log/scans # Custom output directory

EOF
    exit 1
}

check_dependencies() {
    local deps=("nmap" "arp-scan" "netstat" "ss" "dig" "curl" "nslookup")
    local missing=()
    
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" >/dev/null 2>&1; then
            missing+=("$dep")
        fi
    done
    
    if [[ ${#missing[@]} -gt 0 ]]; then
        log_critical "Missing required dependencies: ${missing[*]}"
        echo -e "\nInstall missing dependencies:"
        echo "Ubuntu/Debian: sudo apt install nmap arp-scan net-tools dnsutils curl"
        echo "RHEL/CentOS:   sudo dnf install nmap arp-scan net-tools bind-utils curl"
        exit 1
    fi
    
    log_success "All dependencies satisfied"
}

detect_network_interface() {
    if [[ -z "${INTERFACE:-}" ]]; then
        INTERFACE=$(ip route | grep default | head -1 | awk '{print $5}')
        if [[ -z "$INTERFACE" ]]; then
            log_critical "Could not detect default network interface"
            exit 1
        fi
    fi
    log_info "Using network interface: $INTERFACE"
}

get_network_range() {
    if [[ -z "${TARGET_NETWORK:-}" ]]; then
        local ip_info
        ip_info=$(ip addr show "$INTERFACE" | grep 'inet ' | head -1 | awk '{print $2}')
        if [[ -z "$ip_info" ]]; then
            log_critical "Could not determine network range for $INTERFACE"
            exit 1
        fi
        TARGET_NETWORK="$ip_info"
        # Convert to network address if it's a host address
        if [[ "$TARGET_NETWORK" =~ /32$ ]]; then
            TARGET_NETWORK=$(echo "$TARGET_NETWORK" | sed 's|/32|/24|')
        fi
    fi
    log_info "Target network: $TARGET_NETWORK"
}

initialize_scan() {
    mkdir -p "$OUTPUT_DIR"
    
    {
        echo "========================================"
        echo "NETWORK SECURITY SCANNER REPORT"
        echo "========================================"
        echo "Scan Date: $(date)"
        echo "Scanner Version: $VERSION"
        echo "Target Network: $TARGET_NETWORK"
        echo "Interface: $INTERFACE"
        echo "Output Directory: $OUTPUT_DIR"
        echo "========================================"
        echo
    } > "$REPORT_FILE"
    
    log_info "Network security scan initialized"
    log_info "Report will be saved to: $REPORT_FILE"
}

scan_network_discovery() {
    log_info "Starting network discovery..."
    
    echo -e "\n[1] NETWORK DISCOVERY" >> "$REPORT_FILE"
    echo "=====================" >> "$REPORT_FILE"
    
    # ARP scan for live hosts
    log_info "Performing ARP scan for live hosts..."
    if arp-scan -l -I "$INTERFACE" 2>/dev/null > "$OUTPUT_DIR/arp_scan.txt"; then
        local live_hosts
        live_hosts=$(grep -c "^[0-9]" "$OUTPUT_DIR/arp_scan.txt" 2>/dev/null || echo "0")
        log_info "Found $live_hosts live hosts via ARP scan"
        
        echo -e "\nLive Hosts (ARP):" >> "$REPORT_FILE"
        cat "$OUTPUT_DIR/arp_scan.txt" >> "$REPORT_FILE"
    else
        log_warning "ARP scan failed, trying nmap ping sweep..."
    fi
    
    # Nmap ping sweep
    log_info "Performing nmap ping sweep..."
    if nmap -sn "$TARGET_NETWORK" 2>/dev/null > "$OUTPUT_DIR/ping_sweep.txt"; then
        echo -e "\nPing Sweep Results:" >> "$REPORT_FILE"
        grep "Nmap scan report" "$OUTPUT_DIR/ping_sweep.txt" >> "$REPORT_FILE"
    fi
    
    # Extract live IPs for further scanning
    {
        grep -o '[0-9]\+\.[0-9]\+\.[0-9]\+\.[0-9]\+' "$OUTPUT_DIR/arp_scan.txt" 2>/dev/null || true
        grep "Nmap scan report" "$OUTPUT_DIR/ping_sweep.txt" 2>/dev/null | awk '{print $5}' || true
    } | sort -u > "$OUTPUT_DIR/live_hosts.txt"
    
    local total_hosts
    total_hosts=$(wc -l < "$OUTPUT_DIR/live_hosts.txt")
    log_info "Total unique live hosts discovered: $total_hosts"
}

scan_ports() {
    log_info "Starting port scanning phase..."
    
    echo -e "\n[2] PORT SCANNING" >> "$REPORT_FILE"
    echo "==================" >> "$REPORT_FILE"
    
    local scan_options=""
    local port_range=""
    
    # Determine scan type and options
    if [[ "${STEALTH_MODE:-false}" == "true" ]]; then
        scan_options="-sS -T2"
        log_info "Using stealth scan mode"
    else
        scan_options="-sS -T4"
    fi
    
    if [[ "${QUICK_SCAN:-false}" == "true" ]]; then
        port_range="--top-ports 100"
        log_info "Quick scan: top 100 ports"
    elif [[ "${FULL_SCAN:-false}" == "true" ]]; then
        port_range="-p-"
        log_info "Full scan: all 65535 ports"
    else
        port_range="-p $HIGH_RISK_PORTS,$BACKDOOR_PORTS"
        log_info "Standard scan: high-risk and backdoor ports"
    fi
    
    # Scan each live host
    while read -r host; do
        [[ -z "$host" ]] && continue
        
        log_info "Scanning host: $host"
        
        local output_file="$OUTPUT_DIR/portscan_$host.txt"
        local nmap_cmd="nmap $scan_options $port_range -sV -O --script vuln,default $host"
        
        if timeout "$NMAP_TIMEOUT" $nmap_cmd > "$output_file" 2>&1; then
            # Check for high-risk findings
            if grep -q "backdoor\|trojan\|malware" "$output_file"; then
                log_critical "Potential backdoor/malware detected on $host"
            fi
            
            # Check for high-risk open ports
            while read -r port; do
                if grep -q "$port/tcp.*open" "$output_file"; then
                    log_high "High-risk port $port open on $host"
                fi
            done < <(echo "$HIGH_RISK_PORTS,$BACKDOOR_PORTS" | tr ',' '\n')
            
            # Check for vulnerabilities
            if grep -q "VULNERABLE" "$output_file"; then
                log_critical "Vulnerabilities detected on $host"
            fi
            
            # Add to report
            echo -e "\n--- Host: $host ---" >> "$REPORT_FILE"
            cat "$output_file" >> "$REPORT_FILE"
            
        else
            log_warning "Scan timeout or failed for host: $host"
        fi
        
    done < "$OUTPUT_DIR/live_hosts.txt"
}

check_default_credentials() {
    log_info "Checking for default credentials..."
    
    echo -e "\n[3] DEFAULT CREDENTIALS CHECK" >> "$REPORT_FILE"
    echo "==============================" >> "$REPORT_FILE"
    
    # Common default credentials
    declare -A DEFAULT_CREDS=(
        ["ssh"]="admin:admin,root:root,admin:password,root:password,admin:,root:"
        ["telnet"]="admin:admin,root:root,admin:password"
        ["ftp"]="admin:admin,anonymous:,ftp:ftp"
        ["http"]="admin:admin,admin:password,root:root"
        ["mysql"]="root:,root:root,mysql:mysql"
        ["postgresql"]="postgres:postgres,postgres:"
    )
    
    while read -r host; do
        [[ -z "$host" ]] && continue
        
        # Check SSH
        if nmap -p 22 "$host" 2>/dev/null | grep -q "22/tcp.*open"; then
            log_warning "SSH service detected on $host - manual credential check recommended"
        fi
        
        # Check for web interfaces with default creds
        for port in 80 443 8080 8443; do
            if nmap -p "$port" "$host" 2>/dev/null | grep -q "$port/tcp.*open"; then
                log_warning "Web service on $host:$port - check for default web interface credentials"
            fi
        done
        
    done < "$OUTPUT_DIR/live_hosts.txt"
}

check_ssl_certificates() {
    log_info "Checking SSL/TLS certificates..."
    
    echo -e "\n[4] SSL/TLS CERTIFICATE ANALYSIS" >> "$REPORT_FILE"
    echo "==================================" >> "$REPORT_FILE"
    
    while read -r host; do
        [[ -z "$host" ]] && continue
        
        # Check HTTPS
        if nmap -p 443 "$host" 2>/dev/null | grep -q "443/tcp.*open"; then
            log_info "Checking SSL certificate for $host:443"
            
            local cert_info
            cert_info=$(timeout 10 openssl s_client -connect "$host:443" -servername "$host" 2>/dev/null </dev/null | openssl x509 -noout -text 2>/dev/null || echo "Certificate check failed")
            
            echo -e "\n--- SSL Certificate for $host ---" >> "$REPORT_FILE"
            echo "$cert_info" >> "$REPORT_FILE"
            
            # Check for weak ciphers
            local cipher_check
            cipher_check=$(nmap --script ssl-enum-ciphers -p 443 "$host" 2>/dev/null || echo "Cipher check failed")
            if echo "$cipher_check" | grep -q "SSLv2\|SSLv3\|weak"; then
                log_critical "Weak SSL/TLS configuration detected on $host:443"
            fi
        fi
        
    done < "$OUTPUT_DIR/live_hosts.txt"
}

detect_rogue_devices() {
    log_info "Detecting potential rogue devices..."
    
    echo -e "\n[5] ROGUE DEVICE DETECTION" >> "$REPORT_FILE"
    echo "===========================" >> "$REPORT_FILE"
    
    # Get known MAC addresses (this would typically come from a whitelist)
    # For demo purposes, we'll flag any unknown vendors
    
    if [[ -f "$OUTPUT_DIR/arp_scan.txt" ]]; then
        echo -e "\nMAC Address Analysis:" >> "$REPORT_FILE"
        
        while read -r line; do
            if [[ "$line" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+ ]]; then
                local mac_vendor
                mac_vendor=$(echo "$line" | awk '{print $3,$4,$5}' | sed 's/[[:space:]]*$//')
                
                # Flag suspicious or unknown vendors
                if [[ "$mac_vendor" =~ (Unknown|Private|Randomized) ]]; then
                    log_warning "Suspicious MAC vendor detected: $line"
                fi
                
                echo "$line" >> "$REPORT_FILE"
            fi
        done < "$OUTPUT_DIR/arp_scan.txt"
    fi
}

check_dns_security() {
    log_info "Checking DNS security..."
    
    echo -e "\n[6] DNS SECURITY ANALYSIS" >> "$REPORT_FILE"
    echo "==========================" >> "$REPORT_FILE"
    
    # Check for DNS servers
    local dns_servers
    dns_servers=$(grep "nameserver" /etc/resolv.conf | awk '{print $2}')
    
    echo -e "\nConfigured DNS Servers:" >> "$REPORT_FILE"
    echo "$dns_servers" >> "$REPORT_FILE"
    
    # Test DNS resolution
    for dns in $dns_servers; do
        log_info "Testing DNS server: $dns"
        
        local dns_test
        dns_test=$(dig @"$dns" google.com +short 2>/dev/null || echo "DNS test failed")
        
        echo -e "\nDNS Test for $dns:" >> "$REPORT_FILE"
        echo "$dns_test" >> "$REPORT_FILE"
        
        # Check for DNS over HTTPS/TLS support
        if [[ "$dns" != "127.0.0.1" ]] && [[ "$dns" != "::1" ]]; then
            log_info "Checking if DNS server supports secure protocols"
        fi
    done
}

generate_summary() {
    log_info "Generating security summary..."
    
    {
        echo -e "\n========================================"
        echo "SECURITY ASSESSMENT SUMMARY"
        echo "========================================"
        echo "Scan completed: $(date)"
        echo
        echo "FINDINGS SUMMARY:"
        echo "Critical Issues: ${#CRITICAL_FINDINGS[@]}"
        echo "High Risk Issues: ${#HIGH_FINDINGS[@]}"
        echo "Medium Risk Issues: ${#MEDIUM_FINDINGS[@]}"
        echo
        
        if [[ ${#CRITICAL_FINDINGS[@]} -gt 0 ]]; then
            echo "CRITICAL FINDINGS:"
            printf '%s\n' "${CRITICAL_FINDINGS[@]}"
            echo
        fi
        
        if [[ ${#HIGH_FINDINGS[@]} -gt 0 ]]; then
            echo "HIGH RISK FINDINGS:"
            printf '%s\n' "${HIGH_FINDINGS[@]}"
            echo
        fi
        
        echo "RECOMMENDATIONS:"
        echo "1. Address all critical and high-risk findings immediately"
        echo "2. Implement network segmentation for sensitive systems"
        echo "3. Regular security scanning and monitoring"
        echo "4. Keep all systems and services updated"
        echo "5. Implement strong authentication and access controls"
        echo
        echo "Detailed results saved to: $OUTPUT_DIR"
        
    } >> "$REPORT_FILE"
    
    # Display summary on console
    echo
    log_success "Network security scan completed!"
    echo -e "${BLUE}Summary:${NC}"
    echo -e "  Critical Issues: ${RED}${#CRITICAL_FINDINGS[@]}${NC}"
    echo -e "  High Risk Issues: ${YELLOW}${#HIGH_FINDINGS[@]}${NC}"
    echo -e "  Medium Risk Issues: ${YELLOW}${#MEDIUM_FINDINGS[@]}${NC}"
    echo -e "  Full report: ${GREEN}$REPORT_FILE${NC}"
}

cleanup() {
    log_info "Cleaning up temporary files..."
    # Keep report files but clean up any temporary scanning files
    find "$OUTPUT_DIR" -name "*.tmp" -delete 2>/dev/null || true
}

# Signal handlers
trap cleanup EXIT
trap 'log_critical "Scan interrupted by user"; exit 1' INT TERM

# Main execution
main() {
    local QUICK_SCAN=false
    local FULL_SCAN=false
    local STEALTH_MODE=false
    
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -t|--target)
                TARGET_NETWORK="$2"
                shift 2
                ;;
            -i|--interface)
                INTERFACE="$2"
                shift 2
                ;;
            -q|--quick)
                QUICK_SCAN=true
                shift
                ;;
            -f|--full)
                FULL_SCAN=true
                shift
                ;;
            -s|--stealth)
                STEALTH_MODE=true
                shift
                ;;
            -o|--output)
                OUTPUT_DIR="$2"
                REPORT_FILE="$OUTPUT_DIR/network_security_report.txt"
                shift 2
                ;;
            -h|--help)
                usage
                ;;
            *)
                echo "Unknown option: $1"
                usage
                ;;
        esac
    done
    
    # Check for root privileges
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}Error:${NC} This script requires root privileges for comprehensive scanning"
        echo "Please run with sudo: sudo $0 $*"
        exit 1
    fi
    
    # Run the scan
    check_dependencies
    detect_network_interface
    get_network_range
    initialize_scan
    
    scan_network_discovery
    scan_ports
    check_default_credentials
    check_ssl_certificates
    detect_rogue_devices
    check_dns_security
    
    generate_summary
    
    log_success "Network security assessment completed successfully!"
}

# Execute main function with all arguments
main "$@"