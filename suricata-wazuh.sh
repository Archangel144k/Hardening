#!/bin/bash

# Suricata Installation and Configuration Wizard
# Version: 2.1
# Description: Interactive Suricata IDS/IPS installation and configuration wizard

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Global variables
SURICATA_CONFIG_DIR="/etc/suricata"
SURICATA_LOG_DIR="/var/log/suricata"
DISTRO=""
VERSION=""
PACKAGE_MANAGER=""
NETWORK_INTERFACE=""
HOME_NET=""
MODE="IDS"  # Default mode
CUSTOM_RULE_SOURCES=()
CURRENT_SURICATA_VERSION=""
LATEST_STABLE_VERSION=""

# Logging function
log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] INFO: $1${NC}"
}

log_warning() {
    echo -e "${YELLOW}[$(date +'%Y-%m-%d %H:%M:%S')] WARNING: $1${NC}"
}

log_error() {
    echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')] ERROR: $1${NC}"
}

log_info() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')] INFO: $1${NC}"
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root. Use: sudo $0"
        exit 1
    fi
}

# Display banner
show_banner() {
    clear
    echo -e "${CYAN}"
    echo "  ██████  █    ██  ██▀███   ██▓  ██████ ▄▄▄█████▓ ▄▄▄       ██▓    
▒██    ▒  ██  ▓██▒▓██ ▒ ██▒▓██▒▒██    ▒ ▓  ██▒ ▓▒▒████▄    ▓██▒    
░ ▓██▄   ▓██  ▒██░▓██ ░▄█ ▒▒██▒░ ▓██▄   ▒ ▓██░ ▒░▒██  ▀█▄  ▒██░    
  ▒   ██▒▓▓█  ░██░▒██▀▀█▄  ░██░  ▒   ██▒░ ▓██▓ ░ ░██▄▄▄▄██ ▒██░    
▒██████▒▒▒▒█████▓ ░██▓ ▒██▒░██░▒██████▒▒  ▒██▒ ░  ▓█   ▓██▒░██████▒
▒ ▒▓▒ ▒ ░░▒▓▒ ▒ ▒ ░ ▒▓ ░▒▓░░▓  ▒ ▒▓▒ ▒ ░  ▒ ░░    ▒▒   ▓▒█░░ ▒░▓  ░
░ ░▒  ░ ░░░▒░ ░ ░   ░▒ ░ ▒░ ▒ ░░ ░▒  ░ ░    ░      ▒   ▒▒ ░░ ░ ▒  ░
░  ░  ░   ░░░ ░ ░   ░░   ░  ▒ ░░  ░  ░    ░        ░   ▒     ░ ░   
      ░     ░        ░      ░        ░                 ░  ░    ░  ░"
    echo -e "${NC}"
    echo -e "${BLUE}===================================================${NC}"
    echo -e "${BLUE}    Suricata Installation and Configuration Wizard${NC}"
    echo -e "${BLUE}===================================================${NC}"
    echo
}

# Pause function
pause() {
    read -p "Press [Enter] key to continue..."
}

# Ask user choice function
ask_choice() {
    local prompt="$1"
    local options=("${@:2}")
    local choice
    
    while true; do
        echo -e "${CYAN}$prompt${NC}"
        for i in "${!options[@]}"; do
            echo "  $((i+1)). ${options[$i]}"
        done
        echo
        read -p "Enter your choice [1-${#options[@]}]: " choice
        
        if [[ "$choice" =~ ^[0-9]+$ ]] && [ "$choice" -ge 1 ] && [ "$choice" -le "${#options[@]}" ]; then
            echo "$choice"
            return
        else
            echo -e "${RED}Invalid choice. Please select a number between 1 and ${#options[@]}.${NC}"
        fi
    done
}

# Ask yes/no function
ask_yes_no() {
    local prompt="$1"
    local choice
    
    while true; do
        read -p "$prompt (y/n): " choice
        case "$choice" in
            [Yy]* ) echo "yes"; return ;;
            [Nn]* ) echo "no"; return ;;
            * ) echo -e "${RED}Please answer yes or no.${NC}" ;;
        esac
    done
}

# Get current Suricata version
get_current_suricata_version() {
    if command -v suricata &> /dev/null; then
        CURRENT_SURICATA_VERSION=$(suricata --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || echo "")
        if [[ -n "$CURRENT_SURICATA_VERSION" ]]; then
            log "Current Suricata version: $CURRENT_SURICATA_VERSION"
        else
            log_warning "Could not determine current Suricata version"
        fi
    else
        CURRENT_SURICATA_VERSION=""
        log_info "Suricata is not currently installed"
    fi
}

# Get latest stable Suricata version
get_latest_stable_version() {
    log "Checking for latest stable Suricata version..."
    
    # Try multiple methods to get the latest version
    if command -v curl &> /dev/null; then
        LATEST_STABLE_VERSION=$(curl -s https://www.openinfosecfoundation.org/download/ | grep -oE 'suricata-[0-9]+\.[0-9]+\.[0-9]+\.tar\.gz' | head -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' || echo "")
    elif command -v wget &> /dev/null; then
        LATEST_STABLE_VERSION=$(wget -qO- https://www.openinfosecfoundation.org/download/ | grep -oE 'suricata-[0-9]+\.[0-9]+\.[0-9]+\.tar\.gz' | head -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' || echo "")
    fi
    
    # Fallback version if we can't fetch it
    if [[ -z "$LATEST_STABLE_VERSION" ]]; then
        LATEST_STABLE_VERSION="7.0.4"  # Latest known stable version
        log_warning "Could not fetch latest version info, using default: $LATEST_STABLE_VERSION"
    else
        log "Latest stable Suricata version: $LATEST_STABLE_VERSION"
    fi
}

# Check if update is available
is_update_available() {
    get_current_suricata_version
    get_latest_stable_version
    
    if [[ -z "$CURRENT_SURICATA_VERSION" ]]; then
        log_info "Suricata is not installed"
        return 0  # Need to install
    fi
    
    if [[ "$CURRENT_SURICATA_VERSION" != "$LATEST_STABLE_VERSION" ]]; then
        log_warning "Update available: $CURRENT_SURICATA_VERSION -> $LATEST_STABLE_VERSION"
        return 0  # Update available
    else
        log "Suricata is up to date ($CURRENT_SURICATA_VERSION)"
        return 1  # No update needed
    fi
}

# Detect Linux distribution
detect_distro() {
    log "Detecting Linux distribution..."
    
    if [[ -f /etc/os-release ]]; then
        source /etc/os-release
        DISTRO=$ID
        VERSION=$VERSION_ID
    elif [[ -f /etc/redhat-release ]]; then
        if grep -q "CentOS" /etc/redhat-release; then
            DISTRO="centos"
        elif grep -q "Red Hat" /etc/redhat-release; then
            DISTRO="rhel"
        fi
        VERSION=$(grep -oE '[0-9]+\.[0-9]+' /etc/redhat-release | cut -d. -f1)
    else
        log_error "Unable to detect Linux distribution"
        exit 1
    fi
    
    case $DISTRO in
        ubuntu|debian)
            PACKAGE_MANAGER="apt"
            ;;
        centos|rhel|fedora|rocky|almalinux)
            PACKAGE_MANAGER="yum"
            if command -v dnf &> /dev/null; then
                PACKAGE_MANAGER="dnf"
            fi
            ;;
        opensuse*|sles)
            PACKAGE_MANAGER="zypper"
            ;;
        arch)
            PACKAGE_MANAGER="pacman"
            ;;
        *)
            log_error "Unsupported distribution: $DISTRO"
            exit 1
            ;;
    esac
    
    log "Detected: $DISTRO $VERSION with $PACKAGE_MANAGER package manager"
}

# Update system packages
update_system() {
    if [[ $(ask_yes_no "Update system packages?") == "no" ]]; then
        log_info "Skipping system update"
        return
    fi
    
    log "Updating system packages..."
    
    case $PACKAGE_MANAGER in
        apt)
            apt update && apt upgrade -y
            ;;
        yum|dnf)
            $PACKAGE_MANAGER update -y
            ;;
        zypper)
            zypper refresh && zypper update -y
            ;;
        pacman)
            pacman -Syu --noconfirm
            ;;
    esac
}

# Install dependencies
install_dependencies() {
    if [[ $(ask_yes_no "Install Suricata dependencies?") == "no" ]]; then
        log_info "Skipping dependency installation"
        return
    fi
    
    log "Installing Suricata dependencies..."
    
    case $PACKAGE_MANAGER in
        apt)
            apt install -y software-properties-common curl wget gnupg2 \
                libpcap-dev libnet1-dev libyaml-0-2 libyaml-dev \
                libcap-ng-dev libcap-ng0 libmagic-dev libjansson-dev \
                libjansson4 liblz4-dev libpcre3-dev libssl-dev \
                pkg-config zlib1g-dev make gcc autoconf libtool \
                libnetfilter-queue-dev libnetfilter-queue1 \
                libnfnetlink-dev libnfnetlink0 ethtool jq
            ;;
        yum|dnf)
            # Try to install EPEL release if not Fedora and if it's available
            if [[ $DISTRO != "fedora" ]]; then
                log "Attempting to install EPEL repository..."
                if ! $PACKAGE_MANAGER install -y epel-release 2>/dev/null; then
                    log_warning "EPEL repository not available or already configured, continuing..."
                    
                    # For RHEL 9+ derivatives, enable CRB repository
                    if [[ $VERSION -ge 9 ]] && [[ $DISTRO == "rhel" || $DISTRO == "rocky" || $DISTRO == "almalinux" ]]; then
                        log "Enabling CRB repository for RHEL 9+ derivative..."
                        if command -v dnf config-manager &> /dev/null; then
                            dnf config-manager --set-enabled crb 2>/dev/null || \
                            dnf config-manager --set-enabled powertools 2>/dev/null || \
                            log_warning "Could not enable CRB/PowerTools repository"
                        fi
                    fi
                    
                    # For RHEL 8 derivatives, enable PowerTools
                    if [[ $VERSION -eq 8 ]] && [[ $DISTRO == "rhel" || $DISTRO == "rocky" || $DISTRO == "almalinux" || $DISTRO == "centos" ]]; then
                        log "Enabling PowerTools repository for RHEL 8 derivative..."
                        if command -v dnf config-manager &> /dev/null; then
                            dnf config-manager --set-enabled powertools 2>/dev/null || \
                            log_warning "Could not enable PowerTools repository"
                        fi
                    fi
                fi
            fi
            
            # Install dependencies with error handling
            log "Installing build dependencies..."
            $PACKAGE_MANAGER install -y --skip-unavailable \
                libpcap-devel libnet-devel libyaml-devel libcap-ng-devel \
                libmagic-devel jansson-devel lz4-devel pcre-devel \
                openssl-devel zlib-devel make gcc autoconf libtool \
                libnetfilter_queue-devel libnfnetlink-devel curl wget ethtool \
                file-devel pkg-config jq
            ;;
        zypper)
            zypper install -y libpcap-devel libnet-devel libyaml-devel \
                libcap-ng-devel file-devel libjansson-devel \
                liblz4-devel pcre-devel libopenssl-devel zlib-devel \
                make gcc autoconf libtool libnetfilter_queue-devel \
                libnfnetlink-devel curl wget ethtool jq
            ;;
        pacman)
            pacman -S --noconfirm libpcap libnet libyaml libcap-ng \
                file jansson lz4 pcre openssl zlib make gcc autoconf \
                libtool libnetfilter_queue libnfnetlink curl wget ethtool jq
            ;;
    esac
}

# Check if Suricata is installed
check_suricata_installed() {
    if command -v suricata &> /dev/null; then
        local current_version=$(suricata --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
        log "Suricata is already installed (version: $current_version)"
        return 0
    else
        log "Suricata is not installed"
        return 1
    fi
}

# Upgrade Suricata to latest stable version
upgrade_suricata_to_latest() {
    log "Upgrading Suricata to latest stable version ($LATEST_STABLE_VERSION)..."
    
    # Check if we're already at the latest version
    get_current_suricata_version
    if [[ -n "$CURRENT_SURICATA_VERSION" && "$CURRENT_SURICATA_VERSION" == "$LATEST_STABLE_VERSION" ]]; then
        log "Suricata is already at the latest version ($LATEST_STABLE_VERSION)"
        return 0
    fi
    
    # Stop Suricata service if running
    if systemctl is-active --quiet suricata; then
        log "Stopping Suricata service..."
        systemctl stop suricata
        sleep 2
    fi
    
    # Upgrade based on installation method
    case $PACKAGE_MANAGER in
        apt)
            # Add Suricata PPA if Ubuntu
            if [[ $DISTRO == "ubuntu" ]]; then
                add-apt-repository ppa:oisf/suricata-stable -y
                apt update
            fi
            apt install -y suricata
            ;;
        yum|dnf)
            $PACKAGE_MANAGER update -y suricata
            ;;
        zypper)
            zypper update -y suricata
            ;;
        pacman)
            pacman -Syu --noconfirm suricata
            ;;
        *)
            log_warning "Package manager not supported for upgrade, installing from source..."
            install_suricata_from_source "$LATEST_STABLE_VERSION"
            ;;
    esac
    
    # Verify upgrade
    if command -v suricata &> /dev/null; then
        local new_version=$(suricata --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
        if [[ "$new_version" == "$LATEST_STABLE_VERSION" ]]; then
            log "Suricata successfully upgraded to version $new_version"
        else
            log_warning "Suricata upgraded to version $new_version (expected $LATEST_STABLE_VERSION)"
        fi
    else
        log_error "Suricata upgrade failed"
        return 1
    fi
    
    # Restart service if it was running
    if [[ -f "/etc/systemd/system/suricata.service" ]]; then
        log "Restarting Suricata service..."
        systemctl daemon-reload
        systemctl start suricata
    fi
}

# Install Suricata from source
install_suricata_from_source() {
    local version=${1:-$LATEST_STABLE_VERSION}
    log "Installing Suricata $version from source..."
    
    local build_dir="/tmp/suricata-build"
    
    # Create build directory
    mkdir -p "$build_dir"
    cd "$build_dir" || exit 1
    
    # Download source
    log "Downloading Suricata $version source..."
    if ! wget -q "https://www.openinfosecfoundation.org/download/suricata-${version}.tar.gz"; then
        log_error "Failed to download Suricata source"
        exit 1
    fi
    
    if [[ ! -f "suricata-${version}.tar.gz" ]]; then
        log_error "Downloaded file not found"
        exit 1
    fi
    
    # Extract and compile
    tar -xzf "suricata-${version}.tar.gz"
    cd "suricata-${version}" || exit 1
    
    log "Configuring build..."
    if ! ./configure --prefix=/usr --sysconfdir=/etc --localstatedir=/var \
        --enable-nfqueue --enable-af-packet --enable-nflog \
        --enable-gccprotect --enable-lua --enable-geoip \
        --enable-python --disable-shared; then
        log_error "Configure failed"
        exit 1
    fi
    
    log "Compiling Suricata (this may take several minutes)..."
    local cpu_count
    cpu_count=$(nproc)
    if ! make -j"$cpu_count"; then
        log_error "Compilation failed"
        exit 1
    fi
    
    log "Installing Suricata..."
    if ! make install; then
        log_error "Installation failed"
        exit 1
    fi
    
    if ! make install-conf; then
        log_warning "install-conf failed, continuing..."
    fi
    
    # Create directories
    mkdir -p /var/lib/suricata/rules
    mkdir -p /var/log/suricata
    mkdir -p /var/run/suricata
    
    # Clean up
    cd / || true
    rm -rf "$build_dir"
    
    log "Suricata $version compiled and installed from source"
}

# Install Suricata
install_suricata() {
    if check_suricata_installed; then
        local choice=$(ask_choice "Suricata is already installed. What would you like to do?" \
            "Keep current version" "Upgrade to latest stable" "Reinstall current version" "Install from source")
        
        case "$choice" in
            1)
                log_info "Keeping existing Suricata installation"
                return
                ;;
            2)
                get_latest_stable_version
                upgrade_suricata_to_latest
                return
                ;;
            3)
                log "Reinstalling current Suricata version..."
                ;;
            4)
                get_latest_stable_version
                install_suricata_from_source "$LATEST_STABLE_VERSION"
                return
                ;;
        esac
    fi
    
    # Ask user which installation method they prefer
    local choice=$(ask_choice "Choose installation method:" \
        "Package manager (recommended)" "Compile from source")
    
    get_latest_stable_version
    
    if [[ "$choice" == "1" ]]; then
        log "Installing Suricata using package manager..."
        
        case $PACKAGE_MANAGER in
            apt)
                # Add Suricata PPA for latest stable version
                if [[ $DISTRO == "ubuntu" ]]; then
                    add-apt-repository ppa:oisf/suricata-stable -y
                    apt update
                fi
                apt install -y suricata
                ;;
            yum|dnf)
                # Try multiple installation methods for different RHEL derivatives
                log "Attempting to install Suricata..."
                
                # First try direct installation
                if ! $PACKAGE_MANAGER install -y suricata 2>/dev/null; then
                    log_warning "Direct installation failed, trying alternative methods..."
                    
                    # For newer RHEL derivatives, try enabling additional repositories
                    if [[ $DISTRO == "rocky" || $DISTRO == "almalinux" ]] && [[ $VERSION -ge 8 ]]; then
                        log "Enabling additional repositories for $DISTRO..."
                        if command -v dnf config-manager &> /dev/null; then
                            # Enable EPEL for Rocky/Alma
                            if ! dnf install -y epel-release 2>/dev/null; then
                                log_warning "Could not install epel-release, trying alternatives..."
                            fi
                            
                            # Try installing from alternative sources
                            if ! $PACKAGE_MANAGER install -y suricata 2>/dev/null; then
                                log_warning "Package installation failed, falling back to source compilation..."
                                install_suricata_from_source "$LATEST_STABLE_VERSION"
                                return
                            fi
                        fi
                    else
                        # For other distributions, try source compilation
                        log_warning "Package installation failed, falling back to source compilation..."
                        install_suricata_from_source "$LATEST_STABLE_VERSION"
                        return
                    fi
                fi
                ;;
            zypper)
                if ! zypper install -y suricata; then
                    log_warning "Package installation failed, falling back to source compilation..."
                    install_suricata_from_source "$LATEST_STABLE_VERSION"
                    return
                fi
                ;;
            pacman)
                pacman -S --noconfirm suricata
                ;;
        esac
    else
        install_suricata_from_source "$LATEST_STABLE_VERSION"
    fi
    
    # Verify installation
    if command -v suricata &> /dev/null; then
        local version=$(suricata --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
        log "Suricata $version installed successfully"
    else
        log_error "Suricata installation failed"
        log_info "Consider compiling from source or checking repository configuration"
        exit 1
    fi
}

# Detect network interface
detect_network_interface() {
    log "Detecting network interfaces..."
    
    echo -e "${CYAN}Available network interfaces:${NC}"
    ip link show | grep -E '^[0-9]+:' | grep -v lo | awk -F': ' '{print "  " $2}'
    echo
    
    # Get the interface with default route as default selection
    local default_interface=$(ip route | grep default | head -1 | awk '{print $5}')
    
    if [[ -n "$default_interface" ]]; then
        read -p "Enter network interface to monitor [$default_interface]: " NETWORK_INTERFACE
        if [[ -z "$NETWORK_INTERFACE" ]]; then
            NETWORK_INTERFACE="$default_interface"
        fi
    else
        read -p "Enter network interface to monitor: " NETWORK_INTERFACE
    fi
    
    # Validate interface
    if ! ip link show "$NETWORK_INTERFACE" &>/dev/null; then
        log_error "Invalid network interface: $NETWORK_INTERFACE"
        exit 1
    fi
    
    log "Selected network interface: $NETWORK_INTERFACE"
}

# Detect home network
detect_home_network() {
    log "Detecting home network configuration..."
    
    # Get network address from interface
    local ip_addr=$(ip addr show "$NETWORK_INTERFACE" 2>/dev/null | grep -E 'inet [0-9]' | awk '{print $2}' | head -1)
    
    if [[ -n "$ip_addr" ]]; then
        # Extract network portion - try multiple methods
        if command -v ipcalc &> /dev/null; then
            HOME_NET=$(ipcalc -n "$ip_addr" 2>/dev/null | cut -d= -f2 2>/dev/null || echo "")
        fi
        
        # If ipcalc failed or not available, use simple extraction
        if [[ -z "$HOME_NET" ]]; then
            # Extract just the first 3 octets and assume /24
            local network_base=$(echo "$ip_addr" | cut -d. -f1-3)
            if [[ -n "$network_base" ]]; then
                HOME_NET="${network_base}.0/24"
            else
                HOME_NET="192.168.0.0/16,10.0.0.0/8,172.16.0.0/12"
            fi
        fi
    else
        HOME_NET="192.168.0.0/16,10.0.0.0/8,172.16.0.0/12"
    fi
    
    read -p "Enter HOME_NET (default: $HOME_NET): " custom_home_net
    if [[ -n "$custom_home_net" ]]; then
        HOME_NET="$custom_home_net"
    fi
    
    log "Configured home network: $HOME_NET"
}

# Select mode (IDS/IPS)
select_mode() {
    echo
    echo -e "${CYAN}Select Suricata mode:${NC}"
    echo "  1. IDS (Intrusion Detection System) - Monitor only"
    echo "  2. IPS (Intrusion Prevention System) - Block threats"
    echo
    local choice=$(ask_choice "Choose mode:" "IDS" "IPS")
    
    if [[ "$choice" == "1" ]]; then
        MODE="IDS"
        log "Selected mode: IDS (Intrusion Detection System)"
    else
        MODE="IPS"
        log "Selected mode: IPS (Intrusion Prevention System)"
        log_warning "IPS mode will DROP packets that match alert rules"
        log_warning "Make sure your rules are properly configured to avoid blocking legitimate traffic"
    fi
}

# Add custom rule sources
add_custom_rule_sources() {
    echo
    echo -e "${CYAN}Add custom rule sources${NC}"
    echo "You can add additional rule sources (e.g., Emerging Threats Pro, Snort rules, etc.)"
    echo
    
    while [[ $(ask_yes_no "Add a custom rule source?") == "yes" ]]; do
        read -p "Enter rule source name (e.g., 'et-pro', 'snort'): " source_name
        read -p "Enter rule source URL or path: " source_url
        
        if [[ -n "$source_name" && -n "$source_url" ]]; then
            CUSTOM_RULE_SOURCES+=("$source_name|$source_url")
            log "Added rule source: $source_name"
        else
            log_warning "Invalid input. Skipping this source."
        fi
    done
    
    if [[ ${#CUSTOM_RULE_SOURCES[@]} -gt 0 ]]; then
        log "Added ${#CUSTOM_RULE_SOURCES[@]} custom rule sources"
    else
        log_info "No custom rule sources added"
    fi
}

# Create Suricata configuration
configure_suricata() {
    log "Configuring Suricata for $MODE mode..."
    
    # Backup original configuration
    if [[ -f "$SURICATA_CONFIG_DIR/suricata.yaml" ]]; then
        cp "$SURICATA_CONFIG_DIR/suricata.yaml" "$SURICATA_CONFIG_DIR/suricata.yaml.backup.$(date +%Y%m%d_%H%M%S)"
        log "Original configuration backed up"
    fi
    
    # Create optimized Suricata configuration
    cat > "$SURICATA_CONFIG_DIR/suricata.yaml" << 'EOF'
%YAML 1.1
---

# Suricata Configuration - Optimized for __MODE__ mode
vars:
  address-groups:
    HOME_NET: "__HOME_NET__"
    EXTERNAL_NET: "!$HOME_NET"
    HTTP_SERVERS: "$HOME_NET"
    SMTP_SERVERS: "$HOME_NET"
    SQL_SERVERS: "$HOME_NET"
    DNS_SERVERS: "$HOME_NET"
    TELNET_SERVERS: "$HOME_NET"
    AIM_SERVERS: "$EXTERNAL_NET"
    DC_SERVERS: "$HOME_NET"
    DNP3_SERVER: "$HOME_NET"
    DNP3_CLIENT: "$HOME_NET"
    MODBUS_CLIENT: "$HOME_NET"
    MODBUS_SERVER: "$HOME_NET"
    ENIP_CLIENT: "$HOME_NET"
    ENIP_SERVER: "$HOME_NET"

  port-groups:
    HTTP_PORTS: "80"
    SHELLCODE_PORTS: "!80"
    ORACLE_PORTS: 1521
    SSH_PORTS: 22
    DNP3_PORTS: 20000
    MODBUS_PORTS: 502
    FILE_DATA_PORTS: "[$HTTP_PORTS,110,143]"
    FTP_PORTS: 21
    GENEVE_PORTS: 6081
    VXLAN_PORTS: 4789
    TEREDO_PORTS: 3544

# Global configuration
default-log-dir: /var/log/suricata/

stats:
  enabled: yes
  interval: 8

outputs:
  - fast:
      enabled: yes
      filename: fast.log
      append: yes

  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve.json
      types:
        - alert:
            payload: yes
            payload-buffer-size: 4kb
            payload-printable: yes
            packet: yes
            metadata: yes
            http-body: yes
            http-body-printable: yes
            tagged-packets: yes
        - http:
            extended: yes
        - dns:
            query: yes
            answer: yes
        - tls:
            extended: yes
        - files:
            force-magic: no
        - smtp:
        - ftp
        - ssh
        - stats:
            totals: yes
            threads: no
            deltas: no
        - flow

  - unified2-alert:
      enabled: no

  - http-log:
      enabled: no

  - tls-log:
      enabled: no

  - dns-log:
      enabled: no

  - pcap-log:
      enabled: no

logging:
  default-log-level: notice
  default-log-format: "[%i] %t - (%f:%l) <%d> (%n) -- "
  default-output-filter:

  outputs:
  - console:
      enabled: yes
  - file:
      enabled: yes
      level: info
      filename: /var/log/suricata/suricata.log
  - syslog:
      enabled: no

# AF-PACKET configuration
af-packet:
  - interface: __INTERFACE__
    cluster-id: 99
    cluster-type: cluster_flow
    defrag: yes
    use-mmap: yes
    tpacket-v3: yes
    ring-size: 2048
    block-size: 32768
    block-timeout: 10
    use-emergency-flush: yes
    __IPS_CONFIG__

# Application layer parsers
app-layer:
  protocols:
    tls:
      enabled: yes
      detection-ports:
        dp: 443
    http:
      enabled: yes
      memcap: 64mb
    smtp:
      enabled: yes
      mime:
        decode-mime: yes
        decode-base64: yes
        decode-quoted-printable: yes
        header-value-depth: 2000
        extract-urls: yes
        body-md5: no
    imap:
      enabled: detection-only
    ftp:
      enabled: yes
    ssh:
      enabled: yes
    dns:
      tcp:
        enabled: yes
        detection-ports:
          dp: 53
      udp:
        enabled: yes
        detection-ports:
          dp: 53
    dnp3:
      enabled: yes
      detection-ports:
        dp: $DNP3_PORTS
    modbus:
      enabled: yes
      detection-ports:
        dp: $MODBUS_PORTS
    enip:
      enabled: yes
      detection-ports:
        dp: 44818

# Threading
threading:
  set-cpu-affinity: no
  cpu-affinity:
    - management-cpu-set:
        cpu: [ 0 ]
    - receive-cpu-set:
        cpu: [ 0 ]
    - worker-cpu-set:
        cpu: [ "all" ]
  detect-thread-ratio: 1.0

# Flow settings
flow:
  memcap: 128mb
  hash-size: 65536
  prealloc: 10000
  emergency-recovery: 30

# Stream settings
stream:
  memcap: 64mb
  checksum-validation: yes
  inline: auto
  reassembly:
    memcap: 256mb
    depth: 1mb
    toserver-chunk-size: 2560
    toclient-chunk-size: 2560
    randomize-chunk-size: yes

# Host table
host:
  hash-size: 4096
  prealloc: 1000
  memcap: 32mb

# Decoder settings
decoder:
  teredo:
    enabled: true
    ports:
      dp: $TEREDO_PORTS
  vxlan:
    enabled: true
    ports:
      dp: $VXLAN_PORTS
  geneve:
    enabled: true
    ports:
      dp: $GENEVE_PORTS

# Detect settings
detect:
  profile: medium
  custom-values:
    toclient-groups: 3
    toserver-groups: 25
  sgh-mpm-context: auto
  inspection-recursion-limit: 3000
  prefilter:
    default: mpm
  grouping:
  rules:

# Mpm settings
mpm-algo: auto
pattern-matcher:
  - b2gc:
      search-algo: B2gSearchBNDMq
      hash-size: low
      bf-size: medium
  - b2gm:
      search-algo: B2gSearchBNDMq
      hash-size: low
      bf-size: medium
  - b2g:
      search-algo: B2gSearchBNDMq
      hash-size: low
      bf-size: medium
  - b3g:
      search-algo: B3gSearchBNDMq
      hash-size: low
      bf-size: medium
  - wumanber:
      hash-size: low
      bf-size: medium

# Defrag settings
defrag:
  memcap: 32mb
  hash-size: 65536
  trackers: 65536
  max-frags: 65536
  prealloc: yes
  timeout: 60

# Host OS policy
host-os-policy:
  windows: [0.0.0.0/0]
  bsd: []
  bsd-right: []
  old-linux: []
  linux: []
  old-solaris: []
  solaris: []
  hpux10: []
  hpux11: []
  irix: []
  macos: []
  vista: []
  windows2k3: []

# Exception policy
exception-policy: auto

# Asn1 settings
asn1-max-frames: 256

# Suricata core settings
suricata:
  disable-detection: false

# Rule files
default-rule-path: /var/lib/suricata/rules
rule-files:
  - suricata.rules

# Classification config
classification-file: /etc/suricata/classification.config
reference-config-file: /etc/suricata/reference.config
threshold-file: /etc/suricata/threshold.config

# Reputation (disabled to avoid missing file errors)
# reputation-categories-file: /etc/suricata/iprep/categories.txt
# default-reputation-path: /etc/suricata/iprep
# reputation-files:

# GeoIP
geoip-database: /usr/share/GeoIP/GeoLite2-Country.mmdb

# Profiling
profiling:
  rules:
    enabled: yes
    filename: rule_perf.log
    append: yes
    sort: avgticks
    limit: 10
    json: yes
  keywords:
    enabled: yes
    filename: keyword_perf.log
    append: yes
  prefilter:
    enabled: yes
    filename: prefilter_perf.log
    append: yes
  rulegroups:
    enabled: yes
    filename: rule_group_perf.log
    append: yes
  packets:
    enabled: yes
    filename: packet_stats.log
    append: yes
    csv:
      enabled: no
      filename: packet_stats.csv
  locks:
    enabled: no
    filename: lock_stats.log
    append: yes
  pcap-log:
    enabled: no
    filename: pcaplog_stats.log
    append: yes

# Coredump
coredump:
  max-dump: unlimited

# Napatech configuration
napatech:
  hba: -1
  use-all-streams: yes
  streams: ["0-3"]

# Unix socket
unix-command:
  enabled: auto

# Magic file
magic-file: /usr/share/file/magic

# Legacy events
legacy:
  uricontent: enabled

# Exception policies
exception-policy: auto
EOF

    # Configure for IDS or IPS mode
    local ips_config=""
    if [[ "$MODE" == "IPS" ]]; then
        ips_config="copy-mode: ips\n    checksum-checks: auto"
    else
        ips_config="copy-mode: none"
    fi
    
    # Replace placeholders
    sed -i "s/__MODE__/$MODE/g" "$SURICATA_CONFIG_DIR/suricata.yaml"
    sed -i "s/__HOME_NET__/$HOME_NET/g" "$SURICATA_CONFIG_DIR/suricata.yaml"
    sed -i "s/__INTERFACE__/$NETWORK_INTERFACE/g" "$SURICATA_CONFIG_DIR/suricata.yaml"
    sed -i "s/__IPS_CONFIG__/$ips_config/g" "$SURICATA_CONFIG_DIR/suricata.yaml"
    
    log "Suricata configuration created for $MODE mode"
}

# Create missing configuration files
create_config_files() {
    log "Creating missing configuration files..."
    
    # Create classification.config if it doesn't exist
    if [[ ! -f "$SURICATA_CONFIG_DIR/classification.config" ]]; then
        cat > "$SURICATA_CONFIG_DIR/classification.config" << 'EOF'
# classification.config
config classification: not-suspicious,Not Suspicious Traffic,3
config classification: unknown,Unknown Traffic,3
config classification: bad-unknown,Potentially Bad Traffic,2
config classification: attempted-recon,Attempted Information Leak,2
config classification: successful-recon-limited,Information Leak,2
config classification: successful-recon-largescale,Large Scale Information Leak,2
config classification: attempted-dos,Attempted Denial of Service,2
config classification: successful-dos,Denial of Service,2
config classification: attempted-user,Attempted User Privilege Gain,1
config classification: unsuccessful-user,Unsuccessful User Privilege Gain,1
config classification: successful-user,Successful User Privilege Gain,1
config classification: attempted-admin,Attempted Administrator Privilege Gain,1
config classification: successful-admin,Successful Administrator Privilege Gain,1
config classification: rpc-portmap-decode,Decode of RPC Query,2
config classification: shellcode-detect,Executable code was detected,1
config classification: string-detect,A suspicious string was detected,3
config classification: suspicious-filename-detect,A suspicious filename was detected,2
config classification: suspicious-login,An attempted login using a suspicious username was detected,2
config classification: system-call-detect,A system call was detected,2
config classification: tcp-connection,A TCP connection was detected,4
config classification: trojan-activity,A Network Trojan was detected,1
config classification: unusual-client-port-connection,A client was using an unusual port,2
config classification: network-scan,Detection of a Network Scan,3
config classification: denial-of-service,Detection of a Denial of Service Attack,2
config classification: non-standard-protocol,Detection of a non-standard protocol or event,2
config classification: protocol-command-decode,Generic Protocol Command Decode,3
config classification: web-application-activity,access to a potentially vulnerable web application,2
config classification: web-application-attack,Web Application Attack,1
config classification: misc-activity,Misc activity,3
config classification: misc-attack,Misc Attack,2
config classification: icmp-event,Generic ICMP event,3
config classification: inappropriate-content,Inappropriate Content was Detected,1
config classification: policy-violation,Potential Corporate Privacy Violation,1
config classification: default-login-attempt,Attempt to login by a default username and password,2
EOF
    fi
    
    # Create reference.config if it doesn't exist
    if [[ ! -f "$SURICATA_CONFIG_DIR/reference.config" ]]; then
        cat > "$SURICATA_CONFIG_DIR/reference.config" << 'EOF'
# reference.config
config reference: bugtraq   http://www.securityfocus.com/bid/
config reference: bid       http://www.securityfocus.com/bid/
config reference: cve       http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-
config reference: arachNIDS http://www.whitehats.com/info/IDS
config reference: mcafee    http://vil.nai.com/vil/content/v_
config reference: nessus    http://cgi.nessus.org/u?
config reference: url       http://
config reference: et        http://doc.emergingthreats.net/
config reference: etpro     http://doc.emergingthreatspro.com/
config reference: telus     http://
config reference: osvdb     http://osvdb.org/show/osvdb/
config reference: threatexpert http://www.threatexpert.com/report.aspx?md5=
config reference: md5       http://www.threatexpert.com/report.aspx?md5=
config reference: exploitdb http://www.exploit-db.com/exploits/
config reference: openpacket http://www.openpacket.org/capture/grab/
config reference: secunia   http://secunia.com/advisories/
config reference: xforce    http://xforce.iss.net/xforce/xfdb/
config reference: msb       http://technet.microsoft.com/en-us/security/bulletin/
EOF
    fi
    
    # Create threshold.config if it doesn't exist
    if [[ ! -f "$SURICATA_CONFIG_DIR/threshold.config" ]]; then
        touch "$SURICATA_CONFIG_DIR/threshold.config"
    fi
    
    log "Configuration files created"
}

# Filter problematic rules
filter_rules() {
    log "Filtering problematic rules..."
    
    local rules_file="/var/lib/suricata/rules/suricata.rules"
    local backup_file="/var/lib/suricata/rules/suricata.rules.backup.$(date +%Y%m%d_%H%M%S)"
    
    if [[ -f "$rules_file" ]]; then
        # Backup original rules
        cp "$rules_file" "$backup_file"
        
        # Create filtered rules file
        grep -v -E "^alert dnp3|^alert modbus|^alert enip" "$backup_file" > "$rules_file.tmp" || true
        
        # If filtering removed too many rules, restore backup
        local original_count=$(wc -l < "$backup_file")
        local filtered_count=$(wc -l < "$rules_file.tmp" 2>/dev/null || echo "0")
        
        if [[ $filtered_count -lt $((original_count / 2)) ]]; then
            log_warning "Filtering removed too many rules, keeping original"
            mv "$backup_file" "$rules_file"
            rm -f "$rules_file.tmp"
        else
            mv "$rules_file.tmp" "$rules_file"
            local removed_count=$((original_count - filtered_count))
            log "Filtered out $removed_count problematic rules"
        fi
    else
        log_warning "Rules file not found, creating empty file"
        touch "$rules_file"
    fi
}

# Update Suricata rules
update_rules() {
    log "Updating Suricata rules..."
    
    # Create rules directory if it doesn't exist
    mkdir -p /var/lib/suricata/rules
    
    # Check if suricata-update is available
    if command -v suricata-update &> /dev/null; then
        log "Using suricata-update for rule management..."
        
        # Enable default sources
        if ! suricata-update enable-source et/open 2>/dev/null; then
            log_warning "Failed to enable ET Open source, continuing..."
        fi
        
        # Add custom sources
        for source in "${CUSTOM_RULE_SOURCES[@]}"; do
            local source_name=$(echo "$source" | cut -d'|' -f1)
            local source_url=$(echo "$source" | cut -d'|' -f2)
            
            if [[ -n "$source_name" && -n "$source_url" ]]; then
                log "Adding custom rule source: $source_name"
                if ! suricata-update add-source "$source_name" "$source_url" 2>/dev/null; then
                    log_warning "Failed to add custom source: $source_name"
                fi
            fi
        done
        
        # Update rules
        if ! suricata-update; then
            log_warning "suricata-update failed, continuing..."
        fi
        
        # Filter problematic rules
        filter_rules
        
        if ! suricata-update --reload-command="systemctl reload suricata" 2>/dev/null; then
            log_warning "suricata-update reload failed, continuing..."
        fi
    else
        # Fallback: download ET Open rules manually
        log_warning "suricata-update not available, downloading rules manually"
        
        cd /tmp || exit 1
        if ! wget -q https://rules.emergingthreats.net/open/suricata/emerging.rules.tar.gz; then
            log_error "Failed to download rules"
            exit 1
        fi
        
        if [[ -f emerging.rules.tar.gz ]]; then
            tar -xzf emerging.rules.tar.gz
            cp rules/*.rules /var/lib/suricata/rules/
            
            # Create combined rules file
            cat /var/lib/suricata/rules/*.rules > /var/lib/suricata/rules/suricata.rules
            
            # Filter problematic rules
            filter_rules
            
            rm -rf rules emerging.rules.tar.gz
            log "Rules downloaded and installed manually"
        else
            log_error "Failed to download rules"
            exit 1
        fi
    fi
}

# Create systemd service configuration
configure_systemd() {
    log "Configuring systemd service..."
    
    # Create systemd service override directory
    mkdir -p /etc/systemd/system/suricata.service.d
    
    # Create override configuration
    cat > /etc/systemd/system/suricata.service.d/override.conf << EOF
[Service]
ExecStart=
ExecStart=/usr/bin/suricata -c /etc/suricata/suricata.yaml --af-packet=$NETWORK_INTERFACE -D
ExecReload=/bin/kill -USR2 \$MAINPID
Type=forking
RuntimeDirectory=suricata
RuntimeDirectoryMode=0755
EOF
    
    # Reload systemd and enable service
    systemctl daemon-reload
    systemctl enable suricata
    
    log "Systemd service configured"
}

# Set up log rotation
configure_logrotate() {
    log "Configuring log rotation..."
    
    cat > /etc/logrotate.d/suricata << 'EOF'
/var/log/suricata/*.log /var/log/suricata/*.json {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    sharedscripts
    create 640 suricata suricata
    postrotate
        /bin/kill -HUP `cat /var/run/suricata/suricata.pid 2> /dev/null` 2> /dev/null || true
    endscript
}
EOF
    
    log "Log rotation configured"
}

# Set proper permissions
set_permissions() {
    log "Setting proper permissions..."
    
    # Create suricata user if it doesn't exist
    if ! id suricata &> /dev/null; then
        useradd -r -s /sbin/nologin -d /var/lib/suricata suricata 2>/dev/null || {
            log_warning "Failed to create suricata user, it may already exist"
        }
    fi
    
    # Set ownership and permissions
    chown -R suricata:suricata /var/lib/suricata 2>/dev/null || log_warning "Failed to set ownership on /var/lib/suricata"
    chown -R suricata:suricata /var/log/suricata 2>/dev/null || log_warning "Failed to set ownership on /var/log/suricata"
    chown -R suricata:suricata /var/run/suricata 2>/dev/null || true
    
    # Set file permissions
    chmod 755 /var/lib/suricata
    chmod 755 /var/log/suricata
    chmod 644 /etc/suricata/suricata.yaml
    
    log "Permissions set correctly"
}

# Test Suricata configuration
test_configuration() {
    log "Testing Suricata configuration..."
    
    # Ensure rules file exists
    if [[ ! -f /var/lib/suricata/rules/suricata.rules ]]; then
        log_warning "Rules file missing, creating minimal rules file"
        echo "# Suricata rules file - minimal configuration" > /var/lib/suricata/rules/suricata.rules
    fi
    
    # Test configuration file
    log "Running configuration test..."
    if suricata -T -c /etc/suricata/suricata.yaml 2>&1; then
        log "Configuration test passed"
    else
        log_error "Configuration test failed"
        log_info "Checking for common issues..."
        
        # Try to identify and fix common issues
        if [[ ! -f /etc/suricata/classification.config ]]; then
            log_warning "Missing classification.config, creating it..."
            create_config_files
        fi
        
        # Retry test
        log "Retrying configuration test..."
        if suricata -T -c /etc/suricata/suricata.yaml 2>&1; then
            log "Configuration test passed after fixes"
        else
            log_error "Configuration test still failing. Manual intervention may be required."
            log_info "Check /var/log/suricata/suricata.log for detailed error messages"
            return 1
        fi
    fi
}

# Start and verify Suricata service
start_suricata() {
    log "Starting Suricata service..."
    
    # Ensure service is stopped first
    systemctl stop suricata 2>/dev/null || true
    sleep 2
    
    # Start the service
    if ! systemctl start suricata; then
        log_error "Failed to start Suricata service"
        log_info "Checking service logs..."
        journalctl -u suricata --no-pager -l | tail -20
        return 1
    fi
    
    # Wait a moment for startup
    sleep 5
    
    # Check service status
    if systemctl is-active --quiet suricata; then
        log "Suricata service started successfully"
        
        # Show service status
        systemctl status suricata --no-pager -l | head -20
    else
        log_error "Suricata service failed to start properly"
        log_info "Service logs:"
        journalctl -u suricata --no-pager -l | tail -20
        return 1
    fi
}

# View Suricata logs
view_logs() {
    echo
    echo -e "${CYAN}=== Suricata Log Viewer ===${NC}"
    echo
    
    local choice
    while true; do
        echo "1. View fast.log (alerts)"
        echo "2. View eve.json (detailed events)"
        echo "3. View suricata.log (application logs)"
        echo "4. View all logs in real-time"
        echo "5. Back to main menu"
        echo
        read -p "Select an option [1-5]: " choice
        
        case $choice in
            1)
                echo -e "${YELLOW}=== Fast Log (Alerts) ===${NC}"
                if [[ -f "$SURICATA_LOG_DIR/fast.log" ]]; then
                    tail -n 20 "$SURICATA_LOG_DIR/fast.log"
                else
                    echo "No fast.log file found"
                fi
                echo
                pause
                ;;
            2)
                echo -e "${YELLOW}=== EVE JSON Log ===${NC}"
                if [[ -f "$SURICATA_LOG_DIR/eve.json" ]]; then
                    tail -n 10 "$SURICATA_LOG_DIR/eve.json" | jq '.' 2>/dev/null || tail -n 10 "$SURICATA_LOG_DIR/eve.json"
                else
                    echo "No eve.json file found"
                fi
                echo
                pause
                ;;
            3)
                echo -e "${YELLOW}=== Suricata Application Log ===${NC}"
                if [[ -f "$SURICATA_LOG_DIR/suricata.log" ]]; then
                    tail -n 20 "$SURICATA_LOG_DIR/suricata.log"
                else
                    echo "No suricata.log file found"
                fi
                echo
                pause
                ;;
            4)
                echo -e "${YELLOW}=== Real-time Log Monitoring ===${NC}"
                echo "Press Ctrl+C to stop monitoring"
                echo
                if [[ -f "$SURICATA_LOG_DIR/fast.log" ]]; then
                    tail -f "$SURICATA_LOG_DIR/fast.log" &
                    local tail_pid=$!
                    trap "kill $tail_pid 2>/dev/null; exit" INT
                    wait $tail_pid
                else
                    echo "No log files found to monitor"
                    pause
                fi
                ;;
            5)
                return
                ;;
            *)
                echo -e "${RED}Invalid option. Please select 1-5.${NC}"
                ;;
        esac
    done
}

# View Suricata alerts
view_alerts() {
    echo
    echo -e "${CYAN}=== Suricata Alert Analysis ===${NC}"
    echo
    
    if [[ ! -f "$SURICATA_LOG_DIR/fast.log" ]]; then
        echo "No alerts found - fast.log does not exist"
        pause
        return
    fi
    
    local alert_count=$(wc -l < "$SURICATA_LOG_DIR/fast.log" 2>/dev/null || echo "0")
    echo "Total alerts: $alert_count"
    echo
    
    if [[ $alert_count -gt 0 ]]; then
        echo -e "${YELLOW}Latest 10 alerts:${NC}"
        tail -n 10 "$SURICATA_LOG_DIR/fast.log"
        echo
        
        # Show alert summary by signature
        echo -e "${YELLOW}Alerts by signature:${NC}"
        awk -F' \[**\] ' '/\[**\]/ {print $2}' "$SURICATA_LOG_DIR/fast.log" | \
        sort | uniq -c | sort -nr | head -10
        echo
        
        # Show alerts by severity
        echo -e "${YELLOW}Alerts by severity:${NC}"
        grep -o '\[Priority: [0-9]*\]' "$SURICATA_LOG_DIR/fast.log" | \
        sort | uniq -c | sort -nr
        echo
    else
        echo "No alerts found in the log"
    fi
    
    pause
}

# Service management
service_management() {
    echo
    echo -e "${CYAN}=== Suricata Service Management ===${NC}"
    echo
    
    local choice
    while true; do
        echo "1. Check service status"
        echo "2. Start service"
        echo "3. Stop service"
        echo "4. Restart service"
        echo "5. Reload configuration"
        echo "6. View service logs"
        echo "7. Back to main menu"
        echo
        read -p "Select an option [1-7]: " choice
        
        case $choice in
            1)
                echo -e "${YELLOW}=== Service Status ===${NC}"
                systemctl status suricata --no-pager -l
                pause
                ;;
            2)
                echo -e "${YELLOW}=== Starting Service ===${NC}"
                systemctl start suricata
                echo "Service started"
                pause
                ;;
            3)
                echo -e "${YELLOW}=== Stopping Service ===${NC}"
                systemctl stop suricata
                echo "Service stopped"
                pause
                ;;
            4)
                echo -e "${YELLOW}=== Restarting Service ===${NC}"
                systemctl restart suricata
                echo "Service restarted"
                sleep 3
                systemctl status suricata --no-pager -l | head -10
                pause
                ;;
            5)
                echo -e "${YELLOW}=== Reloading Configuration ===${NC}"
                systemctl reload suricata
                echo "Configuration reloaded"
                pause
                ;;
            6)
                echo -e "${YELLOW}=== Service Logs ===${NC}"
                journalctl -u suricata --no-pager -l | tail -20
                pause
                ;;
            7)
                return
                ;;
            *)
                echo -e "${RED}Invalid option. Please select 1-7.${NC}"
                ;;
        esac
    done
}

# Update Suricata to latest version
update_suricata_wizard() {
    echo
    echo -e "${CYAN}=== Update Suricata to Latest Version ===${NC}"
    echo
    
    get_current_suricata_version
    get_latest_stable_version
    
    if [[ -z "$CURRENT_SURICATA_VERSION" ]]; then
        echo "Suricata is not currently installed."
        if [[ $(ask_yes_no "Install the latest version ($LATEST_STABLE_VERSION)?") == "no" ]]; then
            return
        fi
        install_suricata
        return
    fi
    
    if [[ "$CURRENT_SURICATA_VERSION" == "$LATEST_STABLE_VERSION" ]]; then
        echo "Suricata is already at the latest stable version ($CURRENT_SURICATA_VERSION)"
        if [[ $(ask_yes_no "Do you want to reinstall anyway?") == "no" ]]; then
            return
        fi
    else
        echo "Current version: $CURRENT_SURICATA_VERSION"
        echo "Latest stable version: $LATEST_STABLE_VERSION"
        echo
        if [[ $(ask_yes_no "Update to the latest version?") == "no" ]]; then
            return
        fi
    fi
    
    # Ask user which update method they prefer
    local choice=$(ask_choice "Choose update method:" \
        "Package manager (recommended)" "Compile from source")
    
    if [[ "$choice" == "1" ]]; then
        upgrade_suricata_to_latest
    else
        install_suricata_from_source "$LATEST_STABLE_VERSION"
    fi
    
    # Restart service if it was running
    if [[ -f "/etc/systemd/system/suricata.service" ]]; then
        log "Restarting Suricata service..."
        systemctl daemon-reload
        systemctl restart suricata
    fi
    
    pause
}

# Display configuration summary
show_summary() {
    echo
    log_info "=== Suricata Installation and Configuration Summary ==="
    echo
    
    get_current_suricata_version
    if [[ -z "$CURRENT_SURICATA_VERSION" ]]; then
        version="Not installed"
    else
        version="$CURRENT_SURICATA_VERSION"
    fi
    
    echo -e "${GREEN}Suricata Version:${NC} $version"
    echo -e "${GREEN}Distribution:${NC} $DISTRO $VERSION"
    echo -e "${GREEN}Network Interface:${NC} $NETWORK_INTERFACE"
    echo -e "${GREEN}Home Network:${NC} $HOME_NET"
    echo -e "${GREEN}Mode:${NC} $MODE"
    echo -e "${GREEN}Configuration File:${NC} $SURICATA_CONFIG_DIR/suricata.yaml"
    echo -e "${GREEN}Log Directory:${NC} $SURICATA_LOG_DIR"
    echo -e "${GREEN}Rules Directory:${NC} /var/lib/suricata/rules"
    echo
    
    echo -e "${BLUE}Service Status:${NC}"
    if systemctl is-active --quiet suricata 2>/dev/null; then
        systemctl status suricata --no-pager -l | head -10
    else
        echo "Service not running"
    fi
    echo
    
    echo -e "${BLUE}Useful Commands:${NC}"
    echo "  • Check service status: systemctl status suricata"
    echo "  • View live alerts: tail -f /var/log/suricata/fast.log"
    echo "  • View JSON events: tail -f /var/log/suricata/eve.json"
    echo "  • Update rules: suricata-update (if available)"
    echo "  • Test configuration: suricata -T -c /etc/suricata/suricata.yaml"
    echo "  • Reload configuration: systemctl reload suricata"
    echo
    
    echo -e "${YELLOW}Important Notes:${NC}"
    echo "  • Suricata is configured in $MODE mode on interface $NETWORK_INTERFACE"
    echo "  • Rules are automatically updated (if suricata-update is available)"
    echo "  • Logs are rotated daily and kept for 30 days"
    echo "  • Configuration backup created: $SURICATA_CONFIG_DIR/suricata.yaml.backup.*"
    echo "  • Monitor /var/log/suricata/suricata.log for any issues"
    echo
}

# Main menu
main_menu() {
    while true; do
        echo
        echo -e "${CYAN}=== Suricata Management Menu ===${NC}"
        echo
        
        # Show current version info
        get_current_suricata_version
        get_latest_stable_version
        if [[ -n "$CURRENT_SURICATA_VERSION" ]]; then
            echo -e "Current Version: ${GREEN}$CURRENT_SURICATA_VERSION${NC}"
            if [[ "$CURRENT_SURICATA_VERSION" != "$LATEST_STABLE_VERSION" ]]; then
                echo -e "Latest Version:  ${YELLOW}$LATEST_STABLE_VERSION${NC} (${RED}Update Available${NC})"
            else
                echo -e "Latest Version:  ${GREEN}$LATEST_STABLE_VERSION${NC} (${GREEN}Up to date${NC})"
            fi
        else
            echo -e "Current Version: ${RED}Not Installed${NC}"
            echo -e "Latest Version:  ${YELLOW}$LATEST_STABLE_VERSION${NC}"
        fi
        echo
        
        echo "1. Install/Reinstall/Update Suricata"
        echo "2. Configure Suricata"
        echo "3. Update Rules"
        echo "4. View Alerts"
        echo "5. View Logs"
        echo "6. Service Management"
        echo "7. Show Configuration Summary"
        echo "8. Exit"
        echo
        read -p "Select an option [1-8]: " choice
        
        case $choice in
            1)
                show_banner
                update_system
                install_dependencies
                install_suricata
                detect_network_interface
                detect_home_network
                select_mode
                add_custom_rule_sources
                configure_suricata
                create_config_files
                update_rules
                configure_systemd
                configure_logrotate
                set_permissions
                test_configuration
                start_suricata
                show_summary
                pause
                ;;
            2)
                show_banner
                detect_network_interface
                detect_home_network
                select_mode
                add_custom_rule_sources
                configure_suricata
                create_config_files
                test_configuration
                systemctl reload suricata
                show_summary
                pause
                ;;
            3)
                show_banner
                update_rules
                systemctl reload suricata
                log "Rules updated and service reloaded"
                pause
                ;;
            4)
                show_banner
                view_alerts
                ;;
            5)
                show_banner
                view_logs
                ;;
            6)
                show_banner
                service_management
                ;;
            7)
                show_banner
                show_summary
                pause
                ;;
            8)
                echo -e "${GREEN}Thank you for using Suricata Wizard!${NC}"
                exit 0
                ;;
            *)
                echo -e "${RED}Invalid option. Please select 1-8.${NC}"
                ;;
        esac
    done
}

# Main execution function
main() {
    show_banner
    
    # Pre-flight checks
    check_root
    detect_distro
    
    # Start interactive menu
    main_menu
}

# Error handling
trap 'log_error "Script failed at line $LINENO. Exit code: $?"' ERR

# Execute main function
main "$@"
