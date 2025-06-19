#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

INSTALL_WAZUH=false
MODE="ids"
CHECK_ONLY=false

usage() {
  cat <<EOF
Usage: $0 [--mode ids|ips] [--with-wazuh] [--check]
  --mode       Mode to run Suricata: ids (default) or ips
  --with-wazuh Also install and configure Wazuh agent
  --check      Syntax and basic logic check only (no changes)
EOF
  exit 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --mode)
      shift
      [[ "$1" =~ ^(ids|ips)$ ]] || { echo "Invalid mode: $1" >&2; usage; }
      MODE="$1"; shift ;;
    --with-wazuh) INSTALL_WAZUH=true; shift ;;
    --check) CHECK_ONLY=true; shift ;;
    -h|--help) usage ;;
    *) echo "Unknown option: $1" >&2; usage ;;
  esac
done

log()   { echo -e "[INFO] $*"; }
error() { echo -e "[ERROR] $*" >&2; exit 1; }

if [[ "$CHECK_ONLY" == true ]]; then
  log "Running syntax check (bash -n)"
  bash -n "$0" || error "Syntax errors detected"
  log "No syntax errors found"
  if command -v shellcheck >/dev/null 2>&1; then
    log "Running shellcheck"
    shellcheck "$0" || echo "Shellcheck warnings/errors detected"
  fi
  exit 0
fi

detect_os() {
  if [[ -e /etc/os-release ]]; then
    . /etc/os-release
    OS_ID=$ID
    OS_VER_ID=$VERSION_ID
  else
    error "Cannot detect operating system."
  fi
  case "$OS_ID" in
    ubuntu|debian)
      PKG_UPDATE=(apt-get update)
      PKG_INSTALL=(apt-get install -y)
      ;;  
    rhel|centos|almalinux|rocky|fedora)
      PKG_UPDATE=(dnf makecache -y)
      PKG_INSTALL=(dnf install -y --skip-broken)
      ;;  
    *) error "Unsupported OS: $OS_ID";;
  esac
  log "Detected OS: $PRETTY_NAME"
}

install_deps() {
  log "Updating package lists..."
  "${PKG_UPDATE[@]}"

  log "Installing dependencies..."
  "${PKG_INSTALL[@]}" curl gnupg2 lsb-release iproute iptables-nft || true
  if [[ "$OS_ID" =~ (ubuntu|debian) ]]; then
    "${PKG_INSTALL[@]}" software-properties-common
  fi
}

is_suricata_installed() {
  command -v suricata >/dev/null 2>&1
}

is_suricata_configured() {
  grep -q "enabled: yes" /etc/suricata/suricata.yaml 2>/dev/null
}

install_suricata() {
  if is_suricata_installed; then
    log "Suricata is already installed."
    if ! is_suricata_configured; then
      read -rp "Suricata is not configured. Do you want to configure it now? [y/N]: " ans
      [[ "$ans" =~ ^[Yy]$ ]] && { detect_interface; configure_suricata; }
    else
      log "Suricata is already configured. Skipping."
    fi
    return
  fi

  log "Installing Suricata..."
  if [[ "$OS_ID" =~ (debian|ubuntu) ]]; then
    add-apt-repository -y ppa:oisf/suricata-stable
    "${PKG_UPDATE[@]}"
    "${PKG_INSTALL[@]}" suricata
  else
    "${PKG_INSTALL[@]}" epel-release || true
    "${PKG_INSTALL[@]}" suricata
  fi
}

detect_interface() {
  IFACE=$(ip -o link show up | awk -F': ' '/state UP/ {print $2}' | grep -v lo | head -n1)
  [[ -n "$IFACE" ]] || error "No active network interface found."
  log "Using interface: $IFACE"
}

configure_suricata() {
  SC_CFG=/etc/suricata/suricata.yaml
  [[ -f "$SC_CFG" ]] || error "Suricata config not found at $SC_CFG"

  log "Backing up original config"
  cp -p "$SC_CFG" "${SC_CFG}.bak-$(date +%F_%T)"

  if [[ "$MODE" == "ids" ]]; then
    log "Configuring Suricata in IDS mode (af-packet)"
    sed -ri '/^af-packet:/,/^  - interface:/ s/^enabled:.*/enabled: yes/' "$SC_CFG"
    sed -ri "s#( *- interface:).*#\1 $IFACE#" "$SC_CFG"
    sed -ri '/^nfqueue:/,/^  queue:/ s/^enabled:.*/enabled: no/' "$SC_CFG"
  else
    log "Configuring Suricata in IPS mode (NFQUEUE)"
    sed -ri '/^af-packet:/,/^  - interface:/ s/^enabled:.*/enabled: no/' "$SC_CFG"
    sed -ri '/^nfqueue:/,/^  queue:/ s/^enabled:.*/enabled: yes/' "$SC_CFG"
    sed -ri 's#( *queue:).*#\1 0#' "$SC_CFG"
    log "Inserting iptables NFQUEUE rules"
    iptables -I INPUT -i "$IFACE" -j NFQUEUE --queue-num 0 || error "Failed to insert INPUT rule"
    iptables -I FORWARD -i "$IFACE" -j NFQUEUE --queue-num 0 || error "Failed to insert FORWARD rule"
  fi

  log "Enabling and starting Suricata service"
  systemctl enable suricata
  systemctl restart suricata
  systemctl status suricata --no-pager
}

is_wazuh_installed() {
  systemctl list-units --type=service | grep -q wazuh-agent.service
}

install_wazuh() {
  if is_wazuh_installed; then
    log "Wazuh agent is already installed."
    if ! grep -q "<address>127.0.0.1</address>" /var/ossec/etc/ossec.conf 2>/dev/null; then
      read -rp "Wazuh agent is not fully configured. Configure now? [y/N]: " ans
      [[ "$ans" =~ ^[Yy]$ ]] && {
        sed -i 's@<address>.*</address>@<address>127.0.0.1</address>@' /var/ossec/etc/ossec.conf
        systemctl restart wazuh-agent
      }
    else
      log "Wazuh agent is already configured. Skipping."
    fi
    return
  fi

  log "Installing Wazuh agent..."
  if [[ "$OS_ID" =~ (debian|ubuntu) ]]; then
    curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | apt-key add -
    echo "deb https://packages.wazuh.com/4.x/apt/ stable main" | tee /etc/apt/sources.list.d/wazuh.list
    "${PKG_UPDATE[@]}"
    "${PKG_INSTALL[@]}" wazuh-agent
  else
    cat >/etc/yum.repos.d/wazuh.repo <<EOL
[wazuh_repo]
name=Wazuh repository
baseurl=https://packages.wazuh.com/4.x/yum/
enabled=1
gpgcheck=1
gpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH
EOL
    "${PKG_INSTALL[@]}" wazuh-agent
  fi

  log "Configuring Wazuh agent address (modify manager_address as needed)"
  sed -i 's@<address>.*</address>@<address>127.0.0.1</address>@' /var/ossec/etc/ossec.conf

  log "Enabling and starting Wazuh agent"
  systemctl enable wazuh-agent
  systemctl restart wazuh-agent
  systemctl status wazuh-agent --no-pager
}

main() {
  detect_os
  install_deps
  install_suricata
  detect_interface
  configure_suricata

  if $INSTALL_WAZUH; then
    install_wazuh
  fi

  log "All tasks completed successfully."
}

main "$@"

