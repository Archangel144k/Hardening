#!/bin/bash

echo "🔧 Setting up secure homelab access with firewalld and NordVPN"

# Prompt for subnet(s)
read -p "📡 Enter the subnet(s) to allow through VPN (e.g. 10.0.0.0/24, comma-separated if multiple): " INPUT_SUBNETS
IFS=',' read -ra SUBNETS <<< "$INPUT_SUBNETS"

# Standard ports for Proxmox and common services
ALLOWED_PORTS=(22 443 5601 8006)

# Backup firewalld config
BACKUP_DIR="$HOME/firewalld_backups"
TIMESTAMP=$(date +"%Y-%m-%d_%H-%M-%S")
mkdir -p "$BACKUP_DIR"
echo "📦 Backing up firewalld config to $BACKUP_DIR/firewalld_backup_$TIMESTAMP.tar.gz"
sudo tar -czf "$BACKUP_DIR/firewalld_backup_$TIMESTAMP.tar.gz" /etc/firewalld
echo "✅ Backup complete."

# Create homelab zone if not present
if ! sudo firewall-cmd --get-zones | grep -q "homelab"; then
  echo "🧱 Creating firewalld 'homelab' zone..."
  sudo firewall-cmd --permanent --new-zone=homelab
fi

# Add subnets to homelab zone
for SUBNET in "${SUBNETS[@]}"; do
  TRIMMED_SUBNET=$(echo "$SUBNET" | xargs)
  echo "📍 Adding subnet $TRIMMED_SUBNET to 'homelab' zone"
  sudo firewall-cmd --permanent --zone=homelab --add-source="$TRIMMED_SUBNET"

  echo "🌐 Whitelisting $TRIMMED_SUBNET in NordVPN..."
  nordvpn whitelist add subnet "$TRIMMED_SUBNET"
done

# Add common ports to homelab zone
for PORT in "${ALLOWED_PORTS[@]}"; do
  echo "🔓 Allowing TCP port $PORT in homelab zone..."
  sudo firewall-cmd --permanent --zone=homelab --add-port=${PORT}/tcp
done

# Reload firewalld to apply changes
sudo firewall-cmd --reload
echo "✅ Firewalld reloaded."

# Ask about disabling Kill Switch
read -p "🛡 Do you want to disable NordVPN Kill Switch to ensure lab access? (y/N): " disable_kill
if [[ "$disable_kill" =~ ^[Yy]$ ]]; then
  nordvpn set killswitch off
  echo "⚠️ Kill Switch disabled."
else
  echo "🔐 Kill Switch remains ON. Make sure whitelisting works properly."
fi

# Final output
echo -e "\n✅ Setup complete. Your homelab traffic should now be accessible even while NordVPN is active."
echo "📜 Subnets added:"
for SUBNET in "${SUBNETS[@]}"; do
  echo " - $(echo "$SUBNET" | xargs)"
done

echo -e "\n🔍 Current homelab zone ports:"
sudo firewall-cmd --list-ports --zone=homelab

echo -e "\n🌍 Current NordVPN whitelist:"
nordvpn whitelist list
