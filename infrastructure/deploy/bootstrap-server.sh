#!/usr/bin/env bash
# One-time hardening of a fresh Ubuntu 24.04 server. Run as root:
#   ssh root@<ip> 'bash -s' < infrastructure/deploy/bootstrap-server.sh
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

apt-get update -q
apt-get upgrade -yq
apt-get install -yq ca-certificates curl ufw fail2ban unattended-upgrades rsync jq

# Docker Engine + Compose plugin from Docker's apt repository
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
. /etc/os-release
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu ${VERSION_CODENAME} stable" \
  > /etc/apt/sources.list.d/docker.list
apt-get update -q
apt-get install -yq docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
systemctl enable --now docker

# Deploy user with the same SSH key as root; owns /opt/siem
id siem >/dev/null 2>&1 || useradd --create-home --shell /bin/bash --groups docker siem
install -d -m 700 -o siem -g siem /home/siem/.ssh
install -m 600 -o siem -g siem /root/.ssh/authorized_keys /home/siem/.ssh/authorized_keys
install -d -o siem -g siem /opt/siem

# SSH: keys only, no root password login
sed -i -E 's/^#?PasswordAuthentication .*/PasswordAuthentication no/; s/^#?PermitRootLogin .*/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config
systemctl reload ssh

# Firewall: SSH + HTTP(S) only. (Only the Caddy container publishes ports, on 80/443.)
ufw default deny incoming
ufw default allow outgoing
ufw allow OpenSSH
ufw allow 80/tcp
ufw allow 443/tcp
ufw allow 443/udp
ufw --force enable

systemctl enable --now fail2ban
dpkg-reconfigure -f noninteractive unattended-upgrades

# 4 GB swap as headroom for the Maven/npm image builds
if ! swapon --show | grep -q /swapfile; then
  fallocate -l 4G /swapfile && chmod 600 /swapfile && mkswap /swapfile && swapon /swapfile
  echo '/swapfile none swap sw 0 0' >> /etc/fstab
fi

echo "Bootstrap complete: docker $(docker --version | cut -d' ' -f3 | tr -d ,), user 'siem', firewall on (22, 80, 443)."
