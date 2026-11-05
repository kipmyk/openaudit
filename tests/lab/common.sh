#!/bin/bash
# Hardened baseline applied inside every disposable lab container before a
# scenario introduces its specific misconfiguration.
set -eu

# --- SSH daemon configuration (file only; sshd is not started) ---
mkdir -p /etc/ssh/sshd_config.d
rm -f /etc/ssh/sshd_config.d/*.conf
cat > /etc/ssh/sshd_config <<'EOF'
Include /etc/ssh/sshd_config.d/*.conf
Port 22
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
X11Forwarding no
MaxAuthTries 4
EOF
chmod 0644 /etc/ssh/sshd_config

# --- Critical file permissions and account state ---
chmod 0644 /etc/passwd
chmod 0644 /etc/group
chown root:shadow /etc/shadow
chmod 0640 /etc/shadow
chmod 0440 /etc/sudoers

gpasswd -d ubuntu sudo 2>/dev/null || true
gpasswd -d alice sudo 2>/dev/null || true
gpasswd -d bob sudo 2>/dev/null || true
chsh -s /usr/sbin/nologin www-data 2>/dev/null || true

# --- Kernel hardening baseline ---
mkdir -p /tmp/proc-fake
echo 0 > /tmp/proc-fake/zero && mount --bind /tmp/proc-fake/zero /proc/sys/net/ipv4/ip_forward 2>/dev/null || true
echo 1 > /tmp/proc-fake/one && mount --bind /tmp/proc-fake/one /proc/sys/kernel/dmesg_restrict 2>/dev/null || true
echo 2 > /tmp/proc-fake/two && mount --bind /tmp/proc-fake/two /proc/sys/kernel/randomize_va_space 2>/dev/null || true

# --- Firewall: ufw removed from PATH unless scenario keeps it; nftables active ---
if [ "${KEEP_UFW:-0}" != "1" ]; then
    mv /usr/sbin/ufw /usr/sbin/ufw.lab-disabled 2>/dev/null || true
fi
nft flush ruleset
nft add table inet filter
nft add chain inet filter input '{ type filter hook input priority 0; policy drop; }'
nft add rule inet filter input iif lo accept

# --- Helper: start a TCP listener. Usage: listen <4|6> <addr> <port> [process-name]
listen() {
    local exe=python3
    if [ -n "${4:-}" ]; then
        cp "$(command -v python3)" "/usr/local/bin/$4"
        exe="/usr/local/bin/$4"
    fi
    "$exe" - "$1" "$2" "$3" <<'PY' &
import socket, sys, time
fam = socket.AF_INET6 if sys.argv[1] == "6" else socket.AF_INET
s = socket.socket(fam, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((sys.argv[2], int(sys.argv[3])))
s.listen()
time.sleep(3600)
PY
    sleep 1
}

# --- Helper: start a UDP listener. Usage: listen_udp <4|6> <addr> <port>
listen_udp() {
    python3 - "$1" "$2" "$3" <<'PY' &
import socket, sys, time
fam = socket.AF_INET6 if sys.argv[1] == "6" else socket.AF_INET
s = socket.socket(fam, socket.SOCK_DGRAM)
s.bind((sys.argv[2], int(sys.argv[3])))
time.sleep(3600)
PY
    sleep 1
}

