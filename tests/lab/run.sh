#!/bin/bash
# Executes one lab scenario inside a disposable container, then runs the
# OpenAudit binary and writes its JSON report to /out/<ID>.json.
#
# Usage: bash /lab/run.sh <SCENARIO_ID>
set -eu
ID="$1"
BIN=/opt/openaudit/openaudit-cli
RUN_AS=root

[ "$ID" = "S10" ] && export KEEP_UFW=1
# shellcheck source=common.sh
source /lab/common.sh

SSHD=/etc/ssh/sshd_config
case "$ID" in
    S00|S00b) ;; # hardened baseline (S00b repeats it for determinism checks)
    S01) sed -i 's/^PermitRootLogin no/PermitRootLogin yes/' "$SSHD" ;;
    S02) sed -i 's/^PasswordAuthentication no/PasswordAuthentication yes/' "$SSHD" ;;
    S03) sed -i '/^PasswordAuthentication/d' "$SSHD" ;;
    S04) echo 'PermitRootLogin yes' > /etc/ssh/sshd_config.d/50-override.conf ;;
    S05) sed -i 's/^PermitRootLogin no/PermitRootLogin yes\nPermitRootLogin no/' "$SSHD" ;;
    S06) sed -i 's/^PermitRootLogin no/PermitRootLogin no\nPermitRootLogin yes/' "$SSHD" ;;
    S07) echo 'toor:x:0:0:backdoor:/root:/bin/bash' >> /etc/passwd
         echo 'toor:*:19000:0:99999:7:::' >> /etc/shadow ;;
    S08) usermod -p '' alice ;;
    S09) nft flush ruleset ;;
    S10) ;; # ufw installed but inactive; nftables actively filtering
    S11) RUN_AS=auditor ;;
    S12) listen 4 0.0.0.0 6379 ;;
    S13) listen 6 :: 3306 ;;
    S14) listen 4 0.0.0.0 5432; listen 4 0.0.0.0 27017 ;;
    S15) listen 4 0.0.0.0 6380 redis-server ;;
    S16) chmod 0644 /etc/shadow ;;
    S17) chmod 0666 /etc/passwd ;;
    S18) echo 'alice ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/90-lab
         chmod 0666 /etc/sudoers.d/90-lab ;;
    S19) mkdir -p /etc/cron.d && chmod 0777 /etc/cron.d ;;
    S20) listen 4 127.0.0.1 6379 ;;
    S21) chmod 0666 /etc/sudoers ;;
    S22) chmod 0644 /etc/shadow; chmod 0666 /etc/passwd ;;
    S23) chmod 0666 "$SSHD" ;;
    S24) sed -i 's/^X11Forwarding no/X11Forwarding yes/' "$SSHD" ;;
    S25) sed -i 's/^MaxAuthTries 4/MaxAuthTries 10/' "$SSHD" ;;
    S26) sed -i '/^MaxAuthTries/d' "$SSHD" ;;
    S27) chsh -s /bin/bash www-data ;;
    S28) chsh -s /usr/sbin/nologin www-data ;;
    S29) echo 'alice ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers ;;
    S30) echo 'bob ALL=(ALL) NOPASSWD:/bin/bash' > /etc/sudoers.d/90-bob && chmod 0440 /etc/sudoers.d/90-bob ;;
    S31) ;; # hardened sudoers control
    S32) usermod -aG sudo alice ;;
    S33) ;; # hardened sudo group control
    S34) chmod 0666 /etc/group ;;
    S35) chmod 0644 /etc/group ;;
    S36) nft flush ruleset
         iptables -F
         iptables -P INPUT DROP
         iptables -A INPUT -i lo -j ACCEPT
         iptables -A INPUT -m state --state ESTABLISHED -j ACCEPT ;;
    S37) nft flush ruleset
         iptables -F
         iptables -P INPUT ACCEPT ;;
    S38) listen 4 0.0.0.0 22 ;;
    S39) listen 4 127.0.0.1 22 ;;
    S40) listen_udp 4 0.0.0.0 53 ;;
    S41) listen_udp 4 127.0.0.1 53 ;;
    S42) listen 4 0.0.0.0 8080 ;;
    S43) cp /bin/bash /tmp/setuid-bash && chmod 4755 /tmp/setuid-bash ;;
    S44) ;; # standard SUID control
    S45) cp /bin/cat /tmp/shadow-reader && chmod 2755 /tmp/shadow-reader ;;
    S46) ;; # standard SGID control
    S47) mkdir -p /tmp/evil && chmod 0777 /tmp/evil && export PATH="/tmp/evil:$PATH" ;;
    S48) ;; # hardened PATH control
    S49) echo 0 > /tmp/val && mount --bind /tmp/val /proc/sys/kernel/dmesg_restrict ;;
    S50) echo 1 > /tmp/val && mount --bind /tmp/val /proc/sys/kernel/dmesg_restrict ;;
    S51) echo 1 > /tmp/val && mount --bind /tmp/val /proc/sys/net/ipv4/ip_forward ;;
    S52) echo 0 > /tmp/val && mount --bind /tmp/val /proc/sys/net/ipv4/ip_forward ;;
    S53) echo 0 > /tmp/val && mount --bind /tmp/val /proc/sys/kernel/randomize_va_space ;;
    *) echo "unknown scenario $ID" >&2; exit 2 ;;
esac

set +e
if [ "$RUN_AS" = "root" ]; then
    "$BIN" audit local --format json > "/out/$ID.json" 2> "/out/$ID.err"
else
    su -s /bin/bash "$RUN_AS" -c "$BIN audit local --format json" > "/out/$ID.json" 2> "/out/$ID.err"
fi
echo $? > "/out/$ID.exit"

