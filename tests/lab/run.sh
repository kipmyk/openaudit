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
    *) echo "unknown scenario $ID" >&2; exit 2 ;;
esac

set +e
if [ "$RUN_AS" = "root" ]; then
    "$BIN" audit local --format json > "/out/$ID.json" 2> "/out/$ID.err"
else
    su -s /bin/bash "$RUN_AS" -c "$BIN audit local --format json" > "/out/$ID.json" 2> "/out/$ID.err"
fi
echo $? > "/out/$ID.exit"

