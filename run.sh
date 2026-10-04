#!/usr/bin/env bash
# Hourly checkin wrapper (2026-10-05: B digest mode).
# - Success / first failures: silent.
# - Telegram alert only after 3 CONSECUTIVE failures of the same account,
#   then re-alert every 24 consecutive failures (once a day max).
# - Counters live in .session/fail_N.count, persisted via Actions cache.
set -u
cd "$(dirname "$0")"
mkdir -p .session

OUT=$(python checkin.py 2>&1)
echo "$OUT"
THRESHOLD=3
ALERT_ACCOUNTS=""

# JSON result lines come in account order (1,2); pull "ok" in order.
mapfile -t OKS < <(echo "$OUT" | grep '^{' | grep -oE '"ok": ?(true|false)' | grep -oE '(true|false)')
for i in 0 1; do
  N=$((i + 1))
  OK="${OKS[$i]:-true}"
  CNT_FILE=".session/fail_${N}.count"
  if [ "$OK" = "true" ]; then
    rm -f "$CNT_FILE"
  else
    CNT=0
    [ -f "$CNT_FILE" ] && CNT=$(cat "$CNT_FILE" 2>/dev/null || echo 0)
    CNT=$((CNT + 1))
    echo "$CNT" > "$CNT_FILE"
    if [ "$CNT" -ge "$THRESHOLD" ] && [ $(((CNT - THRESHOLD) % 24)) -eq 0 ]; then
      ALERT_ACCOUNTS="$ALERT_ACCOUNTS $N($CNT)"
    fi
  fi
done

if [ -n "$ALERT_ACCOUNTS" ]; then
  MSG="$(echo "$OUT" | grep '^{' | head -20)"
  TEXT="⚠️ APK.TW 連續簽到失敗（帳號:$ALERT_ACCOUNTS，需重導 cookie）\n$MSG"
  curl -s --max-time 20 "https://api.telegram.org/bot${TG_TOKEN}/sendMessage" \
    -d chat_id="$TG_CHAT" --data-urlencode "text=$TEXT" > /dev/null
fi

# Always exit 0: workflow stays green; failures surface via digest TG above.
exit 0
