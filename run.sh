#!/usr/bin/env bash
# Hourly checkin wrapper (2026-10-05: success-only notify per user request).
# - Any account newly signed -> Telegram success message.
# - Failures / already-signed days: silent.
set -u
cd "$(dirname "$0")"

OUT=$(python checkin.py 2>&1)
echo "$OUT"

FLAG=$(echo "$OUT" | grep -oE 'NOTIFY_[A-Z]+' | tail -1)
if [ "$FLAG" = "NOTIFY_SIGNED" ]; then
  MSG="$(echo "$OUT" | grep '^{' | head -20)"
  TEXT="✅ APK.TW 簽到完成\n$MSG"
  curl -s --max-time 20 "https://api.telegram.org/bot${TG_TOKEN}/sendMessage" \
    -d chat_id="$TG_CHAT" --data-urlencode "text=$TEXT" > /dev/null
fi

# Always exit 0 so the workflow stays green; check logs for JSON.
exit 0
