#!/usr/bin/env bash
# Wrapper: runs checkin.py, parses its NOTIFY_ marker, sends Telegram only
# when there's something worth reporting (real sign-in or failure).
set -u
cd "$(dirname "$0")"

OUT=$(python checkin.py 2>&1)
echo "$OUT"

FLAG=$(echo "$OUT" | grep -oE 'NOTIFY_[A-Z]+' | tail -1)
if [ -z "$FLAG" ] || [ "$FLAG" = "NOTIFY_NONE" ]; then
  # everyone already checked in - stay silent
  exit 0
fi

# Build a compact message from the JSON result lines
MSG="$(echo "$OUT" | grep '^{' | head -20)"
if [ "$FLAG" = "NOTIFY_ALERT" ]; then
  TEXT="⚠️ APK.TW 簽到異常，需要處理！\n$MSG"
else
  TEXT="✅ APK.TW 簽到完成\n$MSG"
fi

curl -s --max-time 20 "https://api.telegram.org/bot${TG_TOKEN}/sendMessage" \
  -d chat_id="$TG_CHAT" --data-urlencode "text=$TEXT" > /dev/null