#!/usr/bin/env bash
# Wrapper: runs checkin.py only. Telegram notifications disabled per user
# request 2026-10-05 (keep checkin running, stay silent on fail/success).
set -u
cd "$(dirname "$0")"

python checkin.py 2>&1
# Always exit 0 so the workflow stays green and silent; check logs for JSON.
exit 0