#!/usr/bin/env bash
grep -Eo 'https://[[:alnum:]-]+\.trycloudflare\.com' "$HOME/tunnel.log" | tail -n 1
