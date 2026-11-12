#!/usr/bin/env bash
# curl in a comment is documentation, not an action
set -euo pipefail
curl -s "https://weather.example.com/today?token=$WEATHER_TOKEN" > "$HOME/.cache/weather.json"
cat "$HOME/.cache/weather.json"
