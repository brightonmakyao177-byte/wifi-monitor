#!/usr/bin/env bash
# Run the monitor in the background whenever you're logged in.
#   ./install.sh              install or update, and start
#   ./install.sh --uninstall  stop and remove the service (keeps your history)
set -euo pipefail

app_dir="$HOME/.local/share/wifi-monitor"
unit="$HOME/.config/systemd/user/wifi-monitor.service"

if [[ "${1:-}" == "--uninstall" ]]; then
    systemctl --user disable --now wifi-monitor.service 2>/dev/null || true
    rm -f "$unit" "$app_dir/wifimon.py" "$app_dir/dashboard.html"
    systemctl --user daemon-reload
    echo "Removed. Your history is still in $app_dir/devices.db"
    exit 0
fi

source_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
mkdir -p "$app_dir" "$(dirname "$unit")"
install -m 644 "$source_dir/wifimon.py" "$source_dir/dashboard.html" "$app_dir/"

cat > "$unit" <<EOF
[Unit]
Description=Wi-Fi device monitor

[Service]
ExecStart=/usr/bin/python3 $app_dir/wifimon.py
Restart=on-failure
RestartSec=10

[Install]
WantedBy=default.target
EOF

systemctl --user daemon-reload
systemctl --user enable wifi-monitor.service
systemctl --user restart wifi-monitor.service
echo "Running. Dashboard: http://127.0.0.1:8765"
