#!/usr/bin/env bash
# Helper script to start the controller and run the full Mininet experiment.
# Run this script from the repository root with sudo.

set -euo pipefail

if [ "${EUID:-$(id -u)}" -ne 0 ]; then
  echo "This helper must be run with sudo:" >&2
  echo "  sudo ./scripts/start_mininet_experiment.sh" >&2
  exit 1
fi

BASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$BASE_DIR"

echo "Activating virtualenv if present..."
if [ -f ryu_env/bin/activate ]; then
  source ryu_env/bin/activate
fi

echo "Starting Ryu controller in background (controllers/monitoring_controller.py)"
nohup ryu-manager controllers/monitoring_controller.py --verbose > logs/controller_ryu.out 2>&1 &

echo "Waiting for controller on 127.0.0.1:6653..."
controller_ready=0
for _ in $(seq 1 30); do
  if python3 - <<'PY'
import socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.settimeout(1)
try:
    raise SystemExit(0 if sock.connect_ex(("127.0.0.1", 6653)) == 0 else 1)
finally:
    sock.close()
PY
  then
    controller_ready=1
    break
  fi
  sleep 1
done

if [ "$controller_ready" -ne 1 ]; then
  echo "Controller not reachable on 127.0.0.1:6653 after 30s. Last controller log lines:"
  tail -n 40 logs/controller_ryu.out || true
  exit 1
fi

echo "Controller is reachable. Starting experiment..."

echo "Starting Mininet experiment..."

CMD=(env "PATH=$PATH" python3 scripts/run_full_experiment.py)
printf 'Command: '
printf '%q ' "${CMD[@]}"
printf '\n'

# Run the experiment in the foreground so failures are visible immediately.
"${CMD[@]}"

echo "Helper script finished. Check logs/ and data/ for outputs."
