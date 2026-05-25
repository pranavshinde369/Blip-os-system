#!/usr/bin/env bash
# Blip — Start everything
# Usage: ./start.sh          → boots backend + frontend
#        ./start.sh demo     → boots everything + fires demo events
#        ./start.sh agent    → also starts mitmproxy agent
#        ./start.sh clip     → also starts clipboard watcher

set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

RED='\033[0;31m'; AMBER='\033[0;33m'; GREEN='\033[0;32m'; NC='\033[0m'; BOLD='\033[1m'

echo ""
echo -e "${BOLD}🛡️  Blip — GenAI Firewall${NC}"
echo -e "    NovaTech Solutions · WitchHunt 2026"
echo "    ────────────────────────────────────"

# ── Check Python ─────────────────────────────────────────────────────────────
if ! command -v python3 &>/dev/null; then
  echo -e "${RED}✗ python3 not found${NC}"; exit 1
fi

# ── Install Python deps ───────────────────────────────────────────────────────
echo -e "\n${AMBER}[1/4] Installing Python dependencies…${NC}"
pip3 install -q -r "$SCRIPT_DIR/requirements.txt"

# ── Install frontend deps ─────────────────────────────────────────────────────
echo -e "${AMBER}[2/4] Installing frontend dependencies…${NC}"
cd "$SCRIPT_DIR/frontend" && npm install --silent && cd "$SCRIPT_DIR"

# ── Start FastAPI backend ─────────────────────────────────────────────────────
echo -e "${AMBER}[3/4] Starting Blip backend (port 8000)…${NC}"
cd "$SCRIPT_DIR/backend"
BLIP_POLICIES_DIR="$SCRIPT_DIR/policies" \
  python3 -m uvicorn main:app --host 0.0.0.0 --port 8000 --reload &
BACKEND_PID=$!
cd "$SCRIPT_DIR"

# Wait for backend to be ready
echo -n "    Waiting for backend"
for i in {1..20}; do
  sleep 1; echo -n "."
  if curl -sf http://localhost:8000/health >/dev/null 2>&1; then
    echo -e " ${GREEN}ready${NC}"; break
  fi
done

# ── Start React frontend ──────────────────────────────────────────────────────
echo -e "${AMBER}[4/4] Starting SOC dashboard (port 5173)…${NC}"
cd "$SCRIPT_DIR/frontend" && npm run dev &
FRONTEND_PID=$!
cd "$SCRIPT_DIR"

# ── Optional: mitmproxy agent ─────────────────────────────────────────────────
if [[ "$1" == "agent" || "$2" == "agent" ]]; then
  echo -e "\n${AMBER}Starting network interceptor on port 8080…${NC}"
  mitmdump -s "$SCRIPT_DIR/agent/blip_agent.py" --listen-port 8080 --quiet &
  echo -e "${GREEN}  Set system proxy: localhost:8080${NC}"
fi

# ── Optional: clipboard watcher ───────────────────────────────────────────────
if [[ "$1" == "clip" || "$2" == "clip" ]]; then
  echo -e "\n${AMBER}Starting clipboard watcher…${NC}"
  python3 "$SCRIPT_DIR/agent/clipboard_watcher.py" &
fi

# ── Optional: demo simulation ─────────────────────────────────────────────────
if [[ "$1" == "demo" ]]; then
  sleep 3
  echo -e "\n${AMBER}Running demo simulation…${NC}"
  python3 "$SCRIPT_DIR/demo_sim.py"
fi

echo ""
echo -e "${GREEN}${BOLD}✅ Blip is running!${NC}"
echo -e "   SOC Dashboard : ${BOLD}http://localhost:5173${NC}"
echo -e "   Backend API   : http://localhost:8000"
echo -e "   API Docs      : http://localhost:8000/docs"
echo ""
echo "   Press Ctrl+C to stop all services."

# Graceful shutdown
trap "echo ''; echo 'Stopping Blip…'; kill $BACKEND_PID $FRONTEND_PID 2>/dev/null; exit 0" INT TERM
wait
