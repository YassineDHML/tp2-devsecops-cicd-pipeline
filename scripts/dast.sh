#!/usr/bin/env bash
# DAST sur environnement ephemere (Docker) : deploiement, scan OWASP ZAP, gate, destruction.
#
#   bash scripts/dast.sh deploy    cree un reseau Docker et y lance l'application (image $IMAGE)
#   bash scripts/dast.sh scan      scan ZAP authentifie (spider + scan actif), rapports dans $OUT_DIR
#   bash scripts/dast.sh gate      echoue (code 1) si une alerte atteint le niveau $FAIL_ON
#   bash scripts/dast.sh destroy   supprime le conteneur et le reseau (a lancer meme apres un echec)
#   bash scripts/dast.sh all       enchaine les quatre etapes (usage local)
#
# Le workflow GitHub Actions appelle chaque etape separement pour qu'elles soient
# visibles dans l'interface ; en local, "all" reproduit exactement le meme parcours.
set -euo pipefail

# Git Bash (Windows) convertit les chemins POSIX passes aux programmes natifs, ce qui
# casserait les montages de volumes : on desactive cette conversion pour docker uniquement.
docker() { MSYS_NO_PATHCONV=1 command docker "$@"; }

IMAGE="${IMAGE:-notes-app:ci}"
NETWORK="${DAST_NETWORK:-dast-net}"
APP_NAME="${DAST_APP_NAME:-app}"          # nom DNS de l'application dans le reseau (voir zap/automation.yaml)
APP_PORT="${DAST_APP_PORT:-5000}"         # port publie sur 127.0.0.1 pour les controles de disponibilite
ZAP_IMAGE="${ZAP_IMAGE:-ghcr.io/zaproxy/zaproxy:2.17.0}"
OUT_DIR="${OUT_DIR:-zap-out}"
FAIL_ON="${FAIL_ON:-high}"
PYTHON="${PYTHON:-python3}"
STATE_DIR="${RUNNER_TEMP:-${TMPDIR:-/tmp}}"
CRED_FILE="$STATE_DIR/dast-credentials.env"

if pwd -W >/dev/null 2>&1; then ROOT="$(pwd -W)"; else ROOT="$(pwd)"; fi

deploy() {
  # Idempotent : repart d'un environnement vierge meme apres un essai local interrompu
  docker rm -f "$APP_NAME" >/dev/null 2>&1 || true
  docker network rm "$NETWORK" >/dev/null 2>&1 || true
  docker network create "$NETWORK" >/dev/null
  mkdir -p "$OUT_DIR"

  # Secrets generes a la volee : rien n'est ecrit dans le depot ni dans l'image.
  local zap_password secret_key
  zap_password="$(openssl rand -hex 16)"
  secret_key="$(openssl rand -hex 32)"
  (umask 077; printf 'ZAP_USER=zap-tester\nZAP_PASSWORD=%s\n' "$zap_password" > "$CRED_FILE")

  docker run -d --name "$APP_NAME" --network "$NETWORK" \
    -p "127.0.0.1:${APP_PORT}:5000" -e SECRET_KEY="$secret_key" "$IMAGE" >/dev/null

  echo "Attente de la disponibilite de l'application..."
  for _ in $(seq 1 40); do
    if curl -fsS -o /dev/null "http://127.0.0.1:${APP_PORT}/login" 2>/dev/null; then break; fi
    sleep 2
  done
  curl -fsS -o /dev/null "http://127.0.0.1:${APP_PORT}/login"
  echo "Application disponible sur le reseau '$NETWORK' (http://${APP_NAME}:5000)."

  # Compte de test pour le scan authentifie (base SQLite vierge, detruite avec l'environnement)
  curl -fsS -o /dev/null -w 'Creation du compte de test -> HTTP %{http_code}\n' \
    --data-urlencode "username=zap-tester" --data-urlencode "password=$zap_password" \
    "http://127.0.0.1:${APP_PORT}/register"
}

scan() {
  set -a; . "$CRED_FILE"; set +a
  mkdir -p "$OUT_DIR"
  chmod 777 "$OUT_DIR"          # le conteneur ZAP s'execute avec l'utilisateur "zap" (uid 1000)
  rm -f "$OUT_DIR"/zap-report.* "$OUT_DIR"/zap-run.log
  docker run --rm --network "$NETWORK" \
    -e ZAP_USER -e ZAP_PASSWORD \
    -v "$ROOT/zap:/zap/plan:ro" -v "$ROOT/$OUT_DIR:/zap/wrk:rw" \
    "$ZAP_IMAGE" zap.sh -cmd -autorun /zap/plan/automation.yaml 2>&1 | tee "$OUT_DIR/zap-run.log"
}

gate() {
  "$PYTHON" scripts/security_report.py zap "$OUT_DIR/zap-report.json" --fail-on "$FAIL_ON"
}

destroy() {
  mkdir -p "$OUT_DIR"
  docker logs "$APP_NAME" > "$OUT_DIR/app.log" 2>&1 || true
  docker rm -f "$APP_NAME" >/dev/null 2>&1 || true
  docker network rm "$NETWORK" >/dev/null 2>&1 || true
  rm -f "$CRED_FILE"
  echo "Environnement ephemere detruit."
}

case "${1:-}" in
  deploy)  deploy ;;
  scan)    scan ;;
  gate)    gate ;;
  destroy) destroy ;;
  all)
    trap destroy EXIT
    deploy
    scan
    gate
    ;;
  *) echo "Usage : $0 {deploy|scan|gate|destroy|all}" >&2; exit 2 ;;
esac
