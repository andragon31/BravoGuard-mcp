#!/usr/bin/env bash
# Host runner (Linux/macOS): build the Linux proof image and run the in-container proof.
# Exits 2 when the Docker daemon is down (honest blocked, never a fake pass).
set -u

IMAGE=bravoguard-linux-test
LOG="$(dirname "$0")/proof-linux-host.log"

if ! docker info >/dev/null 2>&1; then
  echo "Docker daemon is DOWN. Start it, wait until 'docker info' shows a Server, then re-run:"
  echo "  sudo systemctl start docker   # Linux hosts"
  echo "  # or launch Docker Desktop, then: docker info"
  echo "  bash docker/run-linux-proof.sh"
  exit 2
fi

docker build -f docker/Dockerfile.linux-test -t "$IMAGE" . || { echo "docker build FAILED"; exit 1; }

docker run --rm "$IMAGE" 2>&1 | tee "$LOG"
code="${PIPESTATUS[0]}"
echo "proof container exit=$code (host log=$LOG, container log=/tmp/proof.log)"
exit "$code"
