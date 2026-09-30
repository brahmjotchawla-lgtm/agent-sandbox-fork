#!/bin/sh
# Build the workload image and import it as the fork base image.
#   sudo bench/workload/build.sh            (control plane must be running)
set -eu
cd "$(dirname "$0")"
TAG=agent-sandbox-workload:django-5.1.4
[ -d context/repo ] || ./fetch.sh
docker build --quiet -t "$TAG" .
cd ../..
python3 -m control_plane ${AGENT_SANDBOX_CONFIG:+--config "$AGENT_SANDBOX_CONFIG"} image import workload "$TAG"
