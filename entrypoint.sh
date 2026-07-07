#!/bin/sh
# entrypoint.sh – ChainStrike Docker entrypoint
# Passes all arguments to main.py and ensures the reports dir is writable.

set -e

# Ensure the reports output dir exists (in case the bind mount is missing)
mkdir -p /app/reports

# Run ChainStrike, forwarding all docker run arguments
exec python3 /app/main.py "$@"
