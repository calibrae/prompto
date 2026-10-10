#!/usr/bin/env bash
# macOS smoke against the bench prompto (run.sh start first).
exec python3 -I "$(dirname "$0")/smoke.py" "$@"
