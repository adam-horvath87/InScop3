#!/usr/bin/env bash
# InScop3 Recon — Launcher
export GOPATH="$HOME/go"
export PATH="$PATH:$GOPATH/bin"
cd "$(dirname "$0")"
exec python3 inscop3.py "$@"
