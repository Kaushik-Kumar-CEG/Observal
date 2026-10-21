#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Kaushik Kumar <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0
set -Eeuo pipefail
qa=$(cd "$(dirname "$0")" && pwd)
state="$qa/.runtime"
[[ -d "$state" && ! -L "$state" ]] || { echo 'No owned QA state'; exit 0; }
id=$(<"$state/id")
[[ "$id" =~ ^followqa[0-9a-f]{10}$ ]] || { echo 'Invalid QA state; refusing destructive cleanup' >&2; exit 1; }
for suffix in a b; do
    if [[ -f "$state/pid-$suffix" && -f "$state/port-$suffix" ]]; then
        pid=$(<"$state/pid-$suffix"); port=$(<"$state/port-$suffix")
        if [[ "$pid" =~ ^[0-9]+$ && "$port" =~ ^[0-9]+$ && -r "/proc/$pid/cmdline" ]] && \
           tr '\0' ' ' < "/proc/$pid/cmdline" | grep -Fq "uvicorn app:app --app-dir $qa --host 127.0.0.1 --port $port"; then
            kill "$pid" || true
        fi
    fi
done
if [[ -f "$state/pid-worker" ]]; then
    pid=$(<"$state/pid-worker")
    if [[ "$pid" =~ ^[0-9]+$ && -r "/proc/$pid/cmdline" ]] && \
       tr '\0' ' ' < "/proc/$pid/cmdline" | grep -Fq "python $qa/privacy_worker.py"; then
        kill "$pid" || true
    fi
fi
for suffix in nginx redis pg; do docker rm -fv "${id}${suffix}" >/dev/null 2>&1 || true; done
if [[ -f "$state/run" ]]; then
    run=$(<"$state/run")
    if [[ "$run" == /tmp/observal-follow-qa.* && -d "$run" && ! -L "$run" ]]; then
        # CA PRIVATE KEY, TLS leaf, JWT keys and disposable password deleted locally.
        rm -rf -- "$run"
    fi
fi
rm -f -- "$state"/*
rmdir "$state"
if ! python3 - <<'PY'
import socket
for family, address in ((socket.AF_INET, ('0.0.0.0', 18443)), (socket.AF_INET6, ('::', 18443))):
    with socket.socket(family) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if family == socket.AF_INET6: sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        sock.bind(address)
PY
then
    echo 'WARNING: 18443 still has a listener; inspect before restarting' >&2
    exit 1
fi
echo 'QA containers, processes, temporary CA and state removed; 18443 has no listener'
