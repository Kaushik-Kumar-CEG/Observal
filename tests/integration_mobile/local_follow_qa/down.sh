#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Kaushik Kumar <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0
set -Eeuo pipefail
qa=$(cd "$(dirname "$0")" && pwd)
state_name=${MOBILE_FOLLOW_QA_STATE_NAME:-.runtime}
[[ "$state_name" == .runtime || "$state_name" =~ ^\.runtime-scratch-[0-9a-f]{6,12}$ || \
   "$state_name" =~ ^\.runtime-android-[0-9a-f]{6,12}$ || \
   "$state_name" =~ ^\.runtime-android-next-[0-9a-f]{6,12}$ || \
   "$state_name" =~ ^\.runtime-android-diagnostic-[0-9a-f]{6,12}$ ]] || {
    echo 'Invalid QA state name; refusing cleanup' >&2; exit 1;
}
state="$qa/$state_name"
[[ -d "$state" && ! -L "$state" ]] || { echo 'No owned QA state'; exit 0; }
id=$(<"$state/id")
[[ "$id" =~ ^followqa[0-9a-f]{10}$ && "${MOBILE_FOLLOW_QA_EXPECT_ID:-}" == "$id" ]] || {
    echo 'Exact expected QA ID required; refusing destructive cleanup' >&2; exit 1;
}
issuer_port=$(<"$state/issuer-port")
[[ "$state_name" == .runtime && "$issuer_port" == 18443 ]] || \
    [[ "$state_name" =~ ^\.runtime-scratch- && "$issuer_port" == 18444 ]] || \
    [[ "$state_name" =~ ^\.runtime-android-[0-9a-f]{6,12}$ && "$issuer_port" == 18446 ]] || \
    [[ "$state_name" =~ ^\.runtime-android-next-[0-9a-f]{6,12}$ && "$issuer_port" == 18448 ]] || \
    [[ "$state_name" =~ ^\.runtime-android-diagnostic-[0-9a-f]{6,12}$ && "$issuer_port" == 18449 ]] || {
        echo 'QA state/issuer mismatch; refusing cleanup' >&2; exit 1;
    }
docker info >/dev/null || { echo 'Docker unavailable; preserving QA state' >&2; exit 1; }
owned_process() {
    local pid=$1
    [[ "$pid" =~ ^[0-9]+$ && -r "/proc/$pid/cmdline" && -r "/proc/$pid/environ" ]] && \
        tr '\0' '\n' < "/proc/$pid/environ" | grep -Fxq "MOBILE_FOLLOW_QA_OWNER=$id"
}
# `isolated` starts as a bash wrapper; the recorded $! is that wrapper, while
# its uvicorn/worker child alone carries the scrubbed ownership marker. Never
# delete the runtime until the verified child has been signalled too.
kill_owned_slot() {
    local parent=$1 expected=$2 child matched=0 seen=0
    [[ "$parent" =~ ^[0-9]+$ ]] || return 0
    if owned_process "$parent" && tr '\0' ' ' < "/proc/$parent/cmdline" | grep -Fq "$expected"; then
        kill "$parent" || true
        return 0
    fi
    while read -r child; do
        [[ -n "$child" ]] || continue
        seen=1
        if owned_process "$child" && tr '\0' ' ' < "/proc/$child/cmdline" | grep -Fq "$expected"; then
            matched=1
            kill "$child" || true
        fi
    done < <(pgrep -P "$parent" || true)
    if [[ "$seen" == 1 && "$matched" == 0 ]]; then
        echo 'Unrecognized QA child; preserving session state for owner review' >&2
        return 1
    fi
}
# Never remove a resource with the same name unless its ownership label matches.
# Check all existing names before killing anything or deleting state.
for suffix in nginx ch redis pg; do
    if docker inspect "${id}${suffix}" >/dev/null 2>&1; then
        [[ $(docker inspect --format '{{index .Config.Labels "observal.followqa.owner"}}' "${id}${suffix}") == "$id" ]] || {
            echo "Unowned QA container name ${id}${suffix}; refusing cleanup" >&2; exit 1;
        }
    fi
done
for suffix in a b; do
    if [[ -f "$state/pid-$suffix" && -f "$state/port-$suffix" ]]; then
        pid=$(<"$state/pid-$suffix"); port=$(<"$state/port-$suffix")
        if [[ "$port" =~ ^[0-9]+$ ]]; then
            kill_owned_slot "$pid" "uvicorn app:app --app-dir $qa --host 127.0.0.1 --port $port"
        fi
    fi
done
if [[ -f "$state/pid-worker" ]]; then
    pid=$(<"$state/pid-worker")
    kill_owned_slot "$pid" "python $qa/privacy_worker.py"
fi
if [[ -f "$state/pid-projection" ]]; then
    pid=$(<"$state/pid-projection")
    kill_owned_slot "$pid" "python $qa/projection_worker.py"
fi
# A recorded wrapper can exit before its marked child (or SIGTERM can queue
# behind SIGSTOP). Enumerate the marker itself, verify every process has one
# of this session's exact service commands, then wait for all of them to exit.
# Never discard the state/CA while even one owner-marked process survives.
owned_pids() {
    local env_file pid
    for env_file in /proc/[0-9]*/environ; do
        [[ -r "$env_file" ]] || continue
        pid=${env_file#/proc/}; pid=${pid%/environ}
        if (tr '\0' '\n' < "$env_file" | grep -Fxq "MOBILE_FOLLOW_QA_OWNER=$id") 2>/dev/null; then
            printf '%s\n' "$pid"
        fi
    done
}
for pid in $(owned_pids); do
    cmd=$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null || true)
    if [[ "$cmd" == *"uvicorn app:app --app-dir $qa --host 127.0.0.1 --port $(<"$state/port-a")"* ||
          "$cmd" == *"uvicorn app:app --app-dir $qa --host 127.0.0.1 --port $(<"$state/port-b")"* ||
          "$cmd" == *"python $qa/privacy_worker.py"* ||
          "$cmd" == *"python $qa/projection_worker.py"* ]]; then
        kill "$pid" 2>/dev/null || true
    else
        echo 'Unexpected owner-marked QA process; preserving state for review' >&2
        exit 1
    fi
done
for _ in {1..10}; do
    [[ -z $(owned_pids) ]] && break
    sleep 1
done
[[ -z $(owned_pids) ]] || {
    echo 'QA process did not exit; preserving containers, keys and exact-ID state' >&2
    exit 1
}
for suffix in nginx ch redis pg; do
    if docker inspect "${id}${suffix}" >/dev/null 2>&1; then
        docker rm -fv "${id}${suffix}" >/dev/null
    fi
done
if [[ -f "$state/run" ]]; then
    run=$(<"$state/run")
    if [[ "$run" == /tmp/observal-follow-qa.* && -d "$run" && ! -L "$run" ]]; then
        # CA PRIVATE KEY, TLS leaf, JWT keys and disposable password deleted locally.
        rm -rf -- "$run"
    fi
fi
rm -f -- "$state"/*
rmdir "$state"
if ! python3 - "$issuer_port" <<'PY'
import socket, sys
port = int(sys.argv[1])
for family, address in ((socket.AF_INET, ('0.0.0.0', port)), (socket.AF_INET6, ('::', port))):
    with socket.socket(family) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if family == socket.AF_INET6: sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        sock.bind(address)
PY
then
    echo "WARNING: $issuer_port still has a listener; inspect before restarting" >&2
    exit 1
fi
echo "QA containers, processes, temporary CA and state removed; $issuer_port has no listener"
