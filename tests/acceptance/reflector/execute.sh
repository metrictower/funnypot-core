#!/usr/bin/env bash
set -euo pipefail

readonly output=/output
readonly target='http://127.0.0.1:8898/products/quick-search?q=probe'
readonly evidence_limit_kib=16384
readonly router=/workspace/tests/acceptance/reflector/router.php
readonly wait_server=/workspace/tests/acceptance/reflector/wait-server.php

if [ "$#" -ne 0 ]; then
    echo 'execute.sh accepts no arguments' >&2
    exit 2
fi
if [ ! -d "$output" ] || [ -n "$(find "$output" -mindepth 1 -maxdepth 1 -print -quit)" ]; then
    echo 'the dedicated /output mount must exist and be empty' >&2
    exit 2
fi

umask 077
mkdir -p /tmp/home /tmp/config /tmp/cache
php_version=$(php -r 'echo PHP_VERSION;')
case "$php_version" in
    8.3.*) ;;
    *) echo "unexpected fixture PHP version: $php_version" > "$output/setup-error.txt"; exit 2 ;;
esac
nuclei_version=$(/opt/reflector/bin/nuclei -version 2>&1)
case "$nuclei_version" in
    *3.11.1*) ;;
    *) echo 'pinned Nuclei binary reports the wrong version' > "$output/setup-error.txt"; exit 2 ;;
esac
dalfox_version=$(/opt/reflector/bin/dalfox --version 2>&1)
case "$dalfox_version" in
    *3.2.2*) ;;
    *) echo 'pinned Dalfox binary reports the wrong version' > "$output/setup-error.txt"; exit 2 ;;
esac

server_pid=''
scanner_pid=''
cleanup_children() {
    if [ -n "$scanner_pid" ] && kill -0 "$scanner_pid" 2>/dev/null; then
        if kill -TERM "$scanner_pid" 2>/dev/null; then :; fi
        if wait "$scanner_pid" 2>/dev/null; then :; fi
    fi
    if [ -n "$server_pid" ] && kill -0 "$server_pid" 2>/dev/null; then
        if kill -TERM "$server_pid" 2>/dev/null; then :; fi
        for _ in 1 2 3 4 5; do
            kill -0 "$server_pid" 2>/dev/null || break
            sleep 0.2
        done
        if kill -0 "$server_pid" 2>/dev/null; then
            if kill -KILL "$server_pid" 2>/dev/null; then :; fi
        fi
        if wait "$server_pid" 2>/dev/null; then :; fi
    fi
    scanner_pid=''
    server_pid=''
}
trap cleanup_children EXIT INT TERM

run_one() {
    local scanner=$1
    local mode=$2
    local key="${scanner}-${mode}"
    local directory="$output/$key"
    local start end status kib
    local -a command

    mkdir "$directory"
    : > "$directory/records.jsonl"
    printf '0' > "$directory/request-count"
    start=$(date +%s)
    printf '%s' "$start" > "$directory/started-at"

    (
        ulimit -f 32768
        REFLECT_MODE="$mode" REFLECT_RUN_DIR="$directory" \
            php -d memory_limit=256M -d max_execution_time=0 -S 127.0.0.1:8898 "$router"
    ) > "$directory/server.log" 2>&1 &
    server_pid=$!
    if ! php -d max_execution_time=6 "$wait_server"; then
        printf '%s\n' 'loopback responder unavailable' > "$directory/runner-error"
        status=2
    else
        if [ "$scanner" = nuclei ]; then
            command=(
                /opt/reflector/bin/nuclei -u "$target"
                -t /opt/reflector/template/reflected-xss.yaml -dast
                -no-interactsh -disable-update-check -disable-redirects
                -jsonl -no-color -concurrency 1 -bulk-size 1
                -timeout 5 -retries 0 -no-stdin
                -error-log "$directory/nuclei-errors.log"
                -trace-log "$directory/nuclei-trace.log"
                -output "$directory/scanner.jsonl"
            )
        else
            command=(
                /opt/reflector/bin/dalfox scan "$target"
                --format json --output "$directory/scanner.json" --include-all
                --no-color --workers 1 --max-concurrent-targets 1 --max-targets-per-host 1
                --skip-mining --skip-reflection-header --skip-reflection-cookie --skip-reflection-path
                --skip-ast-analysis --skip-waf-probe --waf-bypass off
                --timeout 5 --scan-timeout 60 --retries 0 --max-payloads-per-param 64
            )
        fi

        php /workspace/tests/acceptance/reflector/write-invocation.php \
            "$directory/invocation.json" "${command[@]}"

        (
            ulimit -f 32768
            timeout --signal=TERM --kill-after=3 90 "${command[@]}"
        ) > "$directory/scanner-console.log" 2>&1 &
        scanner_pid=$!
        while kill -0 "$scanner_pid" 2>/dev/null; do
            read -r kib _ < <(du -sk "$output")
            if [ "$kib" -gt "$evidence_limit_kib" ]; then
                : > "$directory/output-overflow"
                if kill -TERM "$scanner_pid" 2>/dev/null; then :; fi
            fi
            if [ -f "$directory/request-overflow" ] || ! kill -0 "$server_pid" 2>/dev/null; then
                [ -f "$directory/request-overflow" ] || printf '%s\n' 'loopback responder exited early' > "$directory/runner-error"
                if kill -TERM "$scanner_pid" 2>/dev/null; then :; fi
            fi
            sleep 0.2
        done
        set +e
        wait "$scanner_pid"
        status=$?
        set -e
        scanner_pid=''
        if [ "$status" -eq 124 ] || [ "$status" -eq 137 ]; then
            : > "$directory/timed-out"
        fi
    fi

    cleanup_children
    end=$(date +%s)
    printf '%s' "$end" > "$directory/ended-at"
    printf '%s' "$status" > "$directory/exit-status"
}

run_one nuclei authorized
run_one nuclei unauthorized
run_one dalfox authorized
run_one dalfox unauthorized

php -d memory_limit=256M -d max_execution_time=30 /opt/reflector/collect.php
