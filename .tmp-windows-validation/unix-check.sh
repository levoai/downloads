#!/usr/bin/env bash
# Runs install-shadownet.sh against a stub docker and asserts what docker was asked to do.
set -u
script="$1"; stub="$2"
export PATH="$stub:$PATH" STUB_LOG="$stub/calls.log"
fail=0
ok() { echo "  ok   $1"; }
bad() { echo "  FAIL $1"; fail=$((fail+1)); }
check() { if eval "$2"; then ok "$1"; else bad "$1"; fi; }

echo "bash: $(bash --version | head -1)"; echo "script: $script"
: > "$STUB_LOG"
out=$(LEVOAI_AUTH_KEY=SECRETKEY123 bash "$script" --org org-1 --group "QA Team" --scheduled --region india --workspace ws-1 --no-pull 2>&1); code=$?
check "exit code 0" "[ $code -eq 0 ]"
check "group with a space is ONE argument" "grep -qx 'ARG:LEVOAI_GROUP=QA Team' $STUB_LOG"
check "container name slug" "grep -qx 'ARG:levoai-shadownet-QA-Team-scheduled' $STUB_LOG"
check "scheduled flag" "grep -qx 'ARG:SHADOWNET_SCHEDULED=true' $STUB_LOG"
check "stop signal SIGINT" "grep -qx 'ARG:SIGINT' $STUB_LOG"
check "auth key NOT on any docker command line" "! grep -q SECRETKEY123 $STUB_LOG"
check "auth key reaches docker through the environment" "grep -qx 'ENVKEY:set' $STUB_LOG"
check "india API URL printed" "echo \"\$out\" | grep -q api.india-1.levo.ai"
check "stop hint quotes the group" "echo \"\$out\" | grep -q -e \"--group 'QA Team' --scheduled\""
out=$(env -u LEVOAI_AUTH_KEY bash "$script" --org o --no-pull </dev/null 2>&1); code=$?
check "missing key: non-zero exit and clear message" "[ $code -ne 0 ] && echo \"\$out\" | grep -q LEVOAI_AUTH_KEY"
out=$(LEVOAI_AUTH_KEY=k bash "$script" --org o --region mars 2>&1); code=$?
check "bad region rejected" "[ $code -ne 0 ]"
[ "$fail" -eq 0 ] && echo "all checks passed" || { echo "$fail check(s) FAILED"; exit 1; }
