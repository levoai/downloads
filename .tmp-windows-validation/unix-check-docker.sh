#!/usr/bin/env bash
# Runs install-all.sh against a stub docker and asserts what docker was asked to do.
set -u
dir="$1"; stub="$2"; rawbase="${3:-}"; ref="${4:-main}"
export PATH="$stub:$PATH" STUB_LOG="$stub/calls.log"
fail=0
ok() { echo "  ok   $1"; }
bad() { echo "  FAIL $1"; fail=$((fail+1)); }
check() { if eval "$2"; then ok "$1"; else bad "$1"; fi; }
hasseq() { grep -A1 -x "$1" "$STUB_LOG" | grep -qx "$2"; }
run() { : > "$STUB_LOG"; "$@" 2>&1; }

echo "bash: $(bash --version | head -1)  dir: $dir"
fresh() { local d; d="$(mktemp -d)"; cp "$dir/docker-compose.yml" "$dir/install-all.sh" "$d/"; echo "$d"; }
cd "$(fresh)"

echo "== install"
out=$(LEVOAI_AUTH_KEY=SECRETKEY123 run ./install-all.sh install --dast 2 --testrunner 1 --scheduled 0 --group "QA Team" --org org-1 --base-url http://x.example --no-wait); code=$?
check "exit code 0" "[ $code -eq 0 ]"
check "dast-worker=2" "hasseq ARG:--scale ARG:dast-worker=2"
check "scheduled=0" "hasseq ARG:--scale ARG:dast-worker-scheduled=0"
check "testrunner=1" "hasseq ARG:--scale ARG:testrunner=1"
check "group reaches compose through the environment, with its space" "grep -qx 'ENVGROUP:QA Team' $STUB_LOG"
check "auth key NOT on any docker command line" "! grep -q SECRETKEY123 $STUB_LOG"
check "auth key reaches docker through the environment" "grep -qx 'ENVKEY:set' $STUB_LOG"
check "install converges (no --no-recreate)" "! grep -qx ARG:--no-recreate $STUB_LOG"

echo "== scale"
out=$(LEVOAI_AUTH_KEY=k run ./install-all.sh scale --dast 3 --org o --no-wait); code=$?
check "exit code 0" "[ $code -eq 0 ]"
check "--no-recreate" "grep -qx ARG:--no-recreate $STUB_LOG"
check "dast-worker=3" "hasseq ARG:--scale ARG:dast-worker=3"

echo "== scheduled test runner and certificates"
cd "$(fresh)"; certd="$(mktemp -d)"; echo ca > "$certd/ca.pem"
out=$(LEVOAI_AUTH_KEY=k run ./install-all.sh install --dast 1 --testrunner 0 --testrunner-scheduled 2 --org o --ca-cert "$certd/ca.pem" --no-wait); code=$?
check "exit code 0" "[ $code -eq 0 ]"; [ $code -eq 0 ] || echo "$out"
check "testrunner-scheduled=2" "hasseq ARG:--scale ARG:testrunner-scheduled=2"
check "CA copied to ./certs" "[ -f certs/ca.pem ]"
check ".env points LEVOAI_CA_CERT at the mounted file" "grep -qx LEVOAI_CA_CERT=/etc/shadownet/certs/ca.pem .env"
check "all four profiles are passed" "grep -qx ARG:api-testing-scheduled $STUB_LOG"
out=$(LEVOAI_AUTH_KEY=k run ./install-all.sh install --org o --client-cert "$certd/ca.pem" --no-wait); code=$?
check "client cert without key is refused" "[ $code -ne 0 ] && echo \"\$out\" | grep -q together"
out=$(LEVOAI_AUTH_KEY=k run ./install-all.sh scale --ca-cert "$certd/ca.pem" --org o --no-wait); code=$?
check "scale refuses certificate options" "[ $code -ne 0 ] && echo \"\$out\" | grep -q 'install only'"

echo "== limits and validation"
cd "$(fresh)"
out=$(LEVOAI_AUTH_KEY=k run ./install-all.sh install --dast 99 --org o); code=$?
check "hard cap rejects 99" "[ $code -ne 0 ] && echo \"\$out\" | grep -q 'above the limit'"
check "compose up not called" "! grep -qx ARG:up $STUB_LOG"
out=$(: > "$STUB_LOG"; env -u LEVOAI_AUTH_KEY ./install-all.sh install --org o </dev/null 2>&1); code=$?
check "missing key is reported" "[ $code -ne 0 ] && echo \"\$out\" | grep -q LEVOAI_AUTH_KEY"
out=$(: > "$STUB_LOG"; env -u LEVOAI_ORG_ID LEVOAI_AUTH_KEY=k ./install-all.sh install </dev/null 2>&1); code=$?
check "missing org is reported" "[ $code -ne 0 ] && echo \"\$out\" | grep -q 'Organization ID'"

echo "== down and status work without credentials"
cd "$(fresh)"
out=$(: > "$STUB_LOG"; env -u LEVOAI_AUTH_KEY -u LEVOAI_ORG_ID ./install-all.sh down 2>&1); code=$?
check "down" "[ $code -eq 0 ] && grep -qx ARG:down $STUB_LOG"
out=$(: > "$STUB_LOG"; env -u LEVOAI_AUTH_KEY -u LEVOAI_ORG_ID ./install-all.sh status 2>&1); code=$?
check "status" "[ $code -eq 0 ] && grep -qx ARG:ps $STUB_LOG"

echo "== install (download mode)"
work="$(mktemp -d)"; mkdir "$work/alone"; cp "$dir/install-all.sh" "$work/alone/"
cd "$work"
envs=(LEVOAI_AUTH_KEY=SECRETKEY123); [ -z "$rawbase" ] || envs+=(LEVO_DOWNLOADS_BASE="$rawbase")
out=$(env "${envs[@]}" bash -c ': > "$STUB_LOG"; exec "$@" 2>&1' _ bash "$work/alone/install-all.sh" --org org-9 --group "QA Team" --dast 2 --testrunner 1 --region india --ref "$ref" --no-wait); code=$?
inst="$work/levo-dast-testrunner"
check "exit code 0" "[ $code -eq 0 ]" ; [ $code -eq 0 ] || echo "$out"
check "compose file downloaded" "[ -s $inst/docker-compose.yml ]"
check "script copied next to the compose file" "[ -x $inst/install-all.sh ]"
check ".env has the org" "grep -qx LEVOAI_ORG_ID=org-9 $inst/.env"
check ".env has the india URL" "grep -qx LEVOAI_BASE_URL=https://api.india-1.levo.ai $inst/.env"
check ".env has the group" "grep -qx 'DAST_GROUP=QA Team' $inst/.env"
check "key NOT written to .env" "! grep -q SECRETKEY123 $inst/.env"
check "compose up with dast-worker=2" "hasseq ARG:--scale ARG:dast-worker=2"
check "key not on any docker command line" "! grep -q SECRETKEY123 $STUB_LOG"
[ "$fail" -eq 0 ] && echo "all checks passed" || { echo "$fail check(s) FAILED"; exit 1; }
