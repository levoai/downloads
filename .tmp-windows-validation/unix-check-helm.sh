#!/usr/bin/env bash
# Runs install-all-helm.sh against stub helm/kubectl and asserts what they were asked to do.
set -u
script="$1"; stub="$2"
export PATH="$stub:$PATH" STUB_LOG="$stub/calls.log"
fail=0
ok() { echo "  ok   $1"; }
bad() { echo "  FAIL $1"; fail=$((fail+1)); }
check() { if eval "$2"; then ok "$1"; else bad "$1"; fi; }
has() { grep -qxF "$1" "$STUB_LOG"; }
argv() { grep '^ARG:' "$STUB_LOG"; }
common=(--context ctx-1 --namespace ns-1 --yes)
run() { : > "$STUB_LOG"; "$@" 2>&1; }

echo "bash: $(bash --version | head -1)"

echo "== install (dry run): every release, tricky group"
out=$(LEVOAI_AUTH_KEY=SECRETKEY123 run bash "$script" --dast 2 --scheduled 1 --testrunner 1 --group 'QA,Team "x"' --org org-1 --workspace ws-1 --region india --dry-run "${common[@]}"); code=$?
check "exit code 0" "[ $code -eq 0 ]"; [ $code -eq 0 ] || echo "$out"
for rel in levoai-shadownet levoai-shadownet-scheduled testrunner; do check "release $rel is installed" "has ARG:$rel"; done
check "uses --repo and the chart URL" "has ARG:--repo && has ARG:https://charts.levo.ai"
check "passes --kube-context" "has ARG:--kube-context"
check "dast replicaCount=2" "has ARG:replicaCount=2"
check "scheduled=true on the scheduled release" "has ARG:scheduled=true"
check "--dry-run is passed, no --wait" "has ARG:--dry-run && ! has ARG:--wait"
check "key reaches helm on stdin" "grep -qF 'key: \"SECRETKEY123\"' $STUB_LOG"
check "key is NOT on any command line" "! argv | grep -q SECRETKEY123"
check "group with comma and quotes is escaped in the YAML" "grep -qF 'group: \"QA,Team \\\"x\\\"\"' $STUB_LOG"
check "group is NOT on any command line" "! argv | grep -q 'QA,Team'"
check "dast workspace via extraEnv" "grep -qF 'LEVOAI_WORKSPACE_ID: \"ws-1\"' $STUB_LOG"
check "test runner workspace" "grep -qF 'workspace: \"ws-1\"' $STUB_LOG"
check "india URL" "grep -qF 'levoBaseUrl: \"https://api.india-1.levo.ai\"' $STUB_LOG"

echo "== install (real): waits"
out=$(LEVOAI_AUTH_KEY=k run bash "$script" --org org-1 "${common[@]}"); code=$?
check "exit code 0" "[ $code -eq 0 ]"
check "--wait" "has ARG:--wait"
check "only dast and testrunner are installed (scheduled skipped at 0)" "[ \$(grep -cxF ARG:upgrade $STUB_LOG) -eq 2 ]"

echo "== validation"
out=$(LEVOAI_AUTH_KEY=k run bash "$script" --dast 99 --org o "${common[@]}"); code=$?
check "hard cap rejects 99" "[ $code -ne 0 ] && echo \"\$out\" | grep -q 'above the limit'"
out=$(: > "$STUB_LOG"; env -u LEVOAI_AUTH_KEY bash "$script" --org o "${common[@]}" </dev/null 2>&1); code=$?
check "missing key is reported" "[ $code -ne 0 ] && echo \"\$out\" | grep -q LEVOAI_AUTH_KEY"
out=$(: > "$STUB_LOG"; LEVOAI_AUTH_KEY=k bash "$script" --org o --context ctx-1 </dev/null 2>&1); code=$?
check "without --yes and no terminal, it refuses" "[ $code -ne 0 ] && echo \"\$out\" | grep -q -e '--yes'"
check "nothing installed when not confirmed" "! has ARG:upgrade"

echo "== scale uses kubectl scale on installed releases only"
out=$(STUB_INSTALLED=levoai-shadownet,testrunner run bash "$script" scale --dast 3 --testrunner 0 --scheduled 2 "${common[@]}"); code=$?
check "exit code 0" "[ $code -eq 0 ]"
check "scales the dast deployment to 3" "has ARG:deployment/levoai-shadownet && has ARG:--replicas=3"
check "testrunner replicas=0" "has ARG:--replicas=0"
check "not-installed scheduled release is not scaled" "! has ARG:deployment/levoai-shadownet-scheduled"

echo "== uninstall"
out=$(STUB_INSTALLED=levoai-shadownet,testrunner run bash "$script" uninstall "${common[@]}"); code=$?
check "exit code 0" "[ $code -eq 0 ]"
check "uninstalls installed releases" "has ARG:uninstall && has ARG:testrunner"
[ "$fail" -eq 0 ] && echo "all checks passed" || { echo "$fail check(s) FAILED"; exit 1; }
