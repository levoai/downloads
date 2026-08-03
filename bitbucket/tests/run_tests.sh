#!/usr/bin/env bash
#
# Automated tests for levo-cli-runner.sh.
#
# Covers: argument parsing/validation, is_int, data-source validation, app-name
# detection, audit exit-code behavior, auth-mode selection, argv parity for
# representative remote-test-run invocations, and (critically) that the auth key
# is NOT present in the argv of ANY process the runner spawns — neither the
# long-running scan nor the `levo login` that establishes the session.
#
# No network or real credentials required — the levo CLI, pip, and python are
# stubbed. Runs on bash 3.2 (macOS) and newer.
#
# Usage: bitbucket/tests/run_tests.sh   (exit 0 = all passed)

set -uo pipefail

TESTS_DIR="$(cd "$(dirname "$0")" && pwd)"
RUNNER="$(cd "$TESTS_DIR/.." && pwd)/levo-cli-runner.sh"

PASS=0
FAIL=0

pass() { PASS=$((PASS + 1)); printf '  ok   - %s\n' "$1"; }
fail() { FAIL=$((FAIL + 1)); printf '  FAIL - %s\n' "$1"; [ -n "${2:-}" ] && printf '         %s\n' "$2"; }

assert_eq()      { if [ "$2" = "$3" ]; then pass "$1"; else fail "$1" "expected '$3', got '$2'"; fi; }
assert_contains(){ case "$2" in *"$3"*) pass "$1" ;; *) fail "$1" "'$2' does not contain '$3'" ;; esac; }
assert_absent()  { case "$2" in *"$3"*) fail "$1" "found forbidden '$3'" ;; *) pass "$1" ;; esac; }

# ---------------------------------------------------------------------------
# Test sandbox: stub python3.12 (host) and a fake venv (python/levo).
# ---------------------------------------------------------------------------
SANDBOX="$(mktemp -d "${TMPDIR:-/tmp}/levo-test-XXXXXX")"
trap 'rm -rf "$SANDBOX"' EXIT

mkdir -p "$SANDBOX/fakebin" "$SANDBOX/work/.levo-venv/bin"

cat > "$SANDBOX/fakebin/python3.12" <<'EOF'
#!/usr/bin/env bash
[ "$1" = "--version" ] && { echo "Python 3.12.9"; exit 0; }
exit 0
EOF

cat > "$SANDBOX/work/.levo-venv/bin/python" <<'EOF'
#!/usr/bin/env bash
[ "$1" = "--version" ] && { echo "Python 3.12.9"; exit 0; }
# `python -c <shim> login ...` is the runner's login path. Record the full argv
# (the shim source included) so tests can prove no secret is on the command
# line, report whether the key arrived via the environment instead, and emulate
# the session file that a real `levo login` would write.
if [ "$1" = "-c" ]; then
    for a in "$@"; do
        if [ "$a" = "login" ]; then
            for b in "$@"; do printf 'PYARG|%s\n' "$b"; done
            if [ -n "${LEVOAI_RUNNER_LOGIN_KEY:-}" ]; then
                printf 'PYENV_KEY_PRESENT|yes\n'
            else
                printf 'PYENV_KEY_PRESENT|no\n'
            fi
            [ -n "${LEVOAI_CONFIG_FILE:-}" ] && printf '{"auth":{}}' > "$LEVOAI_CONFIG_FILE"
            exit 0
        fi
    done
fi
# `-m pip show levo` and `-m pip install ...` both succeed.
exit 0
EOF
: > "$SANDBOX/work/.levo-venv/bin/activate"

# Fake levo: `login` records its argv (so a regression that puts the key back on
# the command line is caught) and writes the session file; `remote-test-run`
# prints its argv (one ARG| line each) and exits with ${FAKE_SCAN_RC:-0}.
cat > "$SANDBOX/work/.levo-venv/bin/levo" <<'EOF'
#!/usr/bin/env bash
case "$1" in
    login)
        for a in "$@"; do printf 'PYARG|%s\n' "$a"; done
        printf 'PYENV_KEY_PRESENT|no\n'
        [ -n "${LEVOAI_CONFIG_FILE:-}" ] && printf '{"auth":{}}' > "$LEVOAI_CONFIG_FILE"
        exit 0 ;;
    remote-test-run)
        for a in "$@"; do printf 'ARG|%s\n' "$a"; done
        exit "${FAKE_SCAN_RC:-0}" ;;
    --version) echo "levo, version 9.9.9"; exit 0 ;;
    *) exit 0 ;;
esac
EOF
chmod +x "$SANDBOX/fakebin/python3.12" "$SANDBOX/work/.levo-venv/bin/python" "$SANDBOX/work/.levo-venv/bin/levo"

AUTH_KEY="SUPERSECRETKEY123"

# Run the runner with stubs in place. Fresh work dir copy per call keeps the
# reusable fake venv but isolated logs/session.
run_runner() {
    PATH="$SANDBOX/fakebin:$PATH" \
    LEVOAI_AUTH_KEY="$AUTH_KEY" \
    LEVOAI_ORG_ID="ORG123" \
        bash "$RUNNER" "$@" --work-dir "$SANDBOX/work" 2>&1
}

scan_argv() { run_runner "$@" | grep '^ARG|' | sed 's/^ARG|//' | tr '\n' ' '; }

# Source the runner (BASH_SOURCE guard prevents main from running) and run one
# expression in a subshell; returns that expression's exit code.
sourced() {
    # shellcheck source=/dev/null
    ( source "$RUNNER"; eval "$1" )
}

echo "== unit: is_int =="
check_is_int() {  # <label> <expected-rc> <value>
    sourced "is_int '$3'"; assert_eq "$1" "$?" "$2"
}
check_is_int "is_int 123 accepted"   0 123
check_is_int "is_int -5 accepted"    0 -5
check_is_int "is_int 1-2 rejected"   1 1-2
check_is_int "is_int '' rejected"    1 ''
check_is_int "is_int abc rejected"   1 abc
check_is_int "is_int 12a rejected"   1 12a

echo "== unit: resolve_app_name =="
NAME="$(sourced "BITBUCKET_REPO_SLUG=bbslug resolve_app_name; echo \"\$APP_NAME\"")"
assert_eq "app-name from BITBUCKET_REPO_SLUG" "$NAME" "bbslug"
NAME="$(sourced "unset BITBUCKET_REPO_SLUG; GITHUB_REPOSITORY=org/ghrepo resolve_app_name; echo \"\$APP_NAME\"")"
assert_eq "app-name from GITHUB_REPOSITORY (leaf)" "$NAME" "ghrepo"
NAME="$( cd "$SANDBOX" || exit 1; sourced "unset BITBUCKET_REPO_SLUG GITHUB_REPOSITORY; resolve_app_name; echo \"\$APP_NAME\"" )"
assert_eq "app-name default (no CI vars, non-git)" "$NAME" "default-app"

echo "== integration: help / validation exit codes =="
run_runner help >/dev/null 2>&1; assert_eq "help exits 0" "$?" "0"
out="$(env -u LEVOAI_AUTH_KEY -u LEVOAI_ORG_ID PATH="$SANDBOX/fakebin:$PATH" bash "$RUNNER" test --work-dir "$SANDBOX/work" 2>&1)"
rc=$?
assert_eq "no-auth test exits 1" "$rc" "1"
assert_contains "no-auth test reports missing key" "$out" "LEVOAI_AUTH_KEY is required"
run_runner test --bogus >/dev/null 2>&1; assert_eq "unknown flag exits 2" "$?" "2"
run_runner test --proxy-port abc >/dev/null 2>&1; assert_eq "non-integer exits 2" "$?" "2"
out="$(run_runner test --target-url https://x --fail-threshold -3 2>&1)"; rc=$?
assert_eq "negative --fail-threshold exits 1" "$rc" "1"
assert_contains "negative --fail-threshold reported" "$out" "cannot be negative"

echo "== integration: data-source validation message =="
out="$(run_runner test --target-url https://x --data-source Bogus 2>&1)"; rc=$?
assert_eq "bad data-source exits 1" "$rc" "1"
assert_contains "data-source error mentions 'Test User Data'" "$out" "Test User Data"

echo "== integration: argv parity + no secret in scan argv =="
argv="$(scan_argv test --target-url https://api.example.com --app-name myapp)"
assert_contains "argv has remote-test-run" "$argv" "remote-test-run"
assert_contains "argv has --app-name myapp" "$argv" "--app-name myapp"
assert_contains "argv defaults --env staging" "$argv" "--env staging"
assert_contains "argv defaults --methods GET,POST" "$argv" "--methods GET,POST"
assert_contains "argv has --target-url" "$argv" "--target-url https://api.example.com"
assert_contains "argv ends with --verbosity INFO" "$argv" "--verbosity INFO"
assert_absent   "scan argv has NO --key"          "$argv" "--key"
assert_absent   "scan argv has NO --organization" "$argv" "--organization"
assert_absent   "scan argv does NOT leak auth key" "$argv" "$AUTH_KEY"

argv="$(scan_argv test --target-url https://x --app-name a --exclude-methods 'DELETE,PUT' --categories 'CORS,FUZZING' --fail-threshold 10)"
assert_contains "exclude-methods passed" "$argv" "--exclude-methods DELETE,PUT"
assert_absent   "no --methods when exclude-methods set" "$argv" "--methods"
assert_contains "categories passed" "$argv" "--categories CORS,FUZZING"
assert_contains "fail-threshold passed" "$argv" "--fail-threshold 10"

argv="$(scan_argv test --app-name a --data-source Traces --use-target-url-from-traces --use-auth-from-traces --header 'Authorization: Bearer tok')"
assert_contains "traces flag replaces target-url" "$argv" "--use-target-url-from-traces"
assert_absent   "no --target-url in traces mode" "$argv" "--target-url"
assert_contains "header preserved with spaces" "$argv" "--header Authorization: Bearer tok"
assert_contains "use-auth-from-traces passed" "$argv" "--use-auth-from-traces"

echo "== integration: login argv carries no secret =="
rm -f "$SANDBOX/work/levo-login.log"
run_runner test --target-url https://x --app-name a >/dev/null 2>&1
login_log="$(cat "$SANDBOX/work/levo-login.log" 2>/dev/null)"
assert_contains "login was invoked"                 "$login_log" "PYARG|login"
assert_contains "login passes --organization"       "$login_log" "PYARG|--organization"
assert_absent   "login argv has NO --key"           "$login_log" "PYARG|--key"
assert_absent   "login argv does NOT leak auth key" "$login_log" "$AUTH_KEY"
assert_contains "auth key delivered via environment, not argv" "$login_log" "PYENV_KEY_PRESENT|yes"

echo "== unit: login shim keeps the key out of the OS command line (real python) =="
# The stubbed test above proves the runner does not put the key on argv. This one
# proves the mechanism itself holds under a real interpreter: the key reaches the
# levo entry point through sys.argv while the kernel's copy of the command line
# (/proc/<pid>/cmdline, what `ps` shows) never contains it.
REAL_PY=""
for c in python3.12 python3.13 python3 python; do
    if command -v "$c" >/dev/null 2>&1 && "$c" -c 'import sys; raise SystemExit(0)' >/dev/null 2>&1; then
        REAL_PY="$c"; break
    fi
done
if [ -z "$REAL_PY" ]; then
    printf '  skip - no python interpreter available for shim verification\n'
else
    # Stands in for the levo console script; the shim runs it via runpy.
    cat > "$SANDBOX/fake-levo-script.py" <<'PYEOF'
import sys

try:
    with open("/proc/self/cmdline", "rb") as fh:
        oscmd = fh.read().replace(b"\0", b" ").decode("utf-8", "replace")
except OSError:
    oscmd = ""
oscmd = oscmd.replace("\n", " ").replace("\r", " ")
print("SYSARGV|" + " ".join(sys.argv))
print("OSCMDLINE|" + oscmd)
print("OSCMDLINE_AVAILABLE|" + ("yes" if oscmd else "no"))
PYEOF

    shim_out="$(
        # shellcheck source=/dev/null
        source "$RUNNER"
        LEVOAI_RUNNER_LOGIN_KEY="$AUTH_KEY" \
        LEVOAI_RUNNER_LEVO_SCRIPT="$SANDBOX/fake-levo-script.py" \
            "$REAL_PY" -c "$LEVO_LOGIN_SHIM" login --organization ORG123 2>&1
    )"
    sysargv="$(printf '%s\n' "$shim_out" | sed -n 's/^SYSARGV|//p')"
    oscmd="$(printf '%s\n' "$shim_out" | sed -n 's/^OSCMDLINE|//p')"
    avail="$(printf '%s\n' "$shim_out" | sed -n 's/^OSCMDLINE_AVAILABLE|//p')"
    assert_contains "shim forwards the login command"      "$sysargv" "login --organization ORG123"
    assert_contains "shim injects --key into in-process argv" "$sysargv" "--key $AUTH_KEY"
    if [ "$avail" = "yes" ]; then
        assert_contains "OS command line is the shim invocation" "$oscmd" "login --organization ORG123"
        assert_absent   "OS command line does NOT contain the auth key" "$oscmd" "$AUTH_KEY"
    else
        printf '  skip - /proc/self/cmdline unavailable (non-Linux); OS argv check skipped\n'
    fi
fi

echo "== integration: audit forces defaults and always exits 0 =="
out="$(FAKE_SCAN_RC=7 PATH="$SANDBOX/fakebin:$PATH" LEVOAI_AUTH_KEY="$AUTH_KEY" LEVOAI_ORG_ID=ORG123 \
        bash "$RUNNER" audit --target-url https://x --app-name a --work-dir "$SANDBOX/work" 2>&1)"
rc=$?
assert_eq "audit exits 0 even when scan fails (rc=7)" "$rc" "0"
argv="$(printf '%s\n' "$out" | grep '^ARG|' | sed 's/^ARG|//' | tr '\n' ' ')"
assert_contains "audit forces --fail-scope none" "$argv" "--fail-scope none"
assert_contains "audit forces --fail-severity none" "$argv" "--fail-severity none"
assert_contains "audit forces all methods" "$argv" "--methods GET,POST,PUT,DELETE,PATCH"

echo ""
echo "==================================================="
printf 'Results: %d passed, %d failed\n' "$PASS" "$FAIL"
echo "==================================================="
[ "$FAIL" -eq 0 ]
