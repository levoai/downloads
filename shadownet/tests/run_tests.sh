#!/usr/bin/env bash
#
# Automated tests for shadownet-runner.sh.
#
# Covers: argument parsing/validation, is_int / url_host helpers, auth-mode
# selection for Artifact Registry, version pinning, Playwright browser install,
# headed/headless flag mapping, display detection on Linux, pass-through args,
# Levo credential checks, and (critically) that no secret — Levo auth key or
# Artifact Registry token — appears in the argv of ANY process the runner spawns.
#
# No network or real credentials required — python, pip, playwright and
# shadownet are stubbed. Runs on bash 3.2 (macOS) and newer.
#
# Usage: shadownet/tests/run_tests.sh   (exit 0 = all passed)

set -uo pipefail

TESTS_DIR="$(cd "$(dirname "$0")" && pwd)"
RUNNER="$(cd "$TESTS_DIR/.." && pwd)/shadownet-runner.sh"

PASS=0
FAIL=0

pass() { PASS=$((PASS + 1)); printf '  ok   - %s\n' "$1"; }
fail() { FAIL=$((FAIL + 1)); printf '  FAIL - %s\n' "$1"; [ -n "${2:-}" ] && printf '         %s\n' "$2"; }

assert_eq()      { if [ "$2" = "$3" ]; then pass "$1"; else fail "$1" "expected '$3', got '$2'"; fi; }
assert_contains(){ case "$2" in *"$3"*) pass "$1" ;; *) fail "$1" "'$2' does not contain '$3'" ;; esac; }
assert_absent()  { case "$2" in *"$3"*) fail "$1" "found forbidden '$3'" ;; *) pass "$1" ;; esac; }

# ---------------------------------------------------------------------------
# Test sandbox: stub python3.12 (host) and a fake venv (python/shadownet).
# ---------------------------------------------------------------------------
SANDBOX="$(mktemp -d "${TMPDIR:-/tmp}/shadownet-test-XXXXXX")"
trap 'rm -rf "$SANDBOX"' EXIT

mkdir -p "$SANDBOX/fakebin" "$SANDBOX/work/.shadownet-venv/bin" "$SANDBOX/home"
ARGV_LOG="$SANDBOX/argv.log"

cat > "$SANDBOX/fakebin/python3.12" <<'EOF'
#!/usr/bin/env bash
[ "$1" = "--version" ] && { echo "Python 3.12.9"; exit 0; }
exit 0
EOF

# Fake venv python. Records every argv line-by-line so tests can prove what pip /
# playwright were invoked with and that no secret is on the command line.
cat > "$SANDBOX/work/.shadownet-venv/bin/python" <<'EOF'
#!/usr/bin/env bash
[ "$1" = "--version" ] && { echo "Python 3.12.9"; exit 0; }
if [ "$1" = "-c" ]; then
    # base64 decode shim used for the GAR key: emulate a decoded key.
    printf '{"type":"service_account"}'
    exit 0
fi
if [ "$1" = "-m" ] && [ "$2" = "pip" ]; then
    case "$3" in
        show)
            [ "${FAKE_SHADOWNET_INSTALLED:-yes}" = "yes" ] && exit 0
            [ -f "${ARGV_LOG:?}.installed" ] && exit 0
            exit 1 ;;
        install)
            # Only the shadownet install honours FAKE_PIP_RC (the keyring helper
            # and pip bootstrap always succeed), and a successful shadownet
            # install flips `pip show shadownet` to found.
            is_shadownet=no
            for a in "$@"; do case "$a" in shadownet|shadownet==*) is_shadownet=yes ;; esac; done
            { for a in "$@"; do printf 'PIP|%s\n' "$a"; done
              printf 'PIPENV_GAC|%s\n' "${GOOGLE_APPLICATION_CREDENTIALS:-}"
              printf 'PIPENV_CFG|%s\n' "${PIP_CONFIG_FILE:-}"
              if [ -n "${PIP_CONFIG_FILE:-}" ] && [ -f "$PIP_CONFIG_FILE" ]; then
                  printf 'PIPCONF|%s\n' "$(stat -f '%Lp' "$PIP_CONFIG_FILE" 2>/dev/null || stat -c '%a' "$PIP_CONFIG_FILE")"
                  sed 's/^/PIPCONFLINE|/' "$PIP_CONFIG_FILE"
              fi
            } >> "${ARGV_LOG:?}"
            if [ "$is_shadownet" = yes ]; then
                [ "${FAKE_PIP_RC:-0}" -eq 0 ] && : > "${ARGV_LOG:?}.installed"
                exit "${FAKE_PIP_RC:-0}"
            fi
            exit 0 ;;
    esac
    exit 0
fi
if [ "$1" = "-m" ] && [ "$2" = "playwright" ]; then
    for a in "$@"; do printf 'PW|%s\n' "$a"; done >> "${ARGV_LOG:?}"
    exit "${FAKE_PW_RC:-0}"
fi
exit 0
EOF

cat > "$SANDBOX/work/.shadownet-venv/bin/shadownet" <<'EOF'
#!/usr/bin/env bash
{ for a in "$@"; do printf 'SN|%s\n' "$a"; done
  printf 'SNENV_KEY_PRESENT|%s\n' "$([ -n "${LEVOAI_AUTH_KEY:-}" ] && echo yes || echo no)"
} >> "${ARGV_LOG:?}"
[ "$1" = "--version" ] && echo "ShadowNet DAST Scanner v9.9.9"
exit "${FAKE_SN_RC:-0}"
EOF
: > "$SANDBOX/work/.shadownet-venv/bin/activate"
chmod +x "$SANDBOX/fakebin/python3.12" "$SANDBOX/work/.shadownet-venv/bin/python" "$SANDBOX/work/.shadownet-venv/bin/shadownet"

# run_runner [env assignments...] -- <args>  : runs the runner in the sandbox,
# captures combined output in OUT and exit code in RC, and resets the argv log.
OUT=""; RC=0
run_runner() {
    : > "$ARGV_LOG"; rm -f "$ARGV_LOG.installed"
    local -a envs=()
    while [ $# -gt 0 ] && [ "$1" != "--" ]; do envs+=("$1"); shift; done
    [ "${1:-}" = "--" ] && shift
    OUT="$(cd "$SANDBOX/work" && env -i \
        PATH="$SANDBOX/fakebin:/usr/bin:/bin" HOME="$SANDBOX/home" ARGV_LOG="$ARGV_LOG" \
        SHADOWNET_RUNNER_OS="${TEST_OS:-Darwin}" TMPDIR="$SANDBOX" \
        ${envs[@]+"${envs[@]}"} bash "$RUNNER" "$@" 2>&1)"
    RC=$?
}
argv() { cat "$ARGV_LOG" 2>/dev/null; }

# Source the runner to unit-test helpers directly (main() is guarded).
# shellcheck source=/dev/null
. "$RUNNER"

printf '\n# helpers\n'
check_is_int() {  # <label> <expected-rc> <value>
    is_int "$3"; local rc=$?
    assert_eq "$1" "$rc" "$2"
}
check_is_int "is_int 123 accepted"   0 123
check_is_int "is_int -5 accepted"    0 -5
check_is_int "is_int 1-2 rejected"   1 1-2
check_is_int "is_int '' rejected"    1 ''
check_is_int "is_int abc rejected"   1 abc

assert_eq "url_host strips scheme/path" "$(url_host https://us-python.pkg.dev/levoai/pypi-levo/simple/)" "us-python.pkg.dev"
assert_eq "url_host keeps port"        "$(url_host http://127.0.0.1:8766/simple/)" "127.0.0.1:8766"
assert_eq "url_host strips userinfo"   "$(url_host https://u:p@host.example/simple/)" "host.example"

printf '\n# help / parsing\n'
run_runner -- help
assert_eq       "help exits 0"            "$RC" "0"
assert_contains "help lists scan"         "$OUT" "  scan "
assert_contains "help mentions headless"  "$OUT" "--headless"

run_runner -- scan --target-url
assert_eq       "missing trailing value exits 2"  "$RC" "2"
assert_contains "missing trailing value reported" "$OUT" "requires a value"

run_runner -- scan --target-url --headless
assert_eq       "flag-as-value exits 2"  "$RC" "2"
assert_contains "flag-as-value reported" "$OUT" "looks like another option"

run_runner -- scan --bogus
assert_eq       "unknown option exits 2"    "$RC" "2"
assert_contains "unknown option hints '--'" "$OUT" "use '--'"

run_runner LEVOAI_AUTH_KEY=k LEVOAI_ORG_ID=o -- scan
assert_eq       "scan without target exits 1"   "$RC" "1"
assert_contains "scan without target reported"  "$OUT" "--target-url or --config"

run_runner LEVOAI_AUTH_KEY=k LEVOAI_ORG_ID=o -- scan --target-url ftp://x
assert_eq       "bad scheme exits 1"     "$RC" "1"
assert_contains "bad scheme reported"    "$OUT" "http:// or https://"

run_runner LEVOAI_AUTH_KEY=k LEVOAI_ORG_ID=o -- scan --config /nonexistent.yml
assert_eq       "missing config exits 1"  "$RC" "1"
assert_contains "missing config reported" "$OUT" "not found"

printf '\n# install: Artifact Registry auth modes\n'
run_runner FAKE_SHADOWNET_INSTALLED=no -- install
assert_eq       "install without GAR creds exits 1"  "$RC" "1"
assert_contains "install without GAR creds reported" "$OUT" "No Artifact Registry credentials"

KEY_B64="$(printf '{"type":"service_account"}' | base64 | tr -d '\n')"
run_runner FAKE_SHADOWNET_INSTALLED=no LEVOAI_GAR_SA_KEY_B64="$KEY_B64" -- install
assert_eq       "install (GAR key) exits 0"            "$RC" "0"
A="$(argv)"
assert_contains "GAR key: keyring helper installed"    "$A" "PIP|keyrings.google-artifactregistry-auth"
assert_contains "GAR key: credential-free index url"   "$A" "PIP|https://us-python.pkg.dev/levoai/pypi-levo/simple/"
assert_contains "GAR key: GOOGLE_APPLICATION_CREDENTIALS set" "$A" "PIPENV_GAC|$SANDBOX/gar-sa-key-"
assert_contains "GAR key: trusted host derived from index" "$A" "PIP|us-python.pkg.dev"
assert_contains "GAR key: latest shadownet requested"  "$A" "PIP|shadownet"
assert_contains "GAR key: playwright chromium installed" "$A" "PW|chromium"
assert_absent   "GAR key: key material not in argv"    "$A" "service_account"
assert_absent   "GAR key: no --with-deps by default"   "$A" "PW|--with-deps"
assert_contains "install prints success banner"        "$OUT" "installed successfully"

run_runner FAKE_SHADOWNET_INSTALLED=no PYPI_USERNAME=oauth2accesstoken PYPI_PASSWORD=ya29.SECRET -- install
assert_eq       "install (legacy token) exits 0"         "$RC" "0"
A="$(argv)"
assert_absent   "legacy: token not in pip argv"          "$(printf '%s\n' "$A" | grep '^PIP|')" "ya29.SECRET"
assert_contains "legacy: PIP_CONFIG_FILE used"           "$A" "PIPENV_CFG|$SANDBOX/shadownet-pip-"
assert_contains "legacy: pip.conf is 0600"               "$A" "PIPCONF|600"
assert_contains "legacy: pip.conf carries token in index-url" "$A" "PIPCONFLINE|index-url = https://oauth2accesstoken:ya29.SECRET@us-python.pkg.dev/levoai/pypi-levo/simple/"
assert_absent   "legacy: no --index-url on argv"         "$(printf '%s\n' "$A" | grep '^PIP|')" "--index-url"

run_runner FAKE_SHADOWNET_INSTALLED=no PYPI_USERNAME=oauth2accesstoken -- install
assert_eq       "legacy without password exits 1"  "$RC" "1"
assert_contains "legacy without password reported" "$OUT" "PYPI_PASSWORD is required"

run_runner FAKE_SHADOWNET_INSTALLED=no LEVOAI_GAR_SA_KEY_B64="$KEY_B64" SHADOWNET_VERSION=1.4.49 -- install
assert_contains "version pin in pip argv" "$(argv)" "PIP|shadownet==1.4.49"

run_runner FAKE_SHADOWNET_INSTALLED=no LEVOAI_GAR_SA_KEY_B64="$KEY_B64" PYPI_INDEX_URL=http://127.0.0.1:8766/simple/ -- install
A="$(argv)"
assert_contains "PYPI_INDEX_URL override used"          "$A" "PIP|http://127.0.0.1:8766/simple/"
assert_contains "PYPI_INDEX_URL override trusted host"  "$A" "PIP|127.0.0.1:8766"

run_runner FAKE_SHADOWNET_INSTALLED=no LEVOAI_GAR_SA_KEY_B64="$KEY_B64" -- install --with-deps
assert_contains "--with-deps forwarded to playwright" "$(argv)" "PW|--with-deps"

run_runner FAKE_SHADOWNET_INSTALLED=no LEVOAI_GAR_SA_KEY_B64="$KEY_B64" FAKE_PIP_RC=1 -- install
assert_eq       "pip failure exits 1"    "$RC" "1"
assert_contains "pip failure reported"   "$OUT" "pip install failed"

TEST_OS=Linux run_runner FAKE_SHADOWNET_INSTALLED=no LEVOAI_GAR_SA_KEY_B64="$KEY_B64" FAKE_PW_RC=1 -- install
assert_eq       "playwright failure exits 1"        "$RC" "1"
assert_contains "playwright failure hints deps"     "$OUT" "--with-deps"

printf '\n# scan\n'
run_runner -- scan --target-url https://app.example.com
assert_eq       "scan without Levo creds exits 1"  "$RC" "1"
assert_contains "scan without Levo creds reported" "$OUT" "Levo credentials are required"

run_runner LEVOAI_AUTH_KEY=SECRETKEY LEVOAI_ORG_ID=org1 -- scan --target-url https://app.example.com
assert_eq       "scan (headed default) exits 0"      "$RC" "0"
A="$(argv)"
assert_contains "scan argv: subcommand"              "$A" "SN|scan"
assert_contains "scan argv: target"                  "$A" "SN|https://app.example.com"
assert_contains "scan argv: --no-headless by default" "$A" "SN|--no-headless"
assert_absent   "scan argv: auth key not on argv"    "$A" "SECRETKEY"
assert_contains "scan: auth key reaches shadownet via env" "$A" "SNENV_KEY_PRESENT|yes"
assert_contains "scan: already-installed short-circuit" "$OUT" "already installed"
assert_absent   "scan: no pip install when installed" "$A" "PIP|shadownet"
assert_contains "scan: config shows headed"          "$OUT" "headed (browser window visible)"

run_runner LEVOAI_AUTH_KEY=k LEVOAI_ORG_ID=o -- scan --target-url https://app.example.com --headless
A="$(argv)"
assert_contains "scan --headless maps to --headless" "$A" "SN|--headless"
assert_absent   "scan --headless has no --no-headless" "$A" "SN|--no-headless"

mkdir -p "$SANDBOX/home/.config/configstore" && printf '{}' > "$SANDBOX/home/.config/configstore/levo.json"
run_runner -- scan --target-url https://app.example.com
assert_eq       "scan with saved session exits 0"   "$RC" "0"
assert_contains "scan with saved session reported"  "$OUT" "Using saved Levo session"
rm -rf "$SANDBOX/home/.config"

printf 'target:\n  url: https://cfg.example.com\n' > "$SANDBOX/work/levo-dast.yml"
run_runner LEVOAI_AUTH_KEY=k LEVOAI_ORG_ID=o -- scan --config levo-dast.yml
A="$(argv)"
assert_eq       "scan --config exits 0"          "$RC" "0"
assert_contains "scan --config forwarded"        "$A" "SN|--config"
assert_contains "scan --config path forwarded"   "$A" "SN|levo-dast.yml"

run_runner LEVOAI_AUTH_KEY=k LEVOAI_ORG_ID=o -- scan --target-url https://app.example.com -- --max-pages 50 --fail-on high
A="$(argv)"
assert_contains "passthrough: --max-pages"  "$A" "SN|--max-pages"
assert_contains "passthrough: 50"           "$A" "SN|50"
assert_contains "passthrough: --fail-on"    "$A" "SN|--fail-on"
assert_eq       "passthrough: order preserved (last arg)" "$(printf '%s\n' "$A" | grep '^SN|' | tail -1)" "SN|high"

run_runner LEVOAI_AUTH_KEY=k LEVOAI_ORG_ID=o FAKE_SN_RC=3 -- scan --target-url https://app.example.com
assert_eq       "scan propagates shadownet exit code" "$RC" "3"
assert_contains "scan non-zero reported"              "$OUT" "exited with code 3"

run_runner FAKE_SHADOWNET_INSTALLED=no LEVOAI_GAR_SA_KEY_B64="$KEY_B64" LEVOAI_AUTH_KEY=k LEVOAI_ORG_ID=o -- scan --target-url https://app.example.com
A="$(argv)"
assert_eq       "scan auto-installs when missing"     "$RC" "0"
assert_contains "auto-install: pip install ran"       "$A" "PIP|shadownet"
assert_contains "auto-install: browser installed"     "$A" "PW|chromium"
assert_contains "auto-install: scan ran afterwards"   "$A" "SN|scan"

printf '\n# display detection (Linux)\n'
TEST_OS=Linux run_runner LEVOAI_AUTH_KEY=k LEVOAI_ORG_ID=o -- scan --target-url https://app.example.com
assert_eq       "Linux headed without DISPLAY exits 1" "$RC" "1"
assert_contains "Linux headed without DISPLAY reported" "$OUT" "graphical session"

TEST_OS=Linux run_runner LEVOAI_AUTH_KEY=k LEVOAI_ORG_ID=o DISPLAY=:0 -- scan --target-url https://app.example.com
assert_eq       "Linux headed with DISPLAY exits 0" "$RC" "0"

TEST_OS=Linux run_runner LEVOAI_AUTH_KEY=k LEVOAI_ORG_ID=o WAYLAND_DISPLAY=wayland-0 -- scan --target-url https://app.example.com
assert_eq       "Linux headed with WAYLAND_DISPLAY exits 0" "$RC" "0"

TEST_OS=Linux run_runner LEVOAI_AUTH_KEY=k LEVOAI_ORG_ID=o -- scan --target-url https://app.example.com --headless
assert_eq       "Linux headless without DISPLAY exits 0" "$RC" "0"

run_runner LEVOAI_AUTH_KEY=k LEVOAI_ORG_ID=o -- scan --target-url https://app.example.com
assert_eq       "macOS headed without DISPLAY exits 0" "$RC" "0"

printf '\n# crawl / login / version\n'
run_runner -- crawl --target-url https://app.example.com
A="$(argv)"
assert_eq       "crawl exits 0 without Levo creds"   "$RC" "0"
assert_contains "crawl argv: subcommand"             "$A" "SN|crawl"
assert_contains "crawl argv: standard crawler"       "$A" "SN|--crawler-type"
assert_contains "crawl argv: standard value"         "$A" "SN|standard"
assert_contains "crawl argv: headed"                 "$A" "SN|--no-headless"

run_runner -- login
assert_eq       "login exits 0"          "$RC" "0"
assert_contains "login argv"             "$(argv)" "SN|login"

run_runner -- version
assert_eq       "version exits 0"        "$RC" "0"
assert_contains "version prints version" "$OUT" "ShadowNet DAST Scanner v9.9.9"

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
