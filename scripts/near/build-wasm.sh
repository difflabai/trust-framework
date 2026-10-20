#!/usr/bin/env bash
# Usage: scripts/near/build-wasm.sh [--ci [COMMIT] | --local [COMMIT]] [--run-id ID] [--out PATH]
#
# Produce the approval contract wasm and record where it came from. Prints
# the wasm's sha256 (hex) and NEAR code hash (base58 sha256) and writes
# <out without .wasm>.build.json next to it (source commit, hashes, mode,
# CI run id), which deploy.sh copies into the deployment record.
#
# Modes:
#   --ci [COMMIT]     (default) download the wasm CI built reproducibly for
#                     COMMIT: find a successful approval-contract.yml run for
#                     it (gh), download its approval-contract-wasm artifact
#                     and check it against the sha256 the run printed in its
#                     log ("approval_contract.wasm sha256: <hex>"). Needs an
#                     authenticated gh; read-only.
#   --local [COMMIT]  build it yourself, the way CI does: fetch the cargo-near
#                     release pinned in .github/workflows/approval-contract.yml
#                     (CARGO_NEAR_VERSION + per-platform sha256), clone COMMIT
#                     into a temp dir outside this repo and run `cargo near
#                     build reproducible-wasm` there (Docker, pinned image).
#                     First run: ~20-40 min on Apple Silicon (amd64 emulation
#                     and image pull); later runs are a few minutes.
#
# COMMIT defaults to the most recent commit touching contracts/approval
# (ignoring *.md), which must be an ancestor of HEAD.
#
# Options:
#   --run-id ID   use this CI run instead of searching (with --ci)
#   --out PATH    output wasm (default contracts/approval/target/near/
#                 approval_contract/approval_contract.wasm)
#   --keep-build-dir  (--local) keep the temp build dir for inspection
#   -h, --help
#
# Environment: NEAR_CACHE_DIR (cargo-near download cache, default
# scripts/near/.cache), GH_REPO (override the GitHub repo gh uses).
set -euo pipefail
NEAR_SELF=${BASH_SOURCE[0]}
while [ -L "$NEAR_SELF" ]; do
  NEAR_SELF_DIR=$(cd "$(dirname "$NEAR_SELF")" && pwd -P)
  NEAR_SELF=$(readlink "$NEAR_SELF")
  case $NEAR_SELF in /*) ;; *) NEAR_SELF="$NEAR_SELF_DIR/$NEAR_SELF" ;; esac
done
# shellcheck source=SCRIPTDIR/lib.sh
. "$(cd "$(dirname "$NEAR_SELF")" && pwd -P)/lib.sh"

MODE=ci
COMMIT=""
RUN_ID=""
OUT=""
KEEP_BUILD_DIR=0
while [ $# -gt 0 ]; do
  case $1 in
    -h | --help)
      print_usage
      exit 0
      ;;
    --ci | --local)
      MODE=${1#--}
      if [ $# -gt 1 ] && [ "${2#-}" = "$2" ]; then
        COMMIT=$2
        shift
      fi
      ;;
    --run-id)
      [ $# -gt 1 ] || usage_error "--run-id needs a value"
      RUN_ID=$2
      shift
      ;;
    --out)
      [ $# -gt 1 ] || usage_error "--out needs a value"
      OUT=$2
      shift
      ;;
    --keep-build-dir) KEEP_BUILD_DIR=1 ;;
    *) usage_error "unknown argument '$1'" ;;
  esac
  shift
done
[ -z "$RUN_ID" ] || [ "$MODE" = ci ] || usage_error "--run-id only applies to --ci"
case $RUN_ID in '' | *[!0-9]*) [ -z "$RUN_ID" ] || usage_error "--run-id must be numeric" ;; esac

near_tmp_init
OUT=${OUT:-$DEFAULT_WASM}
case $OUT in /*) ;; *) OUT="$PWD/$OUT" ;; esac
case $OUT in *.wasm) ;; *) usage_error "--out must end in .wasm" ;; esac
META="${OUT%.wasm}.build.json"
SRC_PATHS=(contracts/approval ':(exclude)contracts/approval/**/*.md' ':(exclude)contracts/approval/*.md')
git_r() { git -C "$REPO_ROOT" "$@"; }

# ------------------------------------------------------------ the commit
if [ -z "$COMMIT" ]; then
  SHA=$(git_r log -1 --format=%H -- "${SRC_PATHS[@]}")
  [ -n "$SHA" ] || die "no commit touches contracts/approval"
  git_r merge-base --is-ancestor "$SHA" HEAD || die "$SHA is not an ancestor of HEAD"
  info "Source commit: $SHA (latest change to contracts/approval, excluding docs)"
else
  SHA=$(git_r rev-parse --verify --quiet "$COMMIT^{commit}") || die "unknown commit '$COMMIT'"
  info "Source commit: $SHA"
  if ! git_r merge-base --is-ancestor "$SHA" HEAD; then
    warn "$SHA is not an ancestor of HEAD."
  elif ! git_r diff --quiet "$SHA" HEAD -- "${SRC_PATHS[@]}"; then
    warn "HEAD has contract changes after $SHA; this wasm does not include them."
  fi
fi
if [ -n "$(git_r status --porcelain -- "${SRC_PATHS[@]}")" ]; then
  warn "contracts/approval has uncommitted changes; they are NOT part of this build (it uses commit $SHA)."
fi
ORIGIN_URL=$(git_r remote get-url origin 2>/dev/null || echo "")

ghr() { (cd "$REPO_ROOT" && gh "$@"); }

# --------------------------------------------------------------- CI mode
build_ci() {
  command -v gh >/dev/null 2>&1 || die "gh (GitHub CLI) not found; install it or use --local."
  local runs head concl log_file hexes n dl
  if [ -z "$RUN_ID" ]; then
    runs=$(ghr run list --workflow approval-contract.yml --commit "$SHA" --status success \
      --json databaseId,headSha,event,createdAt -L 20) ||
      die "gh run list failed (check: gh auth status)."
    RUN_ID=$(jget "$runs" 0.databaseId)
    if [ -z "$RUN_ID" ] || [ "$RUN_ID" = null ]; then
      die "No successful approval-contract.yml run found for $SHA." \
        "CI may not have run for it (e.g. docs-only change) or the run failed." \
        "Build it yourself instead: scripts/near/build-wasm.sh --local $SHA"
    fi
  else
    head=$(ghr run view "$RUN_ID" --json headSha,conclusion) || die "gh run view $RUN_ID failed"
    concl=$(jget "$head" conclusion)
    [ "$(jget "$head" headSha)" = "$SHA" ] || die "run $RUN_ID built $(jget "$head" headSha), not $SHA"
    [ "$concl" = success ] || die "run $RUN_ID concluded '$concl', not success"
  fi
  RUN_URL=$(ghr run view "$RUN_ID" --json url -q .url 2>/dev/null || echo "")
  info "CI run $RUN_ID ${RUN_URL:+($RUN_URL)}"

  log_file="$NEAR_TMP/run.log"
  ghr run view "$RUN_ID" --log >"$log_file" 2>"$NEAR_TMP/gh.err" ||
    die "Could not fetch the log of run $RUN_ID (logs expire). $(head -c 300 "$NEAR_TMP/gh.err")" \
      "Build it yourself instead: scripts/near/build-wasm.sh --local $SHA"
  # The log also contains the echo command with a literal $hex; anchor on 64 hex chars.
  hexes=$(grep -Eo 'approval_contract\.wasm sha256: [0-9a-f]{64}' "$log_file" | awk '{ print $3 }' | sort -u || true)
  n=$(printf '%s' "$hexes" | grep -c . || true)
  [ "$n" = 1 ] || die "Expected one 'approval_contract.wasm sha256: <hex>' line in run $RUN_ID's log, found $n."
  EXPECTED_SHA256=$hexes
  log "    log reports sha256 $EXPECTED_SHA256"

  dl="$NEAR_TMP/artifact"
  mkdir -p "$dl"
  ghr run download "$RUN_ID" -n approval-contract-wasm -D "$dl" >/dev/null 2>"$NEAR_TMP/gh.err" ||
    die "Could not download artifact approval-contract-wasm of run $RUN_ID (artifacts expire). $(head -c 300 "$NEAR_TMP/gh.err")" \
      "Build it yourself instead: scripts/near/build-wasm.sh --local $SHA"
  [ -f "$dl/approval_contract.wasm" ] || die "artifact has no approval_contract.wasm"
  BUILT="$dl/approval_contract.wasm"
  local got
  got=$(sha256_hex "$BUILT")
  [ "$got" = "$EXPECTED_SHA256" ] ||
    die "artifact sha256 $got does not match the run log's $EXPECTED_SHA256"
  ok "artifact matches the sha256 printed by CI"
}

# ------------------------------------------------------------ local mode
BUILD_DIR=""
BUILD_PID=""
TEE_PID=""
near_extra_cleanup() {
  # Stop a build still running (INT/TERM while waiting for it).
  if [ -n "$BUILD_PID" ]; then kill "$BUILD_PID" 2>/dev/null || true; fi
  if [ -n "$TEE_PID" ]; then kill "$TEE_PID" 2>/dev/null || true; fi
  [ -n "$BUILD_DIR" ] || return 0
  # Remove cargo-near build containers that bind-mount our build dir (an
  # interrupted build leaves them running).
  if command -v docker >/dev/null 2>&1; then
    local id
    for id in $(docker ps -aq --filter name=near-verify-rs- 2>/dev/null || true); do
      if docker inspect -f '{{range .Mounts}}{{println .Source}}{{end}}' "$id" 2>/dev/null |
        grep -F "$BUILD_DIR/" >/dev/null; then
        docker rm -f "$id" >/dev/null 2>&1 || true
      fi
    done
  fi
  if [ "$KEEP_BUILD_DIR" = 1 ]; then
    log "build dir kept: $BUILD_DIR"
  else
    rm -rf "$BUILD_DIR"
  fi
}

build_local() {
  command -v cargo >/dev/null 2>&1 || die "cargo not found (rustup) — needed by cargo-near on the host."
  command -v docker >/dev/null 2>&1 || die "docker not found; the reproducible build runs in a container."
  docker info >/dev/null 2>&1 || die "Docker daemon not reachable. Start Docker Desktop and re-run."
  local ver target sha_var pinned
  ver=$CARGO_NEAR_VERSION
  case "$(uname -s):$(uname -m)" in
    Linux:x86_64) target=x86_64-unknown-linux-gnu sha_var=CARGO_NEAR_SHA256 ;;
    Darwin:arm64) target=aarch64-apple-darwin sha_var=CARGO_NEAR_SHA256_MACOS_ARM64 ;;
    *) die "No cargo-near build pinned in the workflow for $(uname -s) $(uname -m)." ;;
  esac
  pinned=$(printf '%s\n' "$WORKFLOW" | sed -n "s/^ *$sha_var: *\"\\([0-9a-f]\\{64\\}\\)\".*/\\1/p" | head -n 1)
  [ -n "$ver" ] && [ -n "$pinned" ] || die "could not read CARGO_NEAR_VERSION / $sha_var from the workflow"
  info "cargo-near $ver ($target), pinned sha256 $pinned (from approval-contract.yml at $SHA)"

  local cache cn
  cache=$(abs_path "${NEAR_CACHE_DIR:-scripts/near/.cache}")
  cn="$cache/cargo-near-$ver-$target/cargo-near"
  if [ ! -x "$cn" ]; then
    local dl="$NEAR_TMP/cargo-near" tarball="cargo-near-$target.tar.gz" got
    mkdir -p "$dl"
    curl --proto '=https' --tlsv1.2 -fsSL --retry 3 -o "$dl/$tarball" \
      "https://github.com/near/cargo-near/releases/download/cargo-near-v$ver/$tarball" ||
      die "could not download cargo-near $ver"
    got=$(sha256_hex "$dl/$tarball")
    [ "$got" = "$pinned" ] || die "cargo-near tarball sha256 mismatch" "expected $pinned" "got      $got"
    mkdir -p "$dl/x"
    tar -xzf "$dl/$tarball" -C "$dl/x"
    [ -f "$dl/x/cargo-near-$target/cargo-near" ] || die "unexpected cargo-near tarball layout"
    mkdir -p "$(dirname "$cn")"
    install -m 0755 "$dl/x/cargo-near-$target/cargo-near" "$cn"
    ok "cargo-near $ver installed in $(dirname "$cn") (sha256 verified)"
  fi

  # cargo-near discovers the *enclosing* git repo, so the clone must live
  # outside this worktree. /tmp is shared with Docker Desktop by default.
  BUILD_DIR=$(mktemp -d /tmp/approval-wasm-build.XXXXXXXX)
  mkdir -p "$BUILD_DIR/tmp"
  info "Cloning $SHA into $BUILD_DIR/src"
  git clone --quiet --no-checkout "$REPO_ROOT" "$BUILD_DIR/src"
  git -C "$BUILD_DIR/src" checkout --quiet --detach "$SHA"
  [ -z "$ORIGIN_URL" ] || git -C "$BUILD_DIR/src" remote set-url origin "$ORIGIN_URL"

  local platform_env="" cn_dir got_ver
  cn_dir=$(dirname "$cn")
  # Run the verified binary directly: `cargo near` would pick whichever
  # cargo-near cargo finds first ($CARGO_HOME/bin can win over PATH).
  got_ver=$("$cn" near --version 2>/dev/null || "$cn" --version 2>/dev/null || true)
  case $got_ver in *" $ver" | *" $ver "*) ;; *) die "$cn is not cargo-near $ver (--version: '$got_ver')" ;; esac
  [ "$(uname -m)" = x86_64 ] || platform_env=linux/amd64
  warn "Reproducible build in Docker; the first run can take 20-40 min under amd64 emulation."
  local rc=0 fifo="$NEAR_TMP/build.fifo"
  mkfifo "$fifo"
  tee "$BUILD_DIR/build.log" <"$fifo" >&2 &
  TEE_PID=$!
  # In the background, so INT/TERM are handled at once (bash defers traps
  # until a foreground job ends); the EXIT trap stops the build and removes
  # its containers.
  (
    cd "$BUILD_DIR/src/contracts/approval/contract"
    PATH="$cn_dir:$PATH"
    TMPDIR="$BUILD_DIR/tmp"
    export PATH TMPDIR
    [ -z "$platform_env" ] || export DOCKER_DEFAULT_PLATFORM="$platform_env"
    exec "$cn" near build reproducible-wasm
  ) >"$fifo" 2>&1 &
  BUILD_PID=$!
  wait "$BUILD_PID" || rc=$?
  BUILD_PID=""
  wait "$TEE_PID" || true
  TEE_PID=""
  [ "$rc" = 0 ] || die "cargo near build reproducible-wasm failed (exit $rc); log: $BUILD_DIR/build.log" \
    "(re-run with --keep-build-dir to keep it)"
  BUILT="$BUILD_DIR/src/contracts/approval/target/near/approval_contract/approval_contract.wasm"
  [ -f "$BUILT" ] || die "build finished but $BUILT is missing"
}

RUN_URL=""
BUILT=""
# The workflow at the source commit is the single source of truth for the
# cargo-near pin (falls back to the working tree's copy).
WORKFLOW=$(git_r show "$SHA:.github/workflows/approval-contract.yml" 2>/dev/null ||
  cat "$REPO_ROOT/.github/workflows/approval-contract.yml")
CARGO_NEAR_VERSION=$(printf '%s\n' "$WORKFLOW" | sed -n 's/^ *CARGO_NEAR_VERSION: *"\([^"]*\)".*/\1/p' | head -n 1)
if [ "$MODE" = ci ]; then build_ci; else build_local; fi

mkdir -p "$(dirname "$OUT")"
cp "$BUILT" "$OUT.tmp.$$"
mv -f "$OUT.tmp.$$" "$OUT"
HASHES=$(nu hash-file "$OUT")
SHA256=$(jget "$HASHES" sha256)
CODE_HASH=$(jget "$HASHES" code_hash)
SIZE=$(jget "$HASHES" size)
if [ "$MODE" = ci ]; then run_json=$RUN_ID; else run_json=null; fi
nu json-build wasm="$(basename "$OUT")" sha256="$SHA256" code_hash="$CODE_HASH" size:="$SIZE" \
  source_commit="$SHA" source_repo="$ORIGIN_URL" mode="$MODE" ci_run_id:="$run_json" \
  ci_run_url="$RUN_URL" cargo_near_version="$CARGO_NEAR_VERSION" built_at="$(utc_now)" |
  nu json-pretty >"$META"

ok "wasm ready"
log "  file:      $OUT ($SIZE bytes)"
log "  sha256:    $SHA256"
log "  code_hash: $CODE_HASH  (compare with view_account.code_hash)"
log "  commit:    $SHA ($MODE${RUN_ID:+, CI run $RUN_ID})"
log "  metadata:  $META"
printf '%s\n' "$SHA256"
