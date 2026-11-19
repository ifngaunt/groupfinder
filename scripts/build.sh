#!/usr/bin/env bash
# Build groupfinder from WSL with the Windows MSVC toolchain and Qt 5.15.2 msvc2019_64.
#
#   scripts/build.sh build            configure + compile, copy DLL to dist/, check exports/imports
#   scripts/build.sh test             build, then run unit tests (ctest)
#   scripts/build.sh harness [modes]  build, then run the plugin harness (default: all modes)
#   scripts/build.sh all              build + test + harness
#   scripts/build.sh package          build, then create dist/groupfinder-<version>.ts3_plugin
#
# Env overrides: GF_QT_DIR (Windows path to Qt 5.15.2\msvc2019_64), GF_BUILD_ROOT (Windows path).
# Sources are mirrored to a Windows directory first: MSVC/Ninja are unreliable on \\wsl$ paths.
set -euo pipefail

CMD=${1:-build}
shift || true
REPO=$(cd "$(dirname "$0")/.." && pwd)
DIST="$REPO/dist"
HARNESS_MODES_ALL="lifecycle execute warn thread screenshots edit modal"

winenv() { (cd /mnt/c && cmd.exe /c "echo %$1%" 2>/dev/null | tr -d '\r'); }
die() { echo "build.sh: $*" >&2; exit 1; }

ROOT_W=${GF_BUILD_ROOT:-"$(winenv LOCALAPPDATA)\\groupfinder-build"}
QT_W=${GF_QT_DIR:-"$(winenv USERPROFILE)\\Qt\\5.15.2\\msvc2019_64"}
ROOT=$(wslpath -u "$ROOT_W")
[ -d "$(wslpath -u "$QT_W")/lib/cmake/Qt5" ] || die "Qt not found at $QT_W (set GF_QT_DIR)"

VSWHERE="/mnt/c/Program Files (x86)/Microsoft Visual Studio/Installer/vswhere.exe"
[ -x "$VSWHERE" ] || die "vswhere.exe not found — install Visual Studio Build Tools 2022 with C++"
VS_W=$( (cd /mnt/c && "$VSWHERE" -latest -products '*' \
          -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath) | tr -d '\r')
[ -n "$VS_W" ] || die "no Visual Studio with the C++ x64 toolset found"
VCVARS_W="$VS_W\\VC\\Auxiliary\\Build\\vcvars64.bat"

version() { sed -n 's/^project(groupfinder VERSION \([0-9.]*\).*/\1/p' "$REPO/CMakeLists.txt"; }

# Run a batch script (lines passed as args) on Windows after vcvars64 + Qt on PATH.
run_bat() {
  local bat="$ROOT/run.bat"
  {
    echo '@echo off'
    echo "call \"$VCVARS_W\" >nul || exit /b 1"
    echo "set \"PATH=$QT_W\\bin;%PATH%\""
    echo "set \"QT_PLUGIN_PATH=$QT_W\\plugins\""
    for line in "$@"; do echo "$line || exit /b 1"; done
  } | sed 's/$/\r/' > "$bat"
  (cd /mnt/c && cmd.exe /c "$(wslpath -w "$bat")" 2>&1 | tr -d '\r')
  return "${PIPESTATUS[0]}"
}

sync_sources() {
  mkdir -p "$ROOT/src"
  rsync -rlt --delete --exclude .git --exclude build --exclude dist --exclude .superpowers \
        "$REPO/" "$ROOT/src/"
}

check_dll() {
  local dll="$1"
  echo "== exports"
  objdump -p "$dll" | sed -n '/\[Ordinal\/Name Pointer\] Table/,/^$/p' | grep -o 'ts3plugin_[A-Za-z0-9_]*' | sort
  echo "== imports"
  local imports bad
  imports=$(objdump -p "$dll" | sed -n 's/^\s*DLL Name: //p')
  echo "$imports"
  bad=$(echo "$imports" | grep -viE '^(KERNEL32|USER32|Qt5Core|Qt5Gui|Qt5Widgets|VCRUNTIME140|VCRUNTIME140_1|MSVCP140|api-ms-win-crt-[a-z0-9-]+)\.dll$' || true)
  [ -z "$bad" ] || die "unexpected DLL imports (would not load on users' machines): $bad"
}

do_build() {
  sync_sources
  run_bat \
    "cmake -S \"$ROOT_W\\src\" -B \"$ROOT_W\\build\" -G Ninja -DCMAKE_BUILD_TYPE=Release -DGF_BUILD_TESTS=ON \"-DCMAKE_PREFIX_PATH=$QT_W\" >nul" \
    "cmake --build \"$ROOT_W\\build\"" || die "build failed"
  mkdir -p "$DIST"
  cp "$ROOT/build/groupfinder.dll" "$DIST/groupfinder.dll"
  check_dll "$DIST/groupfinder.dll"
}

do_test() {
  # QtTest output does not reach the WSL terminal through cmd.exe, so write it to a file.
  local st=0
  rm -rf "$ROOT/testout" && mkdir -p "$ROOT/testout"
  run_bat "set \"GF_TEST_OUT=$ROOT_W\\testout\"" "\"$ROOT_W\\build\\gf_tests.exe\"" >/dev/null || st=$?
  ls "$ROOT"/testout/*.txt >/dev/null 2>&1 || die "gf_tests.exe produced no output (exit $st)"
  local f
  for f in "$ROOT"/testout/*.txt; do
    printf '%s ' "$(basename "$f" .txt)"
    tr -d '\r' < "$f" | grep -E '^(FAIL!|XPASS|QWARN|QFATAL|   Loc:|   Actual|   Expected|Totals:)' || true
  done
  [ "$st" -eq 0 ] || die "unit tests failed"
}

do_harness() {
  local modes=${*:-$HARNESS_MODES_ALL} m st=0
  rm -rf "$ROOT/shots" && mkdir -p "$ROOT/shots"
  for m in $modes; do
    run_bat "set \"QT_QPA_PLATFORM=offscreen\"" "set \"QT_QPA_FONTDIR=C:\\Windows\\Fonts\"" \
            "\"$ROOT_W\\build\\gf_harness.exe\" \"$ROOT_W\\build\\groupfinder.dll\" $m \"$ROOT_W\\shots\"" >/dev/null || st=1
    if [ -f "$ROOT/shots/harness-$m.log" ]; then
      tr -d '\r' < "$ROOT/shots/harness-$m.log" | grep -E 'HARNESS|\[qt:[1-3]\]' || echo "harness $m: no result line (crash?)"
    else
      echo "harness $m: no log (crashed before start?)"; st=1
    fi
  done
  mkdir -p "$DIST/shots" && cp "$ROOT"/shots/* "$DIST/shots/" 2>/dev/null || true
  [ "$st" -eq 0 ] || die "harness failed"
}

do_package() {
  local ver stage out
  ver=$(version)
  stage="$ROOT/package"
  out="$DIST/groupfinder-$ver.ts3_plugin"
  rm -rf "$stage" && mkdir -p "$stage/plugins/groupfinder/sound"
  sed "s/^Version = .*/Version = $ver/" "$REPO/groupfinder/package.ini" > "$stage/package.ini"
  cp "$DIST/groupfinder.dll" "$stage/plugins/groupfinder.dll"
  cp "$REPO/groupfinder/plugins/groupfinder/sound/default.wav" "$stage/plugins/groupfinder/sound/"
  rm -f "$out"
  (cd "$stage" && zip -qr -X "$out" package.ini plugins)
  unzip -tq "$out"
  unzip -l "$out"
  echo "package: $out"
}

case "$CMD" in
  build)   do_build ;;
  test)    do_build && do_test ;;
  harness) do_build && do_harness "$@" ;;
  all)     do_build && do_test && do_harness ;;
  package) do_build && do_package ;;
  *)       die "unknown command '$CMD' (build|test|harness|all|package)" ;;
esac
