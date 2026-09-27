#!/usr/bin/env bash
# One verdict vocabulary for every deploy check (developer / ops).
#
# Two rules, each right about its own half:
#
#   "never report OK for something you could not measure" — common.sh::host_number returns
#   the sentinel `?` so an unreachable host cannot print `OK   disk space`. As a FAIL,
#   though, it would take down a whole `task deploy` over a host with no /proc/meminfo,
#   having found nothing wrong.
#
#   "skipped is not failed" — a subsystem the smoke test could not read is SKIP and exits
#   0. That alone cannot express a check the caller genuinely needed.
#
# They need a third verdict, not a compromise between them:
#
#   PASS     measured, and good.
#   FAIL     measured, and bad.                      → the run failed.
#   UNKNOWN  not measured.                           → the run did NOT fail.
#   UNKNOWN(blocking)  not measured, and the thing that could not be measured is a
#                      SECURITY CONTROL.             → the run stops anyway.
#
# The last one exists so the exception is named rather than silent. A VPN tunnel whose
# peer table cannot be read is the case: continuing would put Redis, PostgreSQL and
# Garage on a routable interface, which is what asking for a VPN was meant to prevent.
# "UNKNOWN never fails a run" with an undocumented exception buried in one script is how
# the next person removes it by accident.
#
# UNKNOWN is never rendered as OK, is always listed in the summary, and is always named
# in the closing banner. A verdict you can hide failures behind is worse than a FAIL.
#
# Exit codes, the same in every script that sources this:
#   0  every measured check passed (UNKNOWNs may exist; they are listed)
#   1  something was measured and failed
#   2  nothing could be measured at all
#   3  a blocking UNKNOWN, in a mode that asked for the thing
#
# NOTE for callers: go-task collapses every non-zero exit to 201, so a caller that needs
# to tell 1 from 2 from 3 must invoke `bash scripts/<x>.sh` directly rather than through
# `task`. deploy-fleet.sh and upgrade.sh both do.

V_PASS=0
V_FAIL=0
V_UNKNOWN=0
V_BLOCKING=0

V_EXIT_OK=0
V_EXIT_FAILED=1
V_EXIT_UNMEASURED=2
V_EXIT_BLOCKED=3

# v_reason holds the first FAIL or blocking-UNKNOWN reason seen since the last v_reset,
# so a per-host loop can label that host with what stopped it.
V_REASON=""

# v_reset — start a new subject (a host, usually).
v_reset() { V_REASON=""; }

# _v_detail LINE... — the indented continuation lines every verdict shares.
_v_detail() {
  local line
  for line in "$@"; do echo "        $line"; done
}

# v_pass REASON [DETAIL...] — measured, and good.
#
# `OK   ` with three spaces, not `OK: `, because the preflight prints it as a column and
# operators read it as one. FAIL/WARN/UNKNOWN carry a colon
# because they are followed by prose; a pass is a label.
#
# Colour wraps the LABEL only, never the padding: the spacing is the column, and
# tests/test_deploy_check_scripts.py reads it back verbatim ("OK   51820/udp allowed").
# For the same reason there is no symbol here — a ✓ ahead of OK would widen every line.
# common.sh empties the colour variables off a TTY, so plain output is byte-identical.
v_pass() {
  printf '  %sOK%s   %s\n' "$C_GREEN" "$C_OFF" "$1"
  shift
  _v_detail "$@"
  V_PASS=$((V_PASS + 1))
}

# v_fail REASON [DETAIL...] — measured, and bad.
#
# REASON is captured BEFORE the shift. Reading $1 afterwards would record the *detail*
# line as the verdict — "BLOCKED — Got: <nothing>, expected shell-ok-0" instead of
# "BLOCKED — a POSIX command did not survive this host's login shell", which is the half
# that says what is wrong.
v_fail() {
  local reason="$1"
  printf '  %sFAIL:%s %s\n' "$C_RED" "$C_OFF" "$reason"
  shift
  _v_detail "$@"
  V_FAIL=$((V_FAIL + 1))
  [ -n "$V_REASON" ] || V_REASON="$reason"
}

# v_warn REASON [DETAIL...] — measured, and worth saying, but not a fault.
#
# A firewall reading cannot be a failure: a rule scoped to a source address is correct
# and does not match a port grep, so refusing the deploy over one would block correctly
# configured fleets. Warnings do not affect the exit code.
v_warn() {
  printf '  %sWARN:%s %s\n' "$C_YELLOW" "$C_OFF" "$1"
  shift
  _v_detail "$@"
  V_WARN=$((V_WARN + 1))
}
V_WARN=0

# v_unknown REASON [DETAIL...] — NOT measured. Never OK, never a failure.
v_unknown() {
  printf '  %sUNKNOWN:%s %s\n' "$C_CYAN" "$C_OFF" "$1"
  shift
  _v_detail "$@"
  V_UNKNOWN=$((V_UNKNOWN + 1))
}

# v_unknown_blocking REASON [DETAIL...] — not measured, and it is a security control.
v_unknown_blocking() {
  local reason="$1"
  printf '  %sUNKNOWN (blocking):%s %s\n' "$C_CYAN" "$C_OFF" "$reason"
  shift
  _v_detail "$@"
  V_UNKNOWN=$((V_UNKNOWN + 1))
  V_BLOCKING=$((V_BLOCKING + 1))
  [ -n "$V_REASON" ] || V_REASON="$reason"
}

# v_tally — "N passed, M failed, K not measured", plus warnings when there are any.
#
# The unmeasured count is in every banner, unconditionally, including a clean run. An
# operator who only ever sees it when something is wrong learns to read its absence as
# "fine".
v_tally() {
  local out
  out=$(printf '%d passed, %d failed, %d not measured' "$V_PASS" "$V_FAIL" "$V_UNKNOWN")
  [ "$V_WARN" -gt 0 ] && out="${out}, ${V_WARN} warning(s)"
  printf '%s' "$out"
}

# v_status — the exit code the tallies imply. Prints it; does not exit.
v_status() {
  if [ "$V_FAIL" -gt 0 ]; then
    printf '%d' "$V_EXIT_FAILED"
  elif [ "$V_BLOCKING" -gt 0 ]; then
    printf '%d' "$V_EXIT_BLOCKED"
  elif [ "$V_PASS" -eq 0 ] && [ "$V_UNKNOWN" -gt 0 ]; then
    printf '%d' "$V_EXIT_UNMEASURED"
  else
    printf '%d' "$V_EXIT_OK"
  fi
}
