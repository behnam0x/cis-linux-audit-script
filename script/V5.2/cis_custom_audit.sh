#!/bin/bash
#===============================================================================
# cis_custom_audit.sh — your own site-specific audit checks.
#
# This file is OPTIONAL. If it exists next to cis_audit.sh, it gets sourced
# automatically at the end of every audit run (as section "8", so it never
# collides with a real CIS section number). Delete or rename it to disable
# custom checks entirely.
#
# It runs inside cis_audit.sh, so every function/variable that script
# defines is already available here — you don't need to redeclare colors,
# helpers, etc. The two you'll actually use:
#
#   check "<id>" "<description>" "<test-command>" ["<diagnostic-command>"]
#     - test-command should exit 0 for PASS, non-zero for FAIL.
#     - diagnostic-command (optional) runs only on FAIL and its output is
#       shown as a "why" hint — use it to print the actual current value.
#
#   manual_check "<id>" "<description>"
#     - for anything that genuinely needs a human to judge, not a script.
#
# Use an ID prefix like "8.x" so it's obviously not a real CIS item, and so
# --exclude patterns for real items never accidentally catch yours too.
#
# --------------------------------------------------------------------------
# EXAMPLES (copy, edit, uncomment):
# --------------------------------------------------------------------------

# check "8.1" "Ensure our internal monitoring agent is installed" \
#   "rpm -q our-monitoring-agent &>/dev/null"

# check "8.2" "Ensure /etc/sudoers has no lingering !use_pty override" \
#   "! grep -Eq 'Defaults.*!use_pty' /etc/sudoers" \
#   "grep -E 'Defaults.*!use_pty' /etc/sudoers"

# check "8.3" "Ensure the company MOTD banner text is present" \
#   "grep -q 'ACME Corp — Authorized Use Only' /etc/motd"

# manual_check "8.4" "Confirm the VPN client config matches the approved template"
