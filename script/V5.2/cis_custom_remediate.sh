#!/bin/bash
#===============================================================================
# cis_custom_remediate.sh — your own site-specific remediation items.
#
# This file is OPTIONAL. If it exists next to cis_remediate.sh, it gets
# sourced automatically at the end of every remediation run (as section
# "8", so it never collides with a real CIS section number). Delete or
# rename it to disable custom items entirely.
#
# It runs inside cis_remediate.sh, so every function/variable that script
# defines is already available here — you don't need to redeclare colors,
# helpers, CFG_* config values, etc. The one you'll actually use:
#
#   run_command "<shell command>" "<id> <description>"
#     e.g. run_command "sed -i '/Defaults.*!use_pty/d' /etc/sudoers" \
#                       "5.2.2 Remove !use_pty from /etc/sudoers"
#
#   run_command "<id>" "<shell command>" "<description>"
#     (same thing, id/description split out as separate arguments instead
#     of packed into one string — useful if your description has spaces
#     right after the id and you don't want to rely on word-splitting)
#     e.g. run_command "5.2.2" "sed -i '/Defaults.*!use_pty/d' /etc/sudoers" \
#                       "Remove !use_pty from /etc/sudoers"
#
# Both forms respect --dry-run (preview only, nothing runs), --exclude
# (by id, same prefix-match rules as every built-in item), and count
# toward the same Applied/Skipped/Failed totals, JSON output, and log
# file as everything else.
#
# IMPORTANT: run_command does NOT know what files your command touches,
# so it can't back them up automatically the way ensure_line/set_perm do
# for built-in items. Make your command idempotent (safe to run more than
# once) and, if you want a backup, do it yourself as part of the command:
#   run_command "cp -a /etc/sudoers /etc/sudoers.bak.\$(date +%s) && sed -i ... /etc/sudoers" \
#               "8.1 Remove !use_pty from sudoers"
#
# Use an ID prefix like "8.x" so it's obviously not a real CIS item, and
# so --exclude patterns for real items never accidentally catch yours too.
#
# --------------------------------------------------------------------------
# EXAMPLES (copy, edit, uncomment):
# --------------------------------------------------------------------------

# run_command "sed -i '/Defaults.*!use_pty/d' /etc/sudoers" \
#             "8.1 Remove !use_pty override from /etc/sudoers"

# run_command "8.2" \
#             "systemctl disable --now some-legacy-service 2>/dev/null || true" \
#             "Disable our decommissioned legacy service"

# run_command "mkdir -p /etc/our-app && chmod 750 /etc/our-app && chown root:our-app-group /etc/our-app" \
#             "8.3 Lock down /etc/our-app to the our-app-group"
