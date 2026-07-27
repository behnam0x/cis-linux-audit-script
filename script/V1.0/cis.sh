#!/bin/bash
#===============================================================================
# cis.sh — single entry point for the CIS Benchmark toolkit (OL9/RHEL9,
# with Debian/Ubuntu audit support).
#
# This is a MENU/LAUNCHER, not a merge of the two scripts into one file.
# cis_audit.sh and cis_remediate.sh stay separate on purpose: they're ~1300
# and ~1800 lines each, and folding them into one script would mean giving
# every function and variable in both a unique name to avoid collisions
# (both use names like `log`, `say`, `check`, `PAM_SU`, `LOG_FILE`, ...).
# That's a lot of moving parts to get silently wrong. This launcher gives
# you the "one command" experience without that risk: it just calls
# whichever script you pick, with the flags you choose from the menu.
#
# Usage:
#   sudo ./cis.sh              # interactive menu
#   sudo ./cis.sh audit        # jump straight to an audit run
#   sudo ./cis.sh remediate    # jump straight to a remediate run
#   sudo ./cis.sh configure    # jump straight to the config wizard
#===============================================================================

set -uo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; WHITE='\033[1;37m'; BOLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AUDIT_SH="${SCRIPT_DIR}/cis_audit.sh"
REMEDIATE_SH="${SCRIPT_DIR}/cis_remediate.sh"

say() { echo -e "$*"; }

check_scripts_present() {
  local missing=0
  [ -f "$AUDIT_SH" ] || { say "  ${RED}✗${NC} cis_audit.sh not found next to cis.sh (expected: ${AUDIT_SH})"; missing=1; }
  [ -f "$REMEDIATE_SH" ] || { say "  ${RED}✗${NC} cis_remediate.sh not found next to cis.sh (expected: ${REMEDIATE_SH})"; missing=1; }
  if [ "$missing" -eq 1 ]; then
    say ""
    say "  All three files need to live in the same directory:"
    say "    cis.sh, cis_audit.sh, cis_remediate.sh"
    exit 1
  fi
  chmod +x "$AUDIT_SH" "$REMEDIATE_SH" 2>/dev/null || true
}

banner() {
  say ""
  say "${BOLD}${WHITE}+==========================================================+${NC}"
  say "${BOLD}${WHITE}|              CIS BENCHMARK TOOLKIT                      |${NC}"
  say "${BOLD}${WHITE}+==========================================================+${NC}"
  say ""
}

pause() {
  say ""
  read -r -p "Press Enter to return to the menu... " _ </dev/tty 2>/dev/null || true
}

run_audit() {
  say ""
  say "${CYAN}How would you like to run the audit?${NC}"
  say "  1) Full audit (all sections)"
  say "  2) Just one section (e.g. 5.1)"
  say "  3) Quiet mode (only FAIL/MANUAL shown)"
  say "  4) Back to main menu"
  read -r -p "Choice [1-4]: " c </dev/tty
  case "$c" in
    1) bash "$AUDIT_SH" ;;
    2) read -r -p "Section number (e.g. 5.1): " s </dev/tty; bash "$AUDIT_SH" --section "$s" ;;
    3) bash "$AUDIT_SH" -q ;;
    4) return 0 ;;
    *) say "${YELLOW}Not a valid choice.${NC}" ;;
  esac
  pause
}

run_remediate() {
  say ""
  say "${CYAN}How would you like to run remediation?${NC}"
  say "  1) Preview only — dry run, changes nothing"
  say "  2) Full apply (interactive: config wizard + per-item install prompts)"
  say "  3) Full apply, non-interactive (--yes — uses saved config, no prompts)"
  say "  4) Just one section (e.g. 5.1), interactive"
  say "  5) Include aggressive items (SELinux enforcing, extra kernel-module blocks)"
  say "  6) Restore a previous run from backup"
  say "  7) Back to main menu"
  read -r -p "Choice [1-7]: " c </dev/tty
  case "$c" in
    1) bash "$REMEDIATE_SH" --dry-run ;;
    2) bash "$REMEDIATE_SH" ;;
    3) bash "$REMEDIATE_SH" --yes ;;
    4) read -r -p "Section number (e.g. 5.1): " s </dev/tty; bash "$REMEDIATE_SH" --section "$s" ;;
    5)
      say "${YELLOW}--aggressive touches SELinux enforcing mode, GRUB, and extra kernel module blocks.${NC}"
      say "${YELLOW}These usually need a reboot and can affect access if something isn't labeled/configured right.${NC}"
      read -r -p "Continue with --aggressive? (yes/no) [no]: " a </dev/tty
      case "$a" in
        [Yy]|[Yy][Ee][Ss]) bash "$REMEDIATE_SH" --aggressive ;;
        *) say "Cancelled." ;;
      esac
      ;;
    6)
      say "Available backups:"
      ls -1 /var/backups/cis_remediation/ 2>/dev/null || say "  (none found)"
      read -r -p "Timestamp to restore (blank = cancel): " ts </dev/tty
      [ -n "$ts" ] && bash "$REMEDIATE_SH" --restore "$ts"
      ;;
    7) return 0 ;;
    *) say "${YELLOW}Not a valid choice.${NC}" ;;
  esac
  pause
}

run_configure() {
  say ""
  say "${CYAN}Sets the values remediation reuses everywhere (admin group/user, NTP${NC}"
  say "${CYAN}servers, firewall ports, GRUB password). By default this opens the${NC}"
  say "${CYAN}config file directly in an editor — change the values, save, done.${NC}"
  say "${CYAN}Saved to /etc/cis-toolkit/remediate.conf for every future run.${NC}"
  say ""
  bash "$REMEDIATE_SH" --configure-only
  pause
}

edit_in_editor() {
  local file="$1"
  local editor="${EDITOR:-}"
  if [ -z "$editor" ]; then
    for cand in nano vim vi; do command -v "$cand" &>/dev/null && { editor="$cand"; break; }; done
  fi
  if [ -n "$editor" ]; then
    "$editor" "$file" </dev/tty >/dev/tty 2>/dev/tty
  else
    say "${YELLOW}No editor found. Edit this file yourself with any editor:${NC}"
    say "  ${CYAN}${file}${NC}"
    read -r -p "  Press Enter once you've saved your changes... " _ </dev/tty
  fi
}

run_custom_items() {
  say ""
  say "${CYAN}Add your own site-specific checks/fixes, run automatically as section${NC}"
  say "${CYAN}'8' at the end of every audit/remediate run — no need to touch the${NC}"
  say "${CYAN}core scripts. Each file has commented examples showing the syntax.${NC}"
  say ""
  say "  1) Edit custom AUDIT items   (${SCRIPT_DIR}/cis_custom_audit.sh)"
  say "  2) Edit custom REMEDIATE items (${SCRIPT_DIR}/cis_custom_remediate.sh)"
  say "  3) Back to main menu"
  read -r -p "Choice [1-3]: " c </dev/tty
  case "$c" in
    1)
      [ -f "${SCRIPT_DIR}/cis_custom_audit.sh" ] || touch "${SCRIPT_DIR}/cis_custom_audit.sh"
      edit_in_editor "${SCRIPT_DIR}/cis_custom_audit.sh"
      bash -n "${SCRIPT_DIR}/cis_custom_audit.sh" 2>&1 && say "${GREEN}Saved — syntax OK.${NC}" || say "${RED}Syntax error in the file — fix it before your next audit run, or it will abort at that point.${NC}"
      ;;
    2)
      [ -f "${SCRIPT_DIR}/cis_custom_remediate.sh" ] || touch "${SCRIPT_DIR}/cis_custom_remediate.sh"
      edit_in_editor "${SCRIPT_DIR}/cis_custom_remediate.sh"
      bash -n "${SCRIPT_DIR}/cis_custom_remediate.sh" 2>&1 && say "${GREEN}Saved — syntax OK.${NC}" || say "${RED}Syntax error in the file — fix it before your next remediate run, or it will abort at that point.${NC}"
      ;;
    3) return 0 ;;
    *) say "${YELLOW}Not a valid choice.${NC}" ;;
  esac
  pause
}

show_help() {
  say ""
  say "${BOLD}What each part does:${NC}"
  say "  ${GREEN}Audit${NC}         Read-only. Checks the system against CIS OL9/RHEL9 items"
  say "                 and reports PASS/FAIL/MANUAL for each. Changes nothing."
  say "  ${GREEN}Remediate${NC}     Applies fixes for FAIL items it can safely automate. Backs"
  say "                 up every file it touches first, so it's always reversible"
  say "                 via '${REMEDIATE_SH##*/} --restore <timestamp>'."
  say "  ${GREEN}Configure${NC}     Set the values remediation reuses everywhere (admin group,"
  say "                 NTP servers, firewall ports, GRUB password) once, instead"
  say "                 of being asked mid-run every time."
  say "  ${GREEN}Custom Items${NC}  Add your own checks/fixes on top of the built-in CIS items,"
  say "                 without editing the core scripts. See the comments in"
  say "                 cis_custom_audit.sh / cis_custom_remediate.sh."
  say ""
  say "${BOLD}Normal workflow:${NC}"
  say "  1. Run Audit to see where things stand."
  say "  2. Run Remediate (dry-run first if you want to preview)."
  say "  3. Run Audit again to confirm FAILs became PASSes."
  say "  4. Review anything still marked MANUAL — those need a human judgment"
  say "     call (e.g. reviewing SUID binaries, setting firewall zones for your"
  say "     specific network) and aren't auto-fixed on purpose."
  say ""
  say "${BOLD}Useful direct flags${NC} (skip the menu entirely):"
  say "  ${CYAN}sudo ./cis.sh audit${NC}                     jump to the audit submenu"
  say "  ${CYAN}sudo ./cis_audit.sh --section 5.1${NC}       audit just SSH"
  say "  ${CYAN}sudo ./cis_remediate.sh --dry-run${NC}       preview every change, apply nothing"
  say "  ${CYAN}sudo ./cis_remediate.sh --yes${NC}           apply everything, no prompts (uses saved config)"
  say "  ${CYAN}sudo ./cis_remediate.sh --configure-only${NC} just update saved settings"
  say "  ${CYAN}sudo ./cis_remediate.sh -h${NC} / ${CYAN}./cis_audit.sh -h${NC}  full flag reference for each script"
  say ""
  say "${BOLD}Nothing extra is required before your first run${NC} — the config wizard"
  say "runs automatically the first time you remediate (unless you pass --yes"
  say "or --no-wizard), and every answer has a sane default if you just press Enter."
  pause
}

main_menu() {
  while true; do
    banner
    say "  ${BOLD}1)${NC} Run Audit          ${DIM}(read-only, check current state)${NC}"
    say "  ${BOLD}2)${NC} Run Remediate      ${DIM}(apply fixes, backed up + reversible)${NC}"
    say "  ${BOLD}3)${NC} Configure          ${DIM}(set admin group, NTP, firewall ports, GRUB password)${NC}"
    say "  ${BOLD}4)${NC} Custom Items       ${DIM}(add your own checks/fixes, no core-script edits)${NC}"
    say "  ${BOLD}5)${NC} Help               ${DIM}(what does what, suggested workflow)${NC}"
    say "  ${BOLD}6)${NC} Exit"
    say ""
    read -r -p "Choice [1-6]: " choice </dev/tty
    case "$choice" in
      1) run_audit ;;
      2) run_remediate ;;
      3) run_configure ;;
      4) run_custom_items ;;
      5) show_help ;;
      6) say "Bye."; exit 0 ;;
      *) say "${YELLOW}Not a valid choice.${NC}"; sleep 1 ;;
    esac
  done
}

main() {
  if [ "$(id -u)" -ne 0 ]; then
    say "${RED}Run this as root — both cis_audit.sh and cis_remediate.sh need it to read/write system files.${NC}"
    exit 1
  fi
  check_scripts_present

  case "${1:-}" in
    audit) run_audit ;;
    remediate) run_remediate ;;
    configure) run_configure ;;
    custom) run_custom_items ;;
    help|-h|--help) show_help ;;
    "") main_menu ;;
    *) say "Unknown argument: $1"; say "Usage: $0 [audit|remediate|configure|custom|help]"; exit 1 ;;
  esac
}

main "$@"
