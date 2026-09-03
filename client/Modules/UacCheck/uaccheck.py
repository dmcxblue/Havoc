"""
UacCheck — recon-only UAC bypass feasibility checker.

Companion to UacBonanza (icyguider/UAC-BOF-Bonanza).  Checks each
technique's preconditions on the target — OS version, UAC settings,
token integrity, file existence, registry keys — and reports which
bypasses would succeed, without executing any of them.

Wire format: single int (mode 0-8) packed via the shared Packer.
"""

from havoc import Demon, RegisterCommand, RegisterModule

BOF_PATH = "bin/uaccheck.x64.o"

def _make_check(mode, desc):
    def handler(demonID, *params):
        demon  = Demon(demonID)
        packer = Packer()
        TaskID = demon.ConsoleWrite(demon.CONSOLE_TASK, f"Tasked demon: {desc}")
        packer.addint(mode)
        demon.InlineExecute(TaskID, "go", BOF_PATH, packer.getbuffer(), False)
        return TaskID
    return handler


RegisterModule("uac-check", "UAC bypass feasibility checks (check before firing uac-bypass)",
               "", "[subcommand]", "", "")

RegisterCommand(_make_check(0, "Run all UAC bypass checks"),
    "uac-check", "all",
    "Run all UAC bypass feasibility checks",
    0, "", "")

RegisterCommand(_make_check(1, "Show environment info (OS, UAC, token)"),
    "uac-check", "env",
    "Show OS version, UAC settings, integrity level, admin membership",
    0, "", "")

RegisterCommand(_make_check(2, "Check TrustedPathDLLHijack feasibility"),
    "uac-check", "trustedpath",
    "Check if TrustedPathDLLHijack UAC bypass would work",
    0, "", "")

RegisterCommand(_make_check(3, "Check SilentCleanupWinDir feasibility"),
    "uac-check", "silentcleanup",
    "Check if SilentCleanup windir hijack would work",
    0, "", "")

RegisterCommand(_make_check(4, "Check SSPI Datagram feasibility"),
    "uac-check", "sspidatagram",
    "Check if SSPI Datagram Contexts bypass would work",
    0, "", "")

RegisterCommand(_make_check(5, "Check RegistryShellCommand feasibility"),
    "uac-check", "registrycommand",
    "Check if ms-settings registry command hijack would work",
    0, "", "")

RegisterCommand(_make_check(6, "Check CmstpElevatedCOM feasibility"),
    "uac-check", "elevatedcom",
    "Check if ICMLuaUtil elevated COM bypass would work",
    0, "", "")

RegisterCommand(_make_check(7, "Check ColorDataProxy feasibility"),
    "uac-check", "colordataproxy",
    "Check if ColorDataProxy + ICMLuaUtil bypass would work",
    0, "", "")

RegisterCommand(_make_check(8, "Check EditionUpgradeManager feasibility"),
    "uac-check", "editionupgrade",
    "Check if EditionUpgradeManager COM bypass would work",
    0, "", "")
