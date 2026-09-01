from havoc import Demon, RegisterCommand, RegisterModule


def copy_cmd(demonID, *params):
    demon = Demon(demonID)

    if len(params) < 2:
        demon.ConsoleWrite(demon.CONSOLE_ERROR,
                           "Usage: copy <source> <destination>")
        return False

    src = params[0]
    dst = params[1]

    packer = Packer()
    packer.addstr(src)
    packer.addstr(dst)

    TaskID = demon.ConsoleWrite(
        demon.CONSOLE_TASK,
        f"Tasked demon to copy '{src}' -> '{dst}'"
    )
    demon.InlineExecute(TaskID, "go", "bin/copy.x64.o", packer.getbuffer(), False)
    return TaskID


RegisterCommand(
    copy_cmd,
    "",
    "copy",
    "Copy a file from source to destination (always overwrites; dest may be a file or directory)",
    0,
    "<source> <destination>",
    "C:\\temp\\a.txt C:\\temp\\b.txt"
)
