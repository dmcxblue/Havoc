from havoc import Demon, RegisterCommand, RegisterModule


def sc_sdshow_cmd(demonID, *params):
    demon = Demon(demonID)

    if len(params) < 1:
        demon.ConsoleWrite(demon.CONSOLE_ERROR,
                           "Usage: sc_sdshow <service_name>")
        return False

    svc = params[0]

    packer = Packer()
    packer.addstr(svc)

    TaskID = demon.ConsoleWrite(
        demon.CONSOLE_TASK,
        f"Tasked demon to read service security descriptor: {svc}"
    )
    demon.InlineExecute(TaskID, "go", "bin/sc_sdshow.x64.o", packer.getbuffer(), False)
    return TaskID


RegisterCommand(
    sc_sdshow_cmd,
    "",
    "sc_sdshow",
    "Show a service's security descriptor (raw SDDL + friendly parsed DACL)",
    0,
    "<service_name>",
    "Spooler"
)
