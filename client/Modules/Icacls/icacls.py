from havoc import Demon, RegisterCommand, RegisterModule

def icacls( demonID, *params ):
    TaskID : str    = None
    demon  : Demon  = None
    packer = Packer()
    demon  = Demon( demonID )
    num_params = len(params)
    if num_params == 0:
        demon.ConsoleWrite( demon.CONSOLE_ERROR, "Missing path argument. Usage: icacls <path>" )
        return False
    path = params[0]
    TaskID = demon.ConsoleWrite( demon.CONSOLE_TASK, f"Tasked demon to read ACLs for: {path}" )
    packer.addstr( path )
    demon.InlineExecute( TaskID, "go", f"bin/icacls.x64.o", packer.getbuffer(), False )
    return TaskID

RegisterCommand( icacls, "", "icacls", "Read file/directory ACLs in human-readable format", 0, "<path>", "C:\\Windows" )
