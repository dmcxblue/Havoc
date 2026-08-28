from havoc import Demon, RegisterCommand, RegisterModule

def privkit_all( demonID, *param ):
    TaskID : str = None
    demon  : Demon = None
    demon  = Demon( demonID )
    TaskID = demon.ConsoleWrite( demon.CONSOLE_TASK, "Running all PrivKit privilege escalation checks..." )
    demon.InlineExecute( TaskID, "go", "bin/PrivKitAll.x64.o", b'', False )
    return TaskID

RegisterModule( "privkit", "Privilege escalation checks", "", "[command]", "", "" )
RegisterCommand( privkit_all, "privkit", "all", "Run all PrivKit privilege escalation checks", 0, "", "" )
