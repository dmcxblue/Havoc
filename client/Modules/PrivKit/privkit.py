from havoc import Demon, RegisterCommand, RegisterModule

BOF_PATH = "bin/PrivKitAll.x64.o"

def _make_check( check_id, desc ):
    def handler( demonID, *param ):
        TaskID : str = None
        demon  : Demon = None
        packer = Packer()
        demon  = Demon( demonID )
        TaskID = demon.ConsoleWrite( demon.CONSOLE_TASK, f"Tasked demon: {desc}" )
        packer.addint( check_id )
        demon.InlineExecute( TaskID, "go", BOF_PATH, packer.getbuffer(), False )
        return TaskID
    return handler

RegisterModule( "privkit", "Privilege escalation checks", "", "[command]", "", "" )

RegisterCommand( _make_check( 0,  "Run all privilege escalation checks" ),        "privkit", "all",            "Run all privilege escalation checks",        0, "", "" )
RegisterCommand( _make_check( 1,  "Check AlwaysInstallElevated" ),                "privkit", "alwaysinstall",   "Check AlwaysInstallElevated",                0, "", "" )
RegisterCommand( _make_check( 2,  "Check Unquoted Service Paths" ),               "privkit", "unquoted",       "Check Unquoted Service Paths",               0, "", "" )
RegisterCommand( _make_check( 3,  "Check Modifiable Services (weak DACL)" ),      "privkit", "modifiable",     "Check Modifiable Services (weak DACL)",      0, "", "" )
RegisterCommand( _make_check( 4,  "Check AutoLogon Credentials" ),                "privkit", "autologon",      "Check AutoLogon Credentials",                0, "", "" )
RegisterCommand( _make_check( 5,  "Check Writable Scheduled Task Files" ),        "privkit", "schtask",        "Check Writable Scheduled Task Files",        0, "", "" )
RegisterCommand( _make_check( 6,  "Check Writable PATH Directories" ),            "privkit", "writablepath",   "Check Writable PATH Directories",            0, "", "" )
RegisterCommand( _make_check( 7,  "Check UAC Settings" ),                         "privkit", "uac",            "Check UAC Settings",                         0, "", "" )
RegisterCommand( _make_check( 8,  "Check Token Privileges" ),                     "privkit", "privileges",     "Check Token Privileges",                     0, "", "" )
RegisterCommand( _make_check( 9,  "Check Cached GPP Passwords" ),                 "privkit", "gpp",            "Check Cached GPP Passwords",                 0, "", "" )
RegisterCommand( _make_check( 10, "Check Unattend/Sysprep Credential Files" ),    "privkit", "unattend",       "Check Unattend/Sysprep Credential Files",    0, "", "" )
