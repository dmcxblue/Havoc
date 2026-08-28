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

RegisterModule( "privkit", "Privilege escalation checks (mertdas/PrivKit)", "", "[command]", "", "" )

RegisterCommand( _make_check( 0,  "Run all privilege escalation checks" ),        "privkit", "all",              "Run all privilege escalation checks",          0, "", "" )
RegisterCommand( _make_check( 1,  "Check AlwaysInstallElevated" ),                "privkit", "alwaysinstall",    "Check AlwaysInstallElevated",                  0, "", "" )
RegisterCommand( _make_check( 2,  "Check Unquoted Service Paths" ),               "privkit", "unquoted",        "Check Unquoted Service Paths",                 0, "", "" )
RegisterCommand( _make_check( 3,  "Check Modifiable Services (weak DACL)" ),      "privkit", "modifiable",      "Check Modifiable Services (weak DACL)",        0, "", "" )
RegisterCommand( _make_check( 4,  "Check AutoLogon Credentials" ),                "privkit", "autologon",       "Check AutoLogon Credentials",                  0, "", "" )
RegisterCommand( _make_check( 5,  "Check Credential Manager" ),                   "privkit", "credmanager",     "Check Credential Manager",                     0, "", "" )
RegisterCommand( _make_check( 6,  "Check Hijackable PATH Directories" ),          "privkit", "hijackablepath",  "Check Hijackable PATH Directories",            0, "", "" )
RegisterCommand( _make_check( 7,  "Check Modifiable Autorun Entries" ),           "privkit", "modifiableautorun","Check Modifiable Autorun Entries",             0, "", "" )
RegisterCommand( _make_check( 8,  "Check Token Privileges" ),                     "privkit", "tokenprivileges", "Check Token Privileges",                       0, "", "" )
RegisterCommand( _make_check( 9,  "Check PowerShell History" ),                   "privkit", "powershellhistory","Check PowerShell History",                     0, "", "" )
RegisterCommand( _make_check( 10, "Check UAC Status" ),                           "privkit", "uac",             "Check UAC Status",                             0, "", "" )
