/*
 * bitsadmin BOF — BITS via COM, no bitsadmin.exe.
 *
 * Modes packed by bitsadmin.py:
 *   0 create    int type, str name          type: 0=DOWNLOAD 1=UPLOAD 2=UPLOAD-REPLY
 *   1 addfile   str job, str remote, str local
 *   2 notify    str job, str program, str params   empty = NULL
 *   3 resume    str job
 *   4 list      int flags   bit0=VERBOSE bit1=ALLUSERS
 *   5 cancel    str job
 *   6 complete  str job
 *   7 priority  str job, int prio           0=FOREGROUND .. 3=LOW
 *   8 retry     str job, int seconds
 *
 * Job identifier is a display name or a {GUID}, same as bitsadmin.exe.
 */

#include <windows.h>
#include "../../RemoteOps/CS-Remote-OPs-BOF/src/common/bofdefs.h"
#include "../../RemoteOps/CS-Remote-OPs-BOF/src/common/base.c"

#ifndef COINIT_APARTMENTTHREADED
#define COINIT_APARTMENTTHREADED 0x2
#endif
#ifndef CLSCTX_INPROC_SERVER
#define CLSCTX_INPROC_SERVER 0x1
#endif
#ifndef CLSCTX_LOCAL_SERVER
#define CLSCTX_LOCAL_SERVER 0x4
#endif
#ifndef CLSCTX_ALL
#define CLSCTX_ALL 0x17
#endif
#ifndef RPC_E_CHANGED_MODE
#define RPC_E_CHANGED_MODE ((HRESULT)0x80010106L)
#endif

#define MODE_CREATE   0
#define MODE_ADDFILE  1
#define MODE_NOTIFY   2
#define MODE_RESUME   3
#define MODE_LIST     4
#define MODE_CANCEL   5
#define MODE_COMPLETE 6
#define MODE_PRIORITY 7
#define MODE_RETRY    8

#define BG_JOB_TYPE_DOWNLOAD      0
#define BG_JOB_TYPE_UPLOAD        1
#define BG_JOB_TYPE_UPLOAD_REPLY  2

#define BG_JOB_PRIORITY_FOREGROUND 0
#define BG_JOB_PRIORITY_HIGH       1
#define BG_JOB_PRIORITY_NORMAL     2
#define BG_JOB_PRIORITY_LOW        3

#define BG_JOB_STATE_QUEUED          0
#define BG_JOB_STATE_CONNECTING      1
#define BG_JOB_STATE_TRANSFERRING    2
#define BG_JOB_STATE_SUSPENDED       3
#define BG_JOB_STATE_ERROR           4
#define BG_JOB_STATE_TRANSIENT_ERROR 5
#define BG_JOB_STATE_TRANSFERRED     6
#define BG_JOB_STATE_ACKNOWLEDGED    7
#define BG_JOB_STATE_CANCELLED       8

#define BG_JOB_ENUM_ALL_USERS  0x0001
#define BG_NOTIFY_JOB_TRANSFERRED 0x0001
#define BG_NOTIFY_JOB_ERROR       0x0002
#define BG_SIZE_UNKNOWN ((UINT64)(INT64)-1)

typedef struct {
    UINT64 BytesTotal;
    UINT64 BytesTransferred;
    ULONG  FilesTotal;
    ULONG  FilesTransferred;
} BG_JOB_PROGRESS;

/* ---- COM vtables (C, no bits.h — keeps the BOF free of ole2 collisions) ---- */

typedef struct IBackgroundCopyJob IBackgroundCopyJob;
typedef struct IBackgroundCopyJob2 IBackgroundCopyJob2;
typedef struct IBackgroundCopyManager IBackgroundCopyManager;
typedef struct IEnumBackgroundCopyJobs IEnumBackgroundCopyJobs;

typedef struct IBackgroundCopyJobVtbl {
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(IBackgroundCopyJob *, REFIID, void **);
    ULONG   (STDMETHODCALLTYPE *AddRef)(IBackgroundCopyJob *);
    ULONG   (STDMETHODCALLTYPE *Release)(IBackgroundCopyJob *);
    HRESULT (STDMETHODCALLTYPE *AddFileSet)(IBackgroundCopyJob *, ULONG, void *);
    HRESULT (STDMETHODCALLTYPE *AddFile)(IBackgroundCopyJob *, LPCWSTR, LPCWSTR);
    HRESULT (STDMETHODCALLTYPE *EnumFiles)(IBackgroundCopyJob *, void **);
    HRESULT (STDMETHODCALLTYPE *Suspend)(IBackgroundCopyJob *);
    HRESULT (STDMETHODCALLTYPE *Resume)(IBackgroundCopyJob *);
    HRESULT (STDMETHODCALLTYPE *Cancel)(IBackgroundCopyJob *);
    HRESULT (STDMETHODCALLTYPE *Complete)(IBackgroundCopyJob *);
    HRESULT (STDMETHODCALLTYPE *GetId)(IBackgroundCopyJob *, GUID *);
    HRESULT (STDMETHODCALLTYPE *GetType)(IBackgroundCopyJob *, ULONG *);
    HRESULT (STDMETHODCALLTYPE *GetProgress)(IBackgroundCopyJob *, BG_JOB_PROGRESS *);
    HRESULT (STDMETHODCALLTYPE *GetTimes)(IBackgroundCopyJob *, void *);
    HRESULT (STDMETHODCALLTYPE *GetState)(IBackgroundCopyJob *, ULONG *);
    HRESULT (STDMETHODCALLTYPE *GetError)(IBackgroundCopyJob *, void **);
    HRESULT (STDMETHODCALLTYPE *GetOwner)(IBackgroundCopyJob *, LPWSTR *);
    HRESULT (STDMETHODCALLTYPE *SetDisplayName)(IBackgroundCopyJob *, LPCWSTR);
    HRESULT (STDMETHODCALLTYPE *GetDisplayName)(IBackgroundCopyJob *, LPWSTR *);
    HRESULT (STDMETHODCALLTYPE *SetDescription)(IBackgroundCopyJob *, LPCWSTR);
    HRESULT (STDMETHODCALLTYPE *GetDescription)(IBackgroundCopyJob *, LPWSTR *);
    HRESULT (STDMETHODCALLTYPE *SetPriority)(IBackgroundCopyJob *, ULONG);
    HRESULT (STDMETHODCALLTYPE *GetPriority)(IBackgroundCopyJob *, ULONG *);
    HRESULT (STDMETHODCALLTYPE *SetNotifyFlags)(IBackgroundCopyJob *, ULONG);
    HRESULT (STDMETHODCALLTYPE *GetNotifyFlags)(IBackgroundCopyJob *, ULONG *);
    HRESULT (STDMETHODCALLTYPE *SetNotifyInterface)(IBackgroundCopyJob *, IUnknown *);
    HRESULT (STDMETHODCALLTYPE *GetNotifyInterface)(IBackgroundCopyJob *, IUnknown **);
    HRESULT (STDMETHODCALLTYPE *SetMinimumRetryDelay)(IBackgroundCopyJob *, ULONG);
    HRESULT (STDMETHODCALLTYPE *GetMinimumRetryDelay)(IBackgroundCopyJob *, ULONG *);
    HRESULT (STDMETHODCALLTYPE *SetNoProgressTimeout)(IBackgroundCopyJob *, ULONG);
    HRESULT (STDMETHODCALLTYPE *GetNoProgressTimeout)(IBackgroundCopyJob *, ULONG *);
    HRESULT (STDMETHODCALLTYPE *GetErrorCount)(IBackgroundCopyJob *, ULONG *);
    HRESULT (STDMETHODCALLTYPE *SetProxySettings)(IBackgroundCopyJob *, ULONG, const WCHAR *, const WCHAR *);
    HRESULT (STDMETHODCALLTYPE *GetProxySettings)(IBackgroundCopyJob *, ULONG *, LPWSTR *, LPWSTR *);
    HRESULT (STDMETHODCALLTYPE *TakeOwnership)(IBackgroundCopyJob *);
} IBackgroundCopyJobVtbl;

struct IBackgroundCopyJob { IBackgroundCopyJobVtbl *lpVtbl; };

/* Job2 = Job vtable + SetNotifyCmdLine. 32 Job methods after IUnknown. */
typedef struct IBackgroundCopyJob2Vtbl {
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(IBackgroundCopyJob2 *, REFIID, void **);
    ULONG   (STDMETHODCALLTYPE *AddRef)(IBackgroundCopyJob2 *);
    ULONG   (STDMETHODCALLTYPE *Release)(IBackgroundCopyJob2 *);
    void   *JobMethods[32];
    HRESULT (STDMETHODCALLTYPE *SetNotifyCmdLine)(IBackgroundCopyJob2 *, LPCWSTR, LPCWSTR);
    HRESULT (STDMETHODCALLTYPE *GetNotifyCmdLine)(IBackgroundCopyJob2 *, LPWSTR *, LPWSTR *);
} IBackgroundCopyJob2Vtbl;

struct IBackgroundCopyJob2 { IBackgroundCopyJob2Vtbl *lpVtbl; };

typedef struct IBackgroundCopyManagerVtbl {
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(IBackgroundCopyManager *, REFIID, void **);
    ULONG   (STDMETHODCALLTYPE *AddRef)(IBackgroundCopyManager *);
    ULONG   (STDMETHODCALLTYPE *Release)(IBackgroundCopyManager *);
    HRESULT (STDMETHODCALLTYPE *CreateJob)(IBackgroundCopyManager *, LPCWSTR, ULONG, GUID *, IBackgroundCopyJob **);
    HRESULT (STDMETHODCALLTYPE *GetJob)(IBackgroundCopyManager *, REFGUID, IBackgroundCopyJob **);
    HRESULT (STDMETHODCALLTYPE *EnumJobs)(IBackgroundCopyManager *, DWORD, IEnumBackgroundCopyJobs **);
    HRESULT (STDMETHODCALLTYPE *GetErrorDescription)(IBackgroundCopyManager *, HRESULT, DWORD, LPWSTR *);
} IBackgroundCopyManagerVtbl;

struct IBackgroundCopyManager { IBackgroundCopyManagerVtbl *lpVtbl; };

typedef struct IEnumBackgroundCopyJobsVtbl {
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(IEnumBackgroundCopyJobs *, REFIID, void **);
    ULONG   (STDMETHODCALLTYPE *AddRef)(IEnumBackgroundCopyJobs *);
    ULONG   (STDMETHODCALLTYPE *Release)(IEnumBackgroundCopyJobs *);
    HRESULT (STDMETHODCALLTYPE *Next)(IEnumBackgroundCopyJobs *, ULONG, IBackgroundCopyJob **, ULONG *);
    HRESULT (STDMETHODCALLTYPE *Skip)(IEnumBackgroundCopyJobs *, ULONG);
    HRESULT (STDMETHODCALLTYPE *Reset)(IEnumBackgroundCopyJobs *);
    HRESULT (STDMETHODCALLTYPE *Clone)(IEnumBackgroundCopyJobs *, IEnumBackgroundCopyJobs **);
    HRESULT (STDMETHODCALLTYPE *GetCount)(IEnumBackgroundCopyJobs *, ULONG *);
} IEnumBackgroundCopyJobsVtbl;

struct IEnumBackgroundCopyJobs { IEnumBackgroundCopyJobsVtbl *lpVtbl; };

void *memcpy(void *dest, const void *src, size_t n) { return MSVCRT$memcpy(dest, src, n); }
void *memset(void *s, int c, size_t n)              { MSVCRT$memset(s, c, n); return s; }

static HRESULT g_comHr = E_FAIL;

static BOOL ComStart(void)
{
    g_comHr = OLE32$CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    if (SUCCEEDED(g_comHr) || g_comHr == RPC_E_CHANGED_MODE)
        return TRUE;
    internal_printf("[-] CoInitializeEx failed: 0x%08lX\n", (unsigned long)g_comHr);
    return FALSE;
}

static void ComStop(void)
{
    if (g_comHr == S_OK)
        OLE32$CoUninitialize();
}

static void FillGuid(GUID *g, DWORD d1, WORD d2, WORD d3,
                    BYTE b0, BYTE b1, BYTE b2, BYTE b3,
                    BYTE b4, BYTE b5, BYTE b6, BYTE b7)
{
    g->Data1 = d1; g->Data2 = d2; g->Data3 = d3;
    g->Data4[0] = b0; g->Data4[1] = b1; g->Data4[2] = b2; g->Data4[3] = b3;
    g->Data4[4] = b4; g->Data4[5] = b5; g->Data4[6] = b6; g->Data4[7] = b7;
}

static IBackgroundCopyManager *GetManager(void)
{
    /* IID_IBackgroundCopyManager {5CE34C0D-0DC9-4C1F-897C-DAA1B78CEE7C} */
    GUID iid, clsid;
    IBackgroundCopyManager *mgr = NULL;
    HRESULT hr = E_FAIL;
    HRESULT last = E_FAIL;
    DWORD ctxs[3];
    int c, i;

    /* Stack immediates — no .rdata GUID, no CLSIDFromString wchar. */
    FillGuid(&iid, 0x5ce34c0d, 0x0dc9, 0x4c1f,
             0x89, 0x7c, 0xda, 0xa1, 0xb7, 0x8c, 0xee, 0x7c);

    ctxs[0] = CLSCTX_INPROC_SERVER;
    ctxs[1] = CLSCTX_ALL;
    ctxs[2] = CLSCTX_LOCAL_SERVER;

    /*
     * Try every documented BackgroundCopyManager coclass. Wine/mingw bits.h
     * has a WRONG 1.0 CLSID (…3328366b9097); Windows is …3328866daae0.
     */
    for (c = 0; c < 6; c++)
    {
        if (c == 0) /* 1.0 MSDN {4991D34B-80A1-4291-83B6-3328866DAAE0} */
            FillGuid(&clsid, 0x4991d34b, 0x80a1, 0x4291,
                     0x83, 0xb6, 0x33, 0x28, 0x86, 0x6d, 0xaa, 0xe0);
        else if (c == 1) /* 1.5 {F087771F-D74F-4C1A-BB8A-E16ACA9124EA} */
            FillGuid(&clsid, 0xf087771f, 0xd74f, 0x4c1a,
                     0xbb, 0x8a, 0xe1, 0x6a, 0xca, 0x91, 0x24, 0xea);
        else if (c == 2) /* 2.0 {6D18AD12-BDE3-4393-B311-099C346E6DF9} */
            FillGuid(&clsid, 0x6d18ad12, 0xbde3, 0x4393,
                     0xb3, 0x11, 0x09, 0x9c, 0x34, 0x6e, 0x6d, 0xf9);
        else if (c == 3) /* 2.5 {03CA98D6-FF5D-49B8-ABC6-03DD84127020} */
            FillGuid(&clsid, 0x03ca98d6, 0xff5d, 0x49b8,
                     0xab, 0xc6, 0x03, 0xdd, 0x84, 0x12, 0x70, 0x20);
        else if (c == 4) /* 3.0 {659CDEA7-489E-11D9-A9CD-000D56965251} */
            FillGuid(&clsid, 0x659cdea7, 0x489e, 0x11d9,
                     0xa9, 0xcd, 0x00, 0x0d, 0x56, 0x96, 0x52, 0x51);
        else /* Wine/mingw typo 1.0 — last resort */
            FillGuid(&clsid, 0x4991d34b, 0x80a1, 0x4291,
                     0x83, 0xb6, 0x33, 0x28, 0x36, 0x6b, 0x90, 0x97);

        for (i = 0; i < 3; i++)
        {
            mgr = NULL;
            hr = OLE32$CoCreateInstance(&clsid, NULL, ctxs[i], &iid, (LPVOID *)&mgr);
            if (SUCCEEDED(hr) && mgr)
                return mgr;
            last = hr;
        }
    }
    internal_printf("[-] BITS CoCreateInstance failed: 0x%08lX "
                    "(tried 1.0/1.5/2.0/2.5/3.0 INPROC+ALL+LOCAL). "
                    "Is the BITS service installed?\n",
                    (unsigned long)last);
    return NULL;
}

static void PrintW(LPCWSTR w)
{
    char *u;
    if (!w) { internal_printf("(null)"); return; }
    u = Utf16ToUtf8(w);
    if (u) { internal_printf("%s", u); intFree(u); }
    else   internal_printf("(utf16 conversion failed)");
}

static void PrintGuid(const GUID *g)
{
    wchar_t w[40];
    if (OLE32$StringFromGUID2(g, w, 40) > 0)
        PrintW(w);
}

static const char *TypeName(ULONG t)
{
    if (t == BG_JOB_TYPE_DOWNLOAD)     return "DOWNLOAD";
    if (t == BG_JOB_TYPE_UPLOAD)       return "UPLOAD";
    if (t == BG_JOB_TYPE_UPLOAD_REPLY) return "UPLOAD-REPLY";
    return "UNKNOWN";
}

static const char *StateName(ULONG s)
{
    switch (s)
    {
        case BG_JOB_STATE_QUEUED:          return "QUEUED";
        case BG_JOB_STATE_CONNECTING:      return "CONNECTING";
        case BG_JOB_STATE_TRANSFERRING:    return "TRANSFERRING";
        case BG_JOB_STATE_SUSPENDED:       return "SUSPENDED";
        case BG_JOB_STATE_ERROR:           return "ERROR";
        case BG_JOB_STATE_TRANSIENT_ERROR: return "TRANSIENT_ERROR";
        case BG_JOB_STATE_TRANSFERRED:     return "TRANSFERRED";
        case BG_JOB_STATE_ACKNOWLEDGED:    return "ACKNOWLEDGED";
        case BG_JOB_STATE_CANCELLED:       return "CANCELLED";
        default:                           return "UNKNOWN";
    }
}

static const char *PrioName(ULONG p)
{
    if (p == BG_JOB_PRIORITY_FOREGROUND) return "FOREGROUND";
    if (p == BG_JOB_PRIORITY_HIGH)       return "HIGH";
    if (p == BG_JOB_PRIORITY_NORMAL)     return "NORMAL";
    if (p == BG_JOB_PRIORITY_LOW)        return "LOW";
    return "UNKNOWN";
}

static void PrintBytes(UINT64 n)
{
    if (n == BG_SIZE_UNKNOWN)
        internal_printf("UNKNOWN");
    else
        internal_printf("%llu", (unsigned long long)n);
}

/* Look up by {GUID} via GetJob, else EnumJobs and match display name. */
static HRESULT FindJob(IBackgroundCopyManager *mgr, const wchar_t *name,
                       IBackgroundCopyJob **out)
{
    GUID guid;
    HRESULT hr;
    IEnumBackgroundCopyJobs *en = NULL;
    IBackgroundCopyJob *job = NULL;
    ULONG fetched = 0;

    *out = NULL;

    if (OLE32$CLSIDFromString((LPCOLESTR)name, &guid) == S_OK)
    {
        hr = mgr->lpVtbl->GetJob(mgr, &guid, out);
        if (SUCCEEDED(hr) && *out)
            return hr;
    }

    hr = mgr->lpVtbl->EnumJobs(mgr, 0, &en);
    if (FAILED(hr) || !en)
        return hr;

    while (en->lpVtbl->Next(en, 1, &job, &fetched) == S_OK && fetched == 1)
    {
        LPWSTR disp = NULL;
        hr = job->lpVtbl->GetDisplayName(job, &disp);
        if (SUCCEEDED(hr) && disp && MSVCRT$_wcsicmp(disp, name) == 0)
        {
            OLE32$CoTaskMemFree(disp);
            *out = job;
            en->lpVtbl->Release(en);
            return S_OK;
        }
        if (disp)
            OLE32$CoTaskMemFree(disp);
        job->lpVtbl->Release(job);
        job = NULL;
    }

    en->lpVtbl->Release(en);
    return (HRESULT)0x80200001L; /* BG_E_NOT_FOUND */
}

static IBackgroundCopyJob *RequireJob(IBackgroundCopyManager *mgr, const char *utf8)
{
    wchar_t *w;
    IBackgroundCopyJob *job = NULL;
    HRESULT hr;

    if (!utf8 || !utf8[0])
    {
        internal_printf("[-] Missing job name\n");
        return NULL;
    }
    w = Utf8ToUtf16(utf8);
    if (!w)
    {
        internal_printf("[-] Failed to convert job name to UTF-16\n");
        return NULL;
    }
    hr = FindJob(mgr, w, &job);
    intFree(w);
    if (FAILED(hr) || !job)
    {
        internal_printf("[-] Unable to find job named '%s'.\n", utf8);
        return NULL;
    }
    return job;
}

static void DoCreate(IBackgroundCopyManager *mgr, ULONG type, const char *name)
{
    wchar_t *w = NULL;
    GUID id;
    IBackgroundCopyJob *job = NULL;
    HRESULT hr;

    if (!name || !name[0])
    {
        internal_printf("[-] Missing display_name\n");
        return;
    }
    w = Utf8ToUtf16(name);
    if (!w)
    {
        internal_printf("[-] Failed to convert display name to UTF-16\n");
        return;
    }
    memset(&id, 0, sizeof(id));
    hr = mgr->lpVtbl->CreateJob(mgr, w, type, &id, &job);
    intFree(w);
    if (FAILED(hr) || !job)
    {
        internal_printf("[-] CreateJob failed: 0x%08lX\n", (unsigned long)hr);
        return;
    }
    internal_printf("Created job ");
    PrintGuid(&id);
    internal_printf(".\n");
    internal_printf("[+] type=%s name='%s'\n", TypeName(type), name);
    job->lpVtbl->Release(job);
}

static void DoAddFile(IBackgroundCopyJob *job, const char *remote, const char *local)
{
    wchar_t *wr = NULL, *wl = NULL;
    HRESULT hr;

    if (!remote || !remote[0] || !local || !local[0])
    {
        internal_printf("[-] /addfile requires <remote_url> and <local_name>\n");
        return;
    }
    wr = Utf8ToUtf16(remote);
    wl = Utf8ToUtf16(local);
    if (!wr || !wl)
    {
        internal_printf("[-] Failed to convert paths to UTF-16\n");
        if (wr) intFree(wr);
        if (wl) intFree(wl);
        return;
    }
    hr = job->lpVtbl->AddFile(job, wr, wl);
    intFree(wr);
    intFree(wl);
    if (FAILED(hr))
        internal_printf("[-] AddFile failed: 0x%08lX\n", (unsigned long)hr);
    else
        internal_printf("[+] Added file %s -> %s\n", remote, local);
}

static void DoNotify(IBackgroundCopyJob *job, const char *program, const char *params)
{
    IBackgroundCopyJob2 *job2 = NULL;
    wchar_t *wp = NULL, *wa = NULL;
    HRESULT hr;

    GUID iid2;
    /* IID_IBackgroundCopyJob2 {54B50739-686F-45EB-9DFF-D6A9A0FAA9AF} */
    FillGuid(&iid2, 0x54b50739, 0x686f, 0x45eb,
             0x9d, 0xff, 0xd6, 0xa9, 0xa0, 0xfa, 0xa9, 0xaf);
    hr = job->lpVtbl->QueryInterface(job, &iid2, (void **)&job2);
    if (FAILED(hr) || !job2)
    {
        internal_printf("[-] QueryInterface(IBackgroundCopyJob2) failed: 0x%08lX\n",
                        (unsigned long)hr);
        return;
    }

    if (program && program[0])
        wp = Utf8ToUtf16(program);
    if (params && params[0])
        wa = Utf8ToUtf16(params);

    hr = job2->lpVtbl->SetNotifyCmdLine(job2, wp, wa);
    if (FAILED(hr))
    {
        internal_printf("[-] SetNotifyCmdLine failed: 0x%08lX\n", (unsigned long)hr);
    }
    else
    {
        /* bitsadmin.exe also arms these flags so the cmdline actually fires. */
        hr = job->lpVtbl->SetNotifyFlags(job,
            BG_NOTIFY_JOB_TRANSFERRED | BG_NOTIFY_JOB_ERROR);
        if (FAILED(hr))
            internal_printf("[*] SetNotifyCmdLine ok, SetNotifyFlags failed: 0x%08lX\n",
                            (unsigned long)hr);
        else
        {
            internal_printf("[+] Notify cmdline set\n");
            internal_printf("    program : %s\n", (program && program[0]) ? program : "NULL");
            internal_printf("    params  : %s\n", (params  && params[0])  ? params  : "NULL");
        }
    }

    if (wp) intFree(wp);
    if (wa) intFree(wa);
    job2->lpVtbl->Release(job2);
}

static void PrintJobLine(IBackgroundCopyJob *job, int verbose)
{
    GUID id;
    ULONG type = 0, state = 0, prio = 0, errc = 0, delay = 0;
    LPWSTR name = NULL, owner = NULL;
    BG_JOB_PROGRESS prog;

    memset(&id, 0, sizeof(id));
    memset(&prog, 0, sizeof(prog));

    job->lpVtbl->GetId(job, &id);
    job->lpVtbl->GetDisplayName(job, &name);
    job->lpVtbl->GetType(job, &type);
    job->lpVtbl->GetState(job, &state);
    job->lpVtbl->GetPriority(job, &prio);
    job->lpVtbl->GetProgress(job, &prog);

    if (!verbose)
    {
        PrintGuid(&id);
        internal_printf("  ");
        PrintW(name);
        internal_printf("  %s  %s  %s  %lu/%lu  ",
                        TypeName(type), StateName(state), PrioName(prio),
                        (unsigned long)prog.FilesTransferred,
                        (unsigned long)prog.FilesTotal);
        PrintBytes(prog.BytesTransferred);
        internal_printf("/");
        PrintBytes(prog.BytesTotal);
        internal_printf("\n");
    }
    else
    {
        internal_printf("GUID: ");
        PrintGuid(&id);
        internal_printf("\nDISPLAY: ");
        PrintW(name);
        internal_printf("\nTYPE: %s\nSTATE: %s\nPRIORITY: %s\n",
                        TypeName(type), StateName(state), PrioName(prio));
        if (SUCCEEDED(job->lpVtbl->GetOwner(job, &owner)) && owner)
        {
            internal_printf("OWNER: ");
            PrintW(owner);
            internal_printf("\n");
            OLE32$CoTaskMemFree(owner);
        }
        internal_printf("JOB FILES: %lu / %lu\nJOB BYTES: ",
                        (unsigned long)prog.FilesTransferred,
                        (unsigned long)prog.FilesTotal);
        PrintBytes(prog.BytesTransferred);
        internal_printf(" / ");
        PrintBytes(prog.BytesTotal);
        internal_printf("\n");
        if (SUCCEEDED(job->lpVtbl->GetMinimumRetryDelay(job, &delay)))
            internal_printf("MIN RETRY DELAY: %lu\n", (unsigned long)delay);
        if (SUCCEEDED(job->lpVtbl->GetErrorCount(job, &errc)))
            internal_printf("ERROR COUNT: %lu\n", (unsigned long)errc);
        internal_printf("\n");
    }

    if (name)
        OLE32$CoTaskMemFree(name);
}

static void DoList(IBackgroundCopyManager *mgr, int flags)
{
    DWORD enumFlags = (flags & 2) ? BG_JOB_ENUM_ALL_USERS : 0;
    int verbose = flags & 1;
    IEnumBackgroundCopyJobs *en = NULL;
    IBackgroundCopyJob *job = NULL;
    ULONG fetched = 0, count = 0;
    HRESULT hr;

    hr = mgr->lpVtbl->EnumJobs(mgr, enumFlags, &en);
    if (FAILED(hr) || !en)
    {
        internal_printf("[-] EnumJobs failed: 0x%08lX\n", (unsigned long)hr);
        return;
    }

    en->lpVtbl->GetCount(en, &count);
    internal_printf("{GUID}  DISPLAY  TYPE  STATE  PRIORITY  FILES  BYTES\n");
    if (count == 0)
        internal_printf("No jobs found.\n");

    while (en->lpVtbl->Next(en, 1, &job, &fetched) == S_OK && fetched == 1)
    {
        PrintJobLine(job, verbose);
        job->lpVtbl->Release(job);
        job = NULL;
    }
    internal_printf("[*] Listed %lu job(s)%s%s\n",
                    (unsigned long)count,
                    (flags & 2) ? " ALLUSERS" : "",
                    verbose ? " VERBOSE" : "");
    en->lpVtbl->Release(en);
}

void go(char *args, int len)
{
    datap parser;
    int mode;
    IBackgroundCopyManager *mgr = NULL;
    IBackgroundCopyJob *job = NULL;

    bofstart();
    BeaconDataParse(&parser, args, len);
    mode = BeaconDataInt(&parser);

    if (!ComStart())
    {
        printoutput(TRUE);
        return;
    }

    mgr = GetManager();
    if (!mgr)
    {
        ComStop();
        printoutput(TRUE);
        return;
    }

    if (mode == MODE_CREATE)
    {
        int type = BeaconDataInt(&parser);
        char *name = BeaconDataExtract(&parser, NULL);
        DoCreate(mgr, (ULONG)type, name);
    }
    else if (mode == MODE_LIST)
    {
        int flags = BeaconDataInt(&parser);
        DoList(mgr, flags);
    }
    else if (mode == MODE_ADDFILE)
    {
        char *name   = BeaconDataExtract(&parser, NULL);
        char *remote = BeaconDataExtract(&parser, NULL);
        char *local  = BeaconDataExtract(&parser, NULL);
        job = RequireJob(mgr, name);
        if (job)
        {
            DoAddFile(job, remote, local);
            job->lpVtbl->Release(job);
        }
    }
    else if (mode == MODE_NOTIFY)
    {
        char *name    = BeaconDataExtract(&parser, NULL);
        char *program = BeaconDataExtract(&parser, NULL);
        char *params  = BeaconDataExtract(&parser, NULL);
        job = RequireJob(mgr, name);
        if (job)
        {
            DoNotify(job, program, params);
            job->lpVtbl->Release(job);
        }
    }
    else if (mode == MODE_RESUME || mode == MODE_CANCEL || mode == MODE_COMPLETE)
    {
        char *name = BeaconDataExtract(&parser, NULL);
        HRESULT hr;
        job = RequireJob(mgr, name);
        if (job)
        {
            if (mode == MODE_RESUME)
            {
                hr = job->lpVtbl->Resume(job);
                if (FAILED(hr))
                    internal_printf("[-] Resume failed: 0x%08lX\n", (unsigned long)hr);
                else
                    internal_printf("[+] Job resumed.\n");
            }
            else if (mode == MODE_CANCEL)
            {
                hr = job->lpVtbl->Cancel(job);
                if (FAILED(hr))
                    internal_printf("[-] Cancel failed: 0x%08lX\n", (unsigned long)hr);
                else
                    internal_printf("[+] Job canceled.\n");
            }
            else
            {
                hr = job->lpVtbl->Complete(job);
                if (FAILED(hr))
                    internal_printf("[-] Complete failed: 0x%08lX (job must be TRANSFERRED)\n",
                                    (unsigned long)hr);
                else
                    internal_printf("[+] Job completed.\n");
            }
            job->lpVtbl->Release(job);
        }
    }
    else if (mode == MODE_PRIORITY)
    {
        char *name = BeaconDataExtract(&parser, NULL);
        int prio = BeaconDataInt(&parser);
        HRESULT hr;
        job = RequireJob(mgr, name);
        if (job)
        {
            hr = job->lpVtbl->SetPriority(job, (ULONG)prio);
            if (FAILED(hr))
                internal_printf("[-] SetPriority failed: 0x%08lX\n", (unsigned long)hr);
            else
                internal_printf("[+] Job priority set to %s.\n", PrioName((ULONG)prio));
            job->lpVtbl->Release(job);
        }
    }
    else if (mode == MODE_RETRY)
    {
        char *name = BeaconDataExtract(&parser, NULL);
        int seconds = BeaconDataInt(&parser);
        HRESULT hr;
        job = RequireJob(mgr, name);
        if (job)
        {
            hr = job->lpVtbl->SetMinimumRetryDelay(job, (ULONG)seconds);
            if (FAILED(hr))
                internal_printf("[-] SetMinimumRetryDelay failed: 0x%08lX\n", (unsigned long)hr);
            else
                internal_printf("[+] Job minimum retry delay set to %d seconds.\n", seconds);
            job->lpVtbl->Release(job);
        }
    }
    else
    {
        internal_printf("[-] Unknown mode: %d\n", mode);
    }

    mgr->lpVtbl->Release(mgr);
    ComStop();
    printoutput(TRUE);
}
