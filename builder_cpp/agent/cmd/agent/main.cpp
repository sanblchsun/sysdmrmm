// builder_cpp/agent/cmd/agent/main.cpp
// Единый агент: регистрация/heartbeat/telemetry в FastAPI (WinHTTP)
//              + RMM-стриминг MJPEG/H.264 и управление (Schannel, Windows).
// Все параметры вшиты через макросы компилятора. Никаких CLI-аргументов.

#ifndef SECURITY_WIN32
#define SECURITY_WIN32
#endif
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <winhttp.h>
#include <wincrypt.h>
#include <security.h>
#include <schannel.h>
#include <shlobj.h>
#include <processthreadsapi.h>

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <chrono>
#include <thread>
#include <mutex>
#include <atomic>
#include <algorithm>
#include <cstring>
#include <cstdarg>
#include <ctime>
#include <random>
#include <unordered_map>
#include <cctype>

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "secur32.lib")
#pragma comment(lib, "user32.lib")

// ===== Вшиваемые параметры =====
#ifndef SERVER_HOST
#define SERVER_HOST "dev.local"
#endif
#ifndef SERVER_PORT
#define SERVER_PORT 443
#endif
#ifndef BUILD_SLUG
#define BUILD_SLUG "1.0.0"
#endif
#ifndef VERIFY_CERT
#define VERIFY_CERT 0
#endif

static const std::string g_serverHost = SERVER_HOST;
static const int g_serverPort = SERVER_PORT;
static const std::string g_buildSlug = BUILD_SLUG;
static const bool g_verifyCert = (VERIFY_CERT != 0);

static const std::string g_serverURL =
    std::string("https://") + SERVER_HOST + ":" + std::to_string(SERVER_PORT);

// ===== Глобальное =====
static std::mutex g_logMutex;
static std::ofstream g_logFile;
static std::atomic<bool> g_stopRequested(false);
static std::string g_telemetryMode = "none";

static std::string g_agentUUID;
static std::string g_agentToken; // используется и для RMM как agent_token
static std::string g_machineUID;
static std::atomic<bool> g_registered(false);

// Screen metrics (для RMM)
static std::atomic<int> g_screen_w{1920};
static std::atomic<int> g_screen_h{1080};
static std::atomic<int> g_screen_origin_x{0};
static std::atomic<int> g_screen_origin_y{0};

static std::mutex g_clip_m;
static std::string g_last_clip;

// ===== Утилиты =====
static std::string getExePath()
{
    char p[MAX_PATH] = {0};
    GetModuleFileNameA(NULL, p, MAX_PATH);
    return std::string(p);
}
static std::string getExeDir()
{
    std::string p = getExePath();
    size_t i = p.find_last_of("\\/");
    return i == std::string::npos ? p : p.substr(0, i);
}
static void setupFileLogger()
{
    g_logFile.open(getExeDir() + "\\agent.log", std::ios::app | std::ios::out);
}
static void logs(const std::string &s)
{
    std::lock_guard<std::mutex> lk(g_logMutex);
    auto now = std::chrono::system_clock::now();
    auto t = std::chrono::system_clock::to_time_t(now);
    tm tmT;
    localtime_s(&tmT, &t);
    char ts[32];
    strftime(ts, sizeof ts, "%Y-%m-%d %H:%M:%S", &tmT);
    std::string line = std::string(ts) + " " + s + "\n";
    std::cout << line;
    if (g_logFile.is_open())
    {
        g_logFile << line;
        g_logFile.flush();
    }
}
static void logf(const char *fmt, ...)
{
    char b[1024];
    va_list a;
    va_start(a, fmt);
    vsnprintf(b, sizeof b, fmt, a);
    va_end(a);
    logs(b);
}
static std::string loadOrCreateMachineUID()
{
    std::string f = getExeDir() + "\\machine_uid";
    std::ifstream i(f);
    if (i.good())
    {
        std::string u;
        std::getline(i, u);
        if (!u.empty())
            return u;
    }
    std::random_device rd;
    std::mt19937 g(rd());
    std::uniform_int_distribution<> d(0, 999999);
    std::ostringstream o;
    o << time(nullptr) << "-" << GetCurrentProcessId() << "-" << d(g);
    std::string u = o.str();
    std::ofstream of(f);
    of << u;
    of.close();
    return u;
}
static std::string getLocalIP()
{
    WSADATA w;
    if (WSAStartup(MAKEWORD(2, 2), &w) != 0)
        return "";
    char h[256];
    if (gethostname(h, sizeof h))
    {
        WSACleanup();
        return "";
    }
    hostent *he = gethostbyname(h);
    std::string r;
    if (he)
    {
        for (int i = 0; he->h_addr_list[i]; ++i)
        {
            in_addr **al = (in_addr **)he->h_addr_list;
            if (al[i])
            {
                char *ip = inet_ntoa(*al[i]);
                if (ip && strncmp(ip, "127.", 4) != 0)
                {
                    r = ip;
                    break;
                }
            }
        }
    }
    WSACleanup();
    return r;
}
static std::string jsonEscape(const std::string &s)
{
    std::string o;
    for (char c : s)
    {
        switch (c)
        {
        case '"':
            o += "\\\"";
            break;
        case '\\':
            o += "\\\\";
            break;
        case '\b':
            o += "\\b";
            break;
        case '\f':
            o += "\\f";
            break;
        case '\n':
            o += "\\n";
            break;
        case '\r':
            o += "\\r";
            break;
        case '\t':
            o += "\\t";
            break;
        default:
            o += c;
        }
    }
    return o;
}

// ===== WinHTTP: POST/GET JSON (TLS + игнор самоподписанного в dev) =====
static bool winhttpRequest(
    const std::string &method, const std::string &path, const std::string &body,
    std::string &outBody, int &status)
{
    HINTERNET hS = WinHttpOpen(L"Agent/1.0", WINHTTP_ACCESS_TYPE_NO_PROXY, NULL, NULL, 0);
    if (!hS)
        return false;
    std::wstring whost(g_serverHost.begin(), g_serverHost.end());
    HINTERNET hC = WinHttpConnect(hS, whost.c_str(), (INTERNET_PORT)g_serverPort, 0);
    if (!hC)
    {
        WinHttpCloseHandle(hS);
        return false;
    }

    std::wstring wpath(path.begin(), path.end());
    std::wstring wm(method.begin(), method.end());
    DWORD flags = WINHTTP_FLAG_SECURE;
    HINTERNET hR = WinHttpOpenRequest(hC, wm.c_str(), wpath.c_str(), NULL, NULL, NULL, flags);
    if (!hR)
    {
        WinHttpCloseHandle(hC);
        WinHttpCloseHandle(hS);
        return false;
    }

    if (!g_verifyCert)
    {
        DWORD f = SECURITY_FLAG_IGNORE_UNKNOWN_CA | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
                  SECURITY_FLAG_IGNORE_CERT_CN_INVALID | SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;
        WinHttpSetOption(hR, WINHTTP_OPTION_SECURITY_FLAGS, &f, sizeof f);
    }

    std::wstring h = L"Content-Type: application/json\r\n";
    WinHttpAddRequestHeaders(hR, h.c_str(), (DWORD)h.size(), WINHTTP_ADDREQ_FLAG_ADD);

    BOOL ok = WinHttpSendRequest(hR, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                                 body.empty() ? NULL : (LPVOID)body.data(),
                                 (DWORD)body.size(), (DWORD)body.size(), 0);
    if (!ok)
    {
        WinHttpCloseHandle(hR);
        WinHttpCloseHandle(hC);
        WinHttpCloseHandle(hS);
        return false;
    }
    if (!WinHttpReceiveResponse(hR, NULL))
    {
        WinHttpCloseHandle(hR);
        WinHttpCloseHandle(hC);
        WinHttpCloseHandle(hS);
        return false;
    }

    DWORD sc = 0, scSz = sizeof sc;
    WinHttpQueryHeaders(hR, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                        NULL, &sc, &scSz, NULL);
    status = (int)sc;

    char bf[4096];
    DWORD rd = 0;
    outBody.clear();
    while (WinHttpReadData(hR, bf, sizeof bf - 1, &rd) && rd > 0)
    {
        bf[rd] = 0;
        outBody.append(bf, rd);
    }
    WinHttpCloseHandle(hR);
    WinHttpCloseHandle(hC);
    WinHttpCloseHandle(hS);
    return true;
}

static bool postJSON(const std::string &path, const std::string &body, std::string &rb, int &st)
{
    return winhttpRequest("POST", path, body, rb, st);
}

// Скачать файл по полному URL (для auto-update)
static bool downloadFile(const std::string &url, const std::string &outPath)
{
    std::string host = g_serverHost;
    int port = g_serverPort;
    std::string path = "/";
    {
        std::string u = url;
        if (u.rfind("https://", 0) == 0)
            u = u.substr(8);
        else if (u.rfind("http://", 0) == 0)
            u = u.substr(7);
        size_t slash = u.find('/');
        std::string hp = slash == std::string::npos ? u : u.substr(0, slash);
        if (slash != std::string::npos)
            path = u.substr(slash);
        size_t colon = hp.find(':');
        if (colon != std::string::npos)
        {
            host = hp.substr(0, colon);
            port = std::stoi(hp.substr(colon + 1));
        }
        else
            host = hp;
    }
    HINTERNET hS = WinHttpOpen(L"Agent/1.0", WINHTTP_ACCESS_TYPE_NO_PROXY, NULL, NULL, 0);
    if (!hS)
        return false;
    std::wstring wh(host.begin(), host.end());
    HINTERNET hC = WinHttpConnect(hS, wh.c_str(), (INTERNET_PORT)port, 0);
    if (!hC)
    {
        WinHttpCloseHandle(hS);
        return false;
    }
    std::wstring wp(path.begin(), path.end());
    HINTERNET hR = WinHttpOpenRequest(hC, L"GET", wp.c_str(), NULL, NULL, NULL, WINHTTP_FLAG_SECURE);
    if (!hR)
    {
        WinHttpCloseHandle(hC);
        WinHttpCloseHandle(hS);
        return false;
    }
    if (!g_verifyCert)
    {
        DWORD f = SECURITY_FLAG_IGNORE_UNKNOWN_CA | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
                  SECURITY_FLAG_IGNORE_CERT_CN_INVALID | SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;
        WinHttpSetOption(hR, WINHTTP_OPTION_SECURITY_FLAGS, &f, sizeof f);
    }
    if (!WinHttpSendRequest(hR, NULL, 0, NULL, 0, 0, 0) ||
        !WinHttpReceiveResponse(hR, NULL))
    {
        WinHttpCloseHandle(hR);
        WinHttpCloseHandle(hC);
        WinHttpCloseHandle(hS);
        return false;
    }
    HANDLE f = CreateFileA(outPath.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (f == INVALID_HANDLE_VALUE)
    {
        WinHttpCloseHandle(hR);
        WinHttpCloseHandle(hC);
        WinHttpCloseHandle(hS);
        return false;
    }
    char buf[8192];
    DWORD rd = 0;
    while (WinHttpReadData(hR, buf, sizeof buf, &rd) && rd > 0)
    {
        DWORD w;
        WriteFile(f, buf, rd, &w, NULL);
    }
    CloseHandle(f);
    WinHttpCloseHandle(hR);
    WinHttpCloseHandle(hC);
    WinHttpCloseHandle(hS);
    return true;
}

static std::string sha256File(const std::string &p)
{
    HCRYPTPROV hP = 0;
    HCRYPTHASH hH = 0;
    if (!CryptAcquireContext(&hP, 0, 0, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
        return "";
    if (!CryptCreateHash(hP, CALG_SHA_256, 0, 0, &hH))
    {
        CryptReleaseContext(hP, 0);
        return "";
    }
    HANDLE f = CreateFileA(p.c_str(), GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, 0, 0);
    if (f == INVALID_HANDLE_VALUE)
    {
        CryptDestroyHash(hH);
        CryptReleaseContext(hP, 0);
        return "";
    }
    BYTE b[4096];
    DWORD rd;
    while (ReadFile(f, b, sizeof b, &rd, NULL) && rd > 0)
        CryptHashData(hH, b, rd, 0);
    CloseHandle(f);
    BYTE dig[32];
    DWORD dl = 32;
    CryptGetHashParam(hH, HP_HASHVAL, dig, &dl, 0);
    CryptDestroyHash(hH);
    CryptReleaseContext(hP, 0);
    static const char hx[] = "0123456789abcdef";
    std::string r;
    for (DWORD i = 0; i < dl; i++)
    {
        r += hx[dig[i] >> 4];
        r += hx[dig[i] & 0xf];
    }
    return r;
}

// ===== Системная память =====
static std::string totalMem()
{
    MEMORYSTATUSEX m{};
    m.dwLength = sizeof m;
    if (!GlobalMemoryStatusEx(&m))
        return "0";
    return std::to_string(m.ullTotalPhys / (1024 * 1024));
}
static std::string availMem()
{
    MEMORYSTATUSEX m{};
    m.dwLength = sizeof m;
    if (!GlobalMemoryStatusEx(&m))
        return "0";
    return std::to_string(m.ullAvailPhys / (1024 * 1024));
}
static std::string getUsersString()
{
    return "";
}

// ===== Регистрация + heartbeat/telemetry/update =====
static void registerLoop()
{
    char hn[256];
    DWORD sz = sizeof hn;
    GetComputerNameA(hn, &sz);

    for (;;)
    {
        if (g_stopRequested)
            return;
        std::string body =
            std::string("{\"name_pc\":\"") + jsonEscape(hn) + "\","
                                                              "\"machine_uid\":\"" +
            jsonEscape(g_machineUID) + "\","
                                       "\"exe_version\":\"" +
            jsonEscape(g_buildSlug) + "\"}";
        std::string rb;
        int st = 0;
        if (postJSON("/api/agent/register", body, rb, st) && st == 200)
        {
            size_t up = rb.find("\"agent_uuid\":\"");
            size_t tp = rb.find("\"token\":\"");
            if (up != std::string::npos && tp != std::string::npos)
            {
                up += 14;
                tp += 9;
                size_t ue = rb.find('"', up);
                size_t te = rb.find('"', tp);
                if (ue != std::string::npos && te != std::string::npos)
                {
                    g_agentUUID = rb.substr(up, ue - up);
                    g_agentToken = rb.substr(tp, te - tp);
                    g_registered = true;
                    logf("Registered UUID=%s", g_agentUUID.c_str());
                    return;
                }
            }
        }
        logs("Registration failed, retry in 10s");
        for (int i = 0; i < 10 && !g_stopRequested; ++i)
            std::this_thread::sleep_for(std::chrono::seconds(1));
    }
}

static void sendTelemetry()
{
    std::string body =
        std::string("{\"system\":\"windows\",") + "\"user_name\":\"" + jsonEscape(getUsersString()) + "\"," + "\"ip_addr\":\"" + jsonEscape(getLocalIP()) + "\"," + "\"total_memory\":" + totalMem() + "," + "\"available_memory\":" + availMem() + "," + "\"exe_version\":\"" + g_buildSlug + "\"}";
    std::string rb;
    int st;
    postJSON("/api/agent/telemetry?uuid=" + g_agentUUID + "&token=" + g_agentToken, body, rb, st);
}

static void checkForUpdate()
{
    std::string body = std::string("{\"build\":\"") + g_buildSlug + "\"}";
    std::string rb;
    int st;
    if (!postJSON("/api/agent/check-update?uuid=" + g_agentUUID + "&token=" + g_agentToken, body, rb, st) || st != 200)
        return;
    if (rb.find("\"update\":true") == std::string::npos)
        return;

    auto grab = [&](const char *k, size_t keyLen) -> std::string
    {
        size_t p = rb.find(k);
        if (p == std::string::npos)
            return "";
        p += keyLen;
        size_t e = rb.find('"', p);
        return e == std::string::npos ? "" : rb.substr(p, e - p);
    };
    std::string newBuild = grab("\"build\":\"", 9);
    std::string url = grab("\"url\":\"", 7);
    std::string sha = grab("\"sha256\":\"", 10);
    if (newBuild.empty() || url.empty() || sha.empty())
        return;

    std::string exe = getExePath();
    std::string tmp = exe + ".new";
    if (!downloadFile(url, tmp))
    {
        logs("download failed");
        return;
    }
    std::string h = sha256File(tmp);
    if (h != sha)
    {
        logs("sha mismatch");
        DeleteFileA(tmp.c_str());
        return;
    }
    std::string old = exe + ".old";
    DeleteFileA(old.c_str());
    if (MoveFileA(exe.c_str(), old.c_str()) && MoveFileA(tmp.c_str(), exe.c_str()))
    {
        logs("update applied, restarting");
        STARTUPINFOA si{};
        si.cb = sizeof si;
        si.dwFlags = STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_HIDE;
        PROCESS_INFORMATION pi{};
        char cmd[512];
        sprintf_s(cmd, "cmd.exe /c \"timeout /t 2 /nobreak >nul && \"%s\"\"", exe.c_str());
        if (CreateProcessA(NULL, cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi))
        {
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
        }
        Sleep(2000);
        ExitProcess(0);
    }
    else
    {
        MoveFileA(old.c_str(), exe.c_str());
        DeleteFileA(tmp.c_str());
    }
}

static void heartbeatLoop()
{
    while (!g_stopRequested)
    {
        for (int i = 0; i < 10 && !g_stopRequested; ++i)
            std::this_thread::sleep_for(std::chrono::seconds(1));
        if (g_stopRequested)
            break;
        std::string rb;
        int st;
        std::string body = "{}";
        postJSON("/api/agent/heartbeat?uuid=" + g_agentUUID + "&token=" + g_agentToken, body, rb, st);
        size_t mp = rb.find("\"telemetry_mode\":\"");
        if (mp != std::string::npos)
        {
            mp += 18;
            size_t me = rb.find('"', mp);
            if (me != std::string::npos)
                g_telemetryMode = rb.substr(mp, me - mp);
        }
        if (g_telemetryMode == "full")
            sendTelemetry();
        for (int i = 0; i < 50 && !g_stopRequested; ++i)
            std::this_thread::sleep_for(std::chrono::seconds(1));
        if (!g_stopRequested)
            checkForUpdate();
    }
}

// =================================================================
// ===================== ДАЛЕЕ: RMM (Schannel) =====================
// =================================================================

struct Runtime;

struct TlsConn
{
    SOCKET sock = INVALID_SOCKET;
    CredHandle cred = {};
    CtxtHandle ctx = {};
    bool cred_ok = false, ctx_ok = false;
    SecPkgContext_StreamSizes sizes = {};
    std::vector<uint8_t> raw, plain;
};

struct Runtime
{
    std::mutex m;
    std::string codec = "mjpeg", encoder = "cpu", bitrate = "4M";
    int framerate = 30, mjpeg_q = 4;
    std::atomic<bool> restart{false};
    std::atomic<bool> stop{false};
    std::mutex ctrl_sock_m;
    TlsConn *ctrl_conn = nullptr;
};

static bool send_all_raw(SOCKET s, const char *p, int n)
{
    while (n > 0)
    {
        int k = send(s, p, n, 0);
        if (k <= 0)
            return false;
        p += k;
        n -= k;
    }
    return true;
}
static SOCKET tcp_connect(const std::string &host, int port)
{
    addrinfo hints{}, *res = NULL;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    std::string p = std::to_string(port);
    if (getaddrinfo(host.c_str(), p.c_str(), &hints, &res) != 0)
        return INVALID_SOCKET;
    SOCKET s = INVALID_SOCKET;
    for (auto *a = res; a; a = a->ai_next)
    {
        s = socket(a->ai_family, a->ai_socktype, a->ai_protocol);
        if (s == INVALID_SOCKET)
            continue;
        if (connect(s, a->ai_addr, (int)a->ai_addrlen) == 0)
            break;
        closesocket(s);
        s = INVALID_SOCKET;
    }
    freeaddrinfo(res);
    if (s != INVALID_SOCKET)
    {
        int one = 1;
        setsockopt(s, IPPROTO_TCP, TCP_NODELAY, (char *)&one, sizeof one);
    }
    return s;
}
static void tls_close(TlsConn *c)
{
    if (!c)
        return;
    if (c->ctx_ok)
    {
        DeleteSecurityContext(&c->ctx);
        c->ctx_ok = false;
    }
    if (c->cred_ok)
    {
        FreeCredentialHandle(&c->cred);
        c->cred_ok = false;
    }
    if (c->sock != INVALID_SOCKET)
    {
        closesocket(c->sock);
        c->sock = INVALID_SOCKET;
    }
}
static bool tls_handshake(TlsConn *c, const std::string &host, bool verify)
{
    SCHANNEL_CRED sc{};
    sc.dwVersion = SCHANNEL_CRED_VERSION;
    sc.dwFlags = SCH_CRED_NO_DEFAULT_CREDS | (verify ? SCH_CRED_AUTO_CRED_VALIDATION : SCH_CRED_MANUAL_CRED_VALIDATION);
    SECURITY_STATUS ss = AcquireCredentialsHandleA(NULL, (SEC_CHAR *)UNISP_NAME_A, SECPKG_CRED_OUTBOUND,
                                                   NULL, &sc, NULL, NULL, &c->cred, NULL);
    if (ss != SEC_E_OK)
        return false;
    c->cred_ok = true;

    const DWORD req = ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT | ISC_REQ_CONFIDENTIALITY |
                      ISC_RET_EXTENDED_ERROR | ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_STREAM;
    std::wstring wh(host.begin(), host.end());

    SecBuffer ob = {0, SECBUFFER_TOKEN, NULL};
    SecBufferDesc od = {SECBUFFER_VERSION, 1, &ob};
    DWORD rf = 0;

    ss = InitializeSecurityContextW(&c->cred, NULL, (SEC_WCHAR *)wh.c_str(), req, 0, SECURITY_NATIVE_DREP,
                                    NULL, 0, &c->ctx, &od, &rf, NULL);
    c->ctx_ok = true;
    if (ob.pvBuffer && ob.cbBuffer)
    {
        bool ok = send_all_raw(c->sock, (const char *)ob.pvBuffer, (int)ob.cbBuffer);
        FreeContextBuffer(ob.pvBuffer);
        ob.pvBuffer = NULL;
        if (!ok)
            return false;
    }
    if (ss != SEC_I_CONTINUE_NEEDED)
        return false;

    std::vector<uint8_t> in;
    char tmp[16384];
    while (true)
    {
        int n = recv(c->sock, tmp, sizeof tmp, 0);
        if (n <= 0)
            return false;
        in.insert(in.end(), tmp, tmp + n);
    retry:
        SecBuffer ib[2] = {{(ULONG)in.size(), SECBUFFER_TOKEN, in.data()}, {0, SECBUFFER_EMPTY, NULL}};
        SecBufferDesc id = {SECBUFFER_VERSION, 2, ib};
        ob = {0, SECBUFFER_TOKEN, NULL};
        od = {SECBUFFER_VERSION, 1, &ob};
        ss = InitializeSecurityContextW(&c->cred, &c->ctx, NULL, req, 0, SECURITY_NATIVE_DREP,
                                        &id, 0, NULL, &od, &rf, NULL);
        if (ob.pvBuffer && ob.cbBuffer)
        {
            bool ok = send_all_raw(c->sock, (const char *)ob.pvBuffer, (int)ob.cbBuffer);
            FreeContextBuffer(ob.pvBuffer);
            ob.pvBuffer = NULL;
            if (!ok)
                return false;
        }
        if (ib[1].BufferType == SECBUFFER_EXTRA && ib[1].cbBuffer > 0)
        {
            size_t off = in.size() - ib[1].cbBuffer;
            std::vector<uint8_t> ex(in.begin() + (ptrdiff_t)off, in.end());
            in = std::move(ex);
        }
        else if (ss != SEC_E_INCOMPLETE_MESSAGE)
            in.clear();
        if (ss == SEC_E_OK)
            break;
        if (ss == SEC_I_CONTINUE_NEEDED)
            continue;
        if (ss == SEC_E_INCOMPLETE_MESSAGE)
        {
            int nn = recv(c->sock, tmp, sizeof tmp, 0);
            if (nn <= 0)
                return false;
            in.insert(in.end(), tmp, tmp + nn);
            goto retry;
        }
        return false;
    }
    if (!in.empty())
        c->raw = std::move(in);
    QueryContextAttributes(&c->ctx, SECPKG_ATTR_STREAM_SIZES, &c->sizes);
    return true;
}
static TlsConn *tls_connect(const std::string &host, int port, bool verify)
{
    SOCKET s = tcp_connect(host, port);
    if (s == INVALID_SOCKET)
        return nullptr;
    TlsConn *c = new TlsConn();
    c->sock = s;
    if (!tls_handshake(c, host, verify))
    {
        tls_close(c);
        delete c;
        return nullptr;
    }
    return c;
}
static bool tls_send_all(TlsConn *c, const char *p, int n)
{
    const int MAX = (int)c->sizes.cbMaximumMessage;
    while (n > 0)
    {
        int ch = std::min(n, MAX);
        std::vector<uint8_t> m(c->sizes.cbHeader + (size_t)ch + c->sizes.cbTrailer);
        SecBuffer b[3] = {
            {c->sizes.cbHeader, SECBUFFER_STREAM_HEADER, m.data()},
            {(ULONG)ch, SECBUFFER_DATA, m.data() + c->sizes.cbHeader},
            {c->sizes.cbTrailer, SECBUFFER_STREAM_TRAILER, m.data() + c->sizes.cbHeader + ch}};
        SecBufferDesc d = {SECBUFFER_VERSION, 3, b};
        memcpy(b[1].pvBuffer, p, (size_t)ch);
        if (EncryptMessage(&c->ctx, 0, &d, 0) != SEC_E_OK)
            return false;
        int total = (int)(b[0].cbBuffer + b[1].cbBuffer + b[2].cbBuffer);
        if (!send_all_raw(c->sock, (const char *)m.data(), total))
            return false;
        p += ch;
        n -= ch;
    }
    return true;
}
static int tls_recv_some(TlsConn *c, char *buf, int want)
{
    if (!c->plain.empty())
    {
        int n = (int)std::min((size_t)want, c->plain.size());
        memcpy(buf, c->plain.data(), (size_t)n);
        c->plain.erase(c->plain.begin(), c->plain.begin() + n);
        return n;
    }
    char tmp[16384];
    for (;;)
    {
        while (!c->raw.empty())
        {
            SecBuffer b[4] = {
                {(ULONG)c->raw.size(), SECBUFFER_DATA, c->raw.data()},
                {0, SECBUFFER_EMPTY, NULL},
                {0, SECBUFFER_EMPTY, NULL},
                {0, SECBUFFER_EMPTY, NULL}};
            SecBufferDesc d = {SECBUFFER_VERSION, 4, b};
            SECURITY_STATUS ss = DecryptMessage(&c->ctx, &d, 0, NULL);
            if (ss == SEC_E_INCOMPLETE_MESSAGE)
                break;
            if (ss == SEC_I_CONTEXT_EXPIRED)
                return 0;
            if (ss != SEC_E_OK && ss != SEC_I_RENEGOTIATE)
                return -1;
            for (int i = 0; i < 4; ++i)
                if (b[i].BufferType == SECBUFFER_DATA && b[i].cbBuffer)
                    c->plain.insert(c->plain.end(), (uint8_t *)b[i].pvBuffer,
                                    (uint8_t *)b[i].pvBuffer + b[i].cbBuffer);
            bool hex = false;
            for (int i = 1; i < 4; ++i)
                if (b[i].BufferType == SECBUFFER_EXTRA && b[i].cbBuffer)
                {
                    size_t off = c->raw.size() - b[i].cbBuffer;
                    std::vector<uint8_t> ex(c->raw.begin() + (ptrdiff_t)off, c->raw.end());
                    c->raw = std::move(ex);
                    hex = true;
                    break;
                }
            if (!hex)
                c->raw.clear();
            if (!c->plain.empty())
            {
                int n = (int)std::min((size_t)want, c->plain.size());
                memcpy(buf, c->plain.data(), (size_t)n);
                c->plain.erase(c->plain.begin(), c->plain.begin() + n);
                return n;
            }
        }
        int n = recv(c->sock, tmp, sizeof tmp, 0);
        if (n <= 0)
            return -1;
        c->raw.insert(c->raw.end(), tmp, tmp + n);
    }
}
static int tls_recv_n(TlsConn *c, char *p, int n)
{
    int got = 0;
    while (got < n)
    {
        int k = tls_recv_some(c, p + got, n - got);
        if (k <= 0)
            return got;
        got += k;
    }
    return got;
}
static bool send_all(TlsConn *c, const char *p, int n) { return tls_send_all(c, p, n); }
static bool send_chunk(TlsConn *c, const char *p, int n)
{
    char h[32];
    int hl = std::snprintf(h, sizeof h, "%X\r\n", n);
    if (!send_all(c, h, hl))
        return false;
    if (n > 0 && !send_all(c, p, n))
        return false;
    return send_all(c, "\r\n", 2);
}
static int recv_n(TlsConn *c, char *p, int n) { return tls_recv_n(c, p, n); }

static std::string http_get(const std::string &host, int port, const std::string &path, bool verify)
{
    TlsConn *c = tls_connect(host, port, verify);
    if (!c)
        return {};
    std::ostringstream r;
    r << "GET " << path << " HTTP/1.1\r\nHost: " << host << ":" << port
      << "\r\nConnection: close\r\nAccept: text/plain\r\n\r\n";
    std::string req = r.str();
    if (!send_all(c, req.data(), (int)req.size()))
    {
        tls_close(c);
        delete c;
        return {};
    }
    std::string all;
    char bf[4096];
    for (;;)
    {
        int n = tls_recv_some(c, bf, sizeof bf);
        if (n <= 0)
            break;
        all.append(bf, (size_t)n);
    }
    tls_close(c);
    delete c;
    auto p2 = all.find("\r\n\r\n");
    return p2 == std::string::npos ? std::string{} : all.substr(p2 + 4);
}

// ===== JSON util =====
static bool json_str(const std::string &j, const std::string &k, std::string &out)
{
    std::string key = "\"" + k + "\"";
    auto p = j.find(key);
    if (p == std::string::npos)
        return false;
    p = j.find(':', p);
    if (p == std::string::npos)
        return false;
    ++p;
    while (p < j.size() && std::isspace((unsigned char)j[p]))
        ++p;
    if (p >= j.size() || j[p] != '"')
        return false;
    ++p;
    auto e = j.find('"', p);
    if (e == std::string::npos)
        return false;
    out = j.substr(p, e - p);
    return true;
}
static bool json_int(const std::string &j, const std::string &k, int &out)
{
    std::string key = "\"" + k + "\"";
    auto p = j.find(key);
    if (p == std::string::npos)
        return false;
    p = j.find(':', p);
    if (p == std::string::npos)
        return false;
    ++p;
    while (p < j.size() && std::isspace((unsigned char)j[p]))
        ++p;
    int sign = 1;
    if (p < j.size() && j[p] == '-')
    {
        sign = -1;
        ++p;
    }
    if (p >= j.size() || !std::isdigit((unsigned char)j[p]))
        return false;
    int v = 0;
    while (p < j.size() && std::isdigit((unsigned char)j[p]))
    {
        v = v * 10 + (j[p] - '0');
        ++p;
    }
    out = sign * v;
    return true;
}
static bool json_str_ex(const std::string &j, const std::string &k, std::string &out)
{
    // упрощённо: unescape основных последовательностей
    std::string key = "\"" + k + "\"";
    auto p = j.find(key);
    if (p == std::string::npos)
        return false;
    p = j.find(':', p);
    if (p == std::string::npos)
        return false;
    ++p;
    while (p < j.size() && std::isspace((unsigned char)j[p]))
        ++p;
    if (p >= j.size() || j[p] != '"')
        return false;
    ++p;
    out.clear();
    while (p < j.size())
    {
        char c = j[p];
        if (c == '"')
            return true;
        if (c == '\\' && p + 1 < j.size())
        {
            char n = j[p + 1];
            if (n == '"' || n == '\\' || n == '/')
            {
                out += n;
                p += 2;
                continue;
            }
            if (n == 'n')
            {
                out += '\n';
                p += 2;
                continue;
            }
            if (n == 't')
            {
                out += '\t';
                p += 2;
                continue;
            }
            if (n == 'r')
            {
                out += '\r';
                p += 2;
                continue;
            }
            if (n == 'b')
            {
                out += '\b';
                p += 2;
                continue;
            }
            if (n == 'f')
            {
                out += '\f';
                p += 2;
                continue;
            }
            p += 2;
            continue;
        }
        out += c;
        ++p;
    }
    return false;
}
static std::string json_escape_str(const std::string &s)
{
    std::string o;
    o.reserve(s.size() + 2);
    o += '"';
    for (unsigned char c : s)
    {
        switch (c)
        {
        case '"':
            o += "\\\"";
            break;
        case '\\':
            o += "\\\\";
            break;
        case '\n':
            o += "\\n";
            break;
        case '\r':
            o += "\\r";
            break;
        case '\t':
            o += "\\t";
            break;
        default:
            if (c < 0x20)
            {
                char b[8];
                std::snprintf(b, sizeof b, "\\u%04x", c);
                o += b;
            }
            else
                o += (char)c;
        }
    }
    o += '"';
    return o;
}

// ===== screen / mouse / keyboard / clipboard =====
static bool read_screen(int &w, int &h, int &ox, int &oy)
{
    w = GetSystemMetrics(SM_CXVIRTUALSCREEN);
    h = GetSystemMetrics(SM_CYVIRTUALSCREEN);
    ox = GetSystemMetrics(SM_XVIRTUALSCREEN);
    oy = GetSystemMetrics(SM_YVIRTUALSCREEN);
    if (w <= 0 || h <= 0)
    {
        w = GetSystemMetrics(SM_CXSCREEN);
        h = GetSystemMetrics(SM_CYSCREEN);
        ox = oy = 0;
    }
    return w > 0 && h > 0;
}
static void init_screen()
{
    int w, h, ox, oy;
    if (read_screen(w, h, ox, oy))
    {
        g_screen_w = w;
        g_screen_h = h;
        g_screen_origin_x = ox;
        g_screen_origin_y = oy;
    }
}
static void do_mouse_move(int x, int y)
{
    int sw = g_screen_w, sh = g_screen_h;
    if (sw <= 1 || sh <= 1)
        return;
    x = std::clamp(x, 0, sw - 1);
    y = std::clamp(y, 0, sh - 1);
    INPUT in{};
    in.type = INPUT_MOUSE;
    in.mi.dx = (LONG)((int64_t)x * 65535 / (sw - 1));
    in.mi.dy = (LONG)((int64_t)y * 65535 / (sh - 1));
    in.mi.dwFlags = MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_VIRTUALDESK;
    SendInput(1, &in, sizeof(INPUT));
}
static void do_mouse_button(int btn, bool down)
{
    INPUT in{};
    in.type = INPUT_MOUSE;
    DWORD f = 0;
    switch (btn)
    {
    case 0:
        f = down ? MOUSEEVENTF_LEFTDOWN : MOUSEEVENTF_LEFTUP;
        break;
    case 1:
        f = down ? MOUSEEVENTF_MIDDLEDOWN : MOUSEEVENTF_MIDDLEUP;
        break;
    case 2:
        f = down ? MOUSEEVENTF_RIGHTDOWN : MOUSEEVENTF_RIGHTUP;
        break;
    default:
        return;
    }
    in.mi.dwFlags = f;
    SendInput(1, &in, sizeof(INPUT));
}
static void do_mouse_wheel(int d)
{
    INPUT in{};
    in.type = INPUT_MOUSE;
    in.mi.mouseData = (DWORD)d;
    in.mi.dwFlags = MOUSEEVENTF_WHEEL;
    SendInput(1, &in, sizeof(INPUT));
}
static void do_text_input(const std::string &s)
{
    if (s.empty())
        return;
    int wl = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), NULL, 0);
    if (wl <= 0)
        return;
    std::vector<wchar_t> w(wl);
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), w.data(), wl);
    std::vector<INPUT> ins;
    for (wchar_t ch : w)
    {
        if (ch == L'\r')
            continue;
        INPUT d{};
        d.type = INPUT_KEYBOARD;
        if (ch == L'\n')
        {
            d.ki.wVk = VK_RETURN;
        }
        else if (ch == L'\t')
        {
            d.ki.wVk = VK_TAB;
        }
        else
        {
            d.ki.wScan = (WORD)ch;
            d.ki.dwFlags = KEYEVENTF_UNICODE;
        }
        INPUT u = d;
        u.ki.dwFlags |= KEYEVENTF_KEYUP;
        ins.push_back(d);
        ins.push_back(u);
    }
    if (!ins.empty())
        SendInput((UINT)ins.size(), ins.data(), sizeof(INPUT));
}
static int code_to_vk(const std::string &c)
{
    if (c.size() == 4 && c.compare(0, 3, "Key") == 0)
    {
        char k = c[3];
        if (k >= 'A' && k <= 'Z')
            return k;
    }
    if (c.size() == 6 && c.compare(0, 5, "Digit") == 0)
    {
        char k = c[5];
        if (k >= '0' && k <= '9')
            return k;
    }
    if (c.compare(0, 6, "Numpad") == 0)
    {
        if (c.size() == 7 && c[6] >= '0' && c[6] <= '9')
            return VK_NUMPAD0 + (c[6] - '0');
        if (c == "NumpadAdd")
            return VK_ADD;
        if (c == "NumpadSubtract")
            return VK_SUBTRACT;
        if (c == "NumpadMultiply")
            return VK_MULTIPLY;
        if (c == "NumpadDivide")
            return VK_DIVIDE;
        if (c == "NumpadDecimal")
            return VK_DECIMAL;
        if (c == "NumpadEnter")
            return VK_RETURN;
    }
    if (!c.empty() && c[0] == 'F' && c.size() >= 2)
    {
        bool d = true;
        for (size_t i = 1; i < c.size(); ++i)
            if (!std::isdigit((unsigned char)c[i]))
            {
                d = false;
                break;
            }
        if (d)
        {
            int n = std::atoi(c.c_str() + 1);
            if (n >= 1 && n <= 24)
                return VK_F1 + (n - 1);
        }
    }
    static const std::unordered_map<std::string, int> m = {
        {"Enter", VK_RETURN},
        {"Backspace", VK_BACK},
        {"Tab", VK_TAB},
        {"Space", VK_SPACE},
        {"Escape", VK_ESCAPE},
        {"ArrowLeft", VK_LEFT},
        {"ArrowRight", VK_RIGHT},
        {"ArrowUp", VK_UP},
        {"ArrowDown", VK_DOWN},
        {"Home", VK_HOME},
        {"End", VK_END},
        {"PageUp", VK_PRIOR},
        {"PageDown", VK_NEXT},
        {"Insert", VK_INSERT},
        {"Delete", VK_DELETE},
        {"ShiftLeft", VK_LSHIFT},
        {"ShiftRight", VK_RSHIFT},
        {"ControlLeft", VK_LCONTROL},
        {"ControlRight", VK_RCONTROL},
        {"AltLeft", VK_LMENU},
        {"AltRight", VK_RMENU},
        {"MetaLeft", VK_LWIN},
        {"MetaRight", VK_RWIN},
        {"OSLeft", VK_LWIN},
        {"OSRight", VK_RWIN},
        {"CapsLock", VK_CAPITAL},
        {"NumLock", VK_NUMLOCK},
        {"ScrollLock", VK_SCROLL},
        {"Minus", VK_OEM_MINUS},
        {"Equal", VK_OEM_PLUS},
        {"BracketLeft", VK_OEM_4},
        {"BracketRight", VK_OEM_6},
        {"Backslash", VK_OEM_5},
        {"Semicolon", VK_OEM_1},
        {"Quote", VK_OEM_7},
        {"Comma", VK_OEM_COMMA},
        {"Period", VK_OEM_PERIOD},
        {"Slash", VK_OEM_2},
        {"Backquote", VK_OEM_3},
    };
    auto it = m.find(c);
    return it == m.end() ? 0 : it->second;
}
static void do_key(const std::string &c, bool down)
{
    int vk = code_to_vk(c);
    if (!vk)
        return;
    INPUT in{};
    in.type = INPUT_KEYBOARD;
    in.ki.wVk = (WORD)vk;
    in.ki.wScan = (WORD)MapVirtualKeyW(vk, MAPVK_VK_TO_VSC);
    in.ki.dwFlags = down ? 0 : KEYEVENTF_KEYUP;
    SendInput(1, &in, sizeof(INPUT));
}

static std::string clip_read()
{
    if (!OpenClipboard(NULL))
        return "";
    std::string r;
    HANDLE h = GetClipboardData(CF_UNICODETEXT);
    if (h)
    {
        const wchar_t *w = (const wchar_t *)GlobalLock(h);
        if (w)
        {
            int n = WideCharToMultiByte(CP_UTF8, 0, w, -1, NULL, 0, NULL, NULL);
            if (n > 1)
            {
                r.resize(n - 1);
                WideCharToMultiByte(CP_UTF8, 0, w, -1, &r[0], n, NULL, NULL);
            }
            GlobalUnlock(h);
        }
    }
    CloseClipboard();
    return r;
}
static void clip_write(const std::string &s)
{
    int wl = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size() + 1, NULL, 0);
    if (wl <= 0)
        return;
    HGLOBAL m = GlobalAlloc(GMEM_MOVEABLE, (size_t)wl * sizeof(wchar_t));
    if (!m)
        return;
    wchar_t *d = (wchar_t *)GlobalLock(m);
    if (!d)
    {
        GlobalFree(m);
        return;
    }
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size() + 1, d, wl);
    GlobalUnlock(m);
    if (!OpenClipboard(NULL))
    {
        GlobalFree(m);
        return;
    }
    EmptyClipboard();
    if (!SetClipboardData(CF_UNICODETEXT, m))
        GlobalFree(m);
    CloseClipboard();
    std::lock_guard<std::mutex> lk(g_clip_m);
    g_last_clip = s;
}

// ===== WebSocket =====
static std::string b64(const unsigned char *d, size_t n)
{
    static const char *T = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string o;
    size_t i = 0;
    while (i < n)
    {
        uint32_t v = 0;
        int k = (int)std::min<size_t>(3, n - i);
        for (int j = 0; j < k; ++j)
            v |= d[i + j] << ((2 - j) * 8);
        for (int j = 0; j < 4; ++j)
            o += (j <= k) ? T[(v >> ((3 - j) * 6)) & 63] : '=';
        i += 3;
    }
    return o;
}
static bool ws_handshake(TlsConn *c, const std::string &host, int port, const std::string &path)
{
    unsigned char k[16];
    std::random_device rd;
    for (int i = 0; i < 16; ++i)
        k[i] = (unsigned char)(rd() & 0xFF);
    std::ostringstream r;
    r << "GET " << path << " HTTP/1.1\r\n"
      << "Host: " << host << ":" << port << "\r\n"
      << "Upgrade: websocket\r\nConnection: Upgrade\r\n"
      << "Sec-WebSocket-Key: " << b64(k, 16) << "\r\n"
      << "Sec-WebSocket-Version: 13\r\n\r\n";
    std::string rs = r.str();
    if (!send_all(c, rs.data(), (int)rs.size()))
        return false;
    std::string h;
    char ch;
    while (h.size() < 8192)
    {
        if (recv_n(c, &ch, 1) != 1)
            return false;
        h += ch;
        if (h.size() >= 4 && h.compare(h.size() - 4, 4, "\r\n\r\n") == 0)
            break;
    }
    return h.find(" 101") != std::string::npos;
}
static bool ws_send(TlsConn *c, int op, const void *data, size_t len)
{
    std::vector<uint8_t> f;
    f.reserve(len + 14);
    f.push_back((uint8_t)(0x80 | op));
    uint8_t mask[4];
    std::random_device rd;
    for (int i = 0; i < 4; ++i)
        mask[i] = (uint8_t)(rd() & 0xFF);
    if (len < 126)
        f.push_back((uint8_t)(0x80 | len));
    else if (len < 65536)
    {
        f.push_back((uint8_t)(0x80 | 126));
        f.push_back((uint8_t)((len >> 8) & 0xFF));
        f.push_back((uint8_t)(len & 0xFF));
    }
    else
    {
        f.push_back((uint8_t)(0x80 | 127));
        for (int i = 7; i >= 0; --i)
            f.push_back((uint8_t)((len >> (i * 8)) & 0xFF));
    }
    for (int i = 0; i < 4; ++i)
        f.push_back(mask[i]);
    const uint8_t *p = (const uint8_t *)data;
    for (size_t i = 0; i < len; ++i)
        f.push_back(p[i] ^ mask[i & 3]);
    return send_all(c, (const char *)f.data(), (int)f.size());
}
static int ws_recv(TlsConn *c, std::vector<uint8_t> &pl)
{
    uint8_t h[2];
    if (recv_n(c, (char *)h, 2) != 2)
        return -1;
    int op = h[0] & 0x0F;
    bool masked = (h[1] & 0x80) != 0;
    uint64_t len = h[1] & 0x7F;
    if (len == 126)
    {
        uint8_t b[2];
        if (recv_n(c, (char *)b, 2) != 2)
            return -1;
        len = ((uint64_t)b[0] << 8) | b[1];
    }
    else if (len == 127)
    {
        uint8_t b[8];
        if (recv_n(c, (char *)b, 8) != 8)
            return -1;
        len = 0;
        for (int i = 0; i < 8; ++i)
            len = (len << 8) | b[i];
    }
    uint8_t mk[4] = {0, 0, 0, 0};
    if (masked && recv_n(c, (char *)mk, 4) != 4)
        return -1;
    if (len > (8u << 20))
        return -1;
    pl.resize((size_t)len);
    if (len && recv_n(c, (char *)pl.data(), (int)len) != (int)len)
        return -1;
    if (masked)
        for (size_t i = 0; i < pl.size(); ++i)
            pl[i] ^= mk[i & 3];
    if (op == 0x8)
        return -1;
    if (op == 0x9)
    {
        ws_send(c, 0xA, pl.data(), pl.size());
        return 0;
    }
    if (op == 0xA)
        return 0;
    if (op == 0x1)
        return 1;
    if (op == 0x2)
        return 2;
    return 0;
}

// ===== RMM control =====
static std::string make_hello()
{
    std::ostringstream s;
    s << "{\"type\":\"hello\",\"screen_w\":" << g_screen_w.load() << ",\"screen_h\":" << g_screen_h.load() << "}";
    return s.str();
}
static void ctrl_send_hello(Runtime &rt)
{
    std::lock_guard<std::mutex> lk(rt.ctrl_sock_m);
    if (!rt.ctrl_conn)
        return;
    std::string h = make_hello();
    ws_send(rt.ctrl_conn, 0x1, h.data(), h.size());
}
static void ctrl_send_clipboard(Runtime &rt, const std::string &t)
{
    std::string m = "{\"type\":\"clipboard\",\"text\":" + json_escape_str(t) + "}";
    std::lock_guard<std::mutex> lk(rt.ctrl_sock_m);
    if (!rt.ctrl_conn)
        return;
    ws_send(rt.ctrl_conn, 0x1, m.data(), m.size());
}
static void handle_control(const std::string &j)
{
    std::string type;
    if (!json_str(j, "type", type))
        return;
    if (type == "mouse_move")
    {
        int x = 0, y = 0;
        if (json_int(j, "x", x) && json_int(j, "y", y))
            do_mouse_move(x, y);
    }
    else if (type == "mouse_down" || type == "mouse_up")
    {
        int b = 0;
        json_int(j, "button", b);
        do_mouse_button(b, type == "mouse_down");
    }
    else if (type == "mouse_wheel")
    {
        int d = 0;
        if (json_int(j, "delta", d))
            do_mouse_wheel(d);
    }
    else if (type == "text")
    {
        std::string t;
        if (json_str_ex(j, "text", t))
            do_text_input(t);
    }
    else if (type == "key_down" || type == "key_up")
    {
        std::string c;
        if (json_str(j, "code", c))
            do_key(c, type == "key_down");
    }
    else if (type == "clipboard")
    {
        std::string t;
        if (json_str_ex(j, "text", t))
            clip_write(t);
    }
}

static std::string rmm_path(const std::string &suffix)
{
    // suffix начинается с /
    return std::string("/rmm-agent") + suffix + "?agent_token=" + g_agentToken;
}

static void control_loop(Runtime &rt)
{
    while (!rt.stop)
    {
        if (!g_registered)
        {
            std::this_thread::sleep_for(std::chrono::seconds(2));
            continue;
        }
        TlsConn *c = tls_connect(g_serverHost, g_serverPort, g_verifyCert);
        if (!c)
        {
            std::this_thread::sleep_for(std::chrono::seconds(3));
            continue;
        }
        std::string path = rmm_path("/ws/control/agent/" + g_machineUID);
        if (!ws_handshake(c, g_serverHost, g_serverPort, path))
        {
            logs("ctrl wss handshake failed");
            tls_close(c);
            delete c;
            std::this_thread::sleep_for(std::chrono::seconds(3));
            continue;
        }
        logs("ctrl wss connected");
        {
            std::lock_guard<std::mutex> lk(rt.ctrl_sock_m);
            rt.ctrl_conn = c;
        }
        ctrl_send_hello(rt);

        std::vector<uint8_t> buf;
        while (!rt.stop)
        {
            int r = ws_recv(c, buf);
            if (r < 0)
                break;
            if (r == 1)
                handle_control(std::string(buf.begin(), buf.end()));
        }
        {
            std::lock_guard<std::mutex> lk(rt.ctrl_sock_m);
            rt.ctrl_conn = nullptr;
        }
        tls_close(c);
        delete c;
        logs("ctrl wss disconnected, retry in 2s");
        std::this_thread::sleep_for(std::chrono::seconds(2));
    }
}

static void resolution_watch_loop(Runtime &rt)
{
    while (!rt.stop)
    {
        std::this_thread::sleep_for(std::chrono::seconds(2));
        if (rt.stop)
            break;
        int w, h, ox, oy;
        if (!read_screen(w, h, ox, oy))
            continue;
        if (w == g_screen_w && h == g_screen_h && ox == g_screen_origin_x && oy == g_screen_origin_y)
            continue;
        g_screen_w = w;
        g_screen_h = h;
        g_screen_origin_x = ox;
        g_screen_origin_y = oy;
        rt.restart = true;
        ctrl_send_hello(rt);
    }
}

static void clipboard_watch_loop(Runtime &rt)
{
    {
        auto c = clip_read();
        std::lock_guard<std::mutex> lk(g_clip_m);
        g_last_clip = c;
    }
    while (!rt.stop)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
        if (rt.stop)
            break;
        auto cur = clip_read();
        if (cur.empty())
            continue;
        bool ch = false;
        {
            std::lock_guard<std::mutex> lk(g_clip_m);
            if (cur != g_last_clip)
            {
                g_last_clip = cur;
                ch = true;
            }
        }
        if (ch && cur.size() <= 512 * 1024)
            ctrl_send_clipboard(rt, cur);
    }
}

// ===== ffmpeg =====
static std::string build_ffmpeg_cmd(const Runtime &r)
{
    std::string exePath = getExePath();
    std::string dir = getExeDir();
    std::string ffmpeg = dir + "\\ffmpeg.exe";
    std::ostringstream c;
    c << "\"" << ffmpeg << "\" -hide_banner -loglevel warning"
      << " -f gdigrab -framerate " << r.framerate << " -draw_mouse 1"
      << " -i desktop";
    if (r.codec == "mjpeg")
    {
        c << " -f mjpeg -q:v " << r.mjpeg_q << " -pix_fmt yuvj420p pipe:1";
    }
    else
    {
        const std::string &e = r.encoder;
        if (e == "amf")
        {
            int gop = r.framerate * 2;
            c << " -c:v h264_amf -usage lowlatency -quality balanced -rc vbr_latency"
              << " -b:v " << r.bitrate << " -maxrate " << r.bitrate << " -g " << gop << " -bf 0";
        }
        else if (e == "qsv")
        {
            c << " -c:v h264_qsv -preset veryfast -look_ahead 0"
              << " -b:v " << r.bitrate << " -maxrate " << r.bitrate << " -g " << r.framerate << " -bf 0";
        }
        else if (e == "nvenc")
        {
            c << " -c:v h264_nvenc -preset p1 -tune ull -rc cbr"
              << " -b:v " << r.bitrate << " -g " << r.framerate << " -bf 0";
        }
        else
        {
            int gop = r.framerate * 2;
            c << " -c:v libx264 -preset veryfast -tune zerolatency -profile:v main -pix_fmt yuv420p"
              << " -bf 0 -refs 1 -b:v " << r.bitrate << " -maxrate " << r.bitrate
              << " -bufsize " << r.bitrate << " -g " << gop << " -keyint_min " << r.framerate;
        }
        c << " -f h264 -flush_packets 1 pipe:1";
    }
    return c.str();
}
static HANDLE start_ffmpeg(const std::string &cmd, PROCESS_INFORMATION &pi)
{
    SECURITY_ATTRIBUTES sa{sizeof sa, NULL, TRUE};
    HANDLE rd = NULL, wr = NULL;
    if (!CreatePipe(&rd, &wr, &sa, 4 * 1024 * 1024))
        return NULL;
    SetHandleInformation(rd, HANDLE_FLAG_INHERIT, 0);
    STARTUPINFOA si{};
    si.cb = sizeof si;
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = wr;
    si.hStdError = GetStdHandle(STD_ERROR_HANDLE);
    si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    std::vector<char> b(cmd.begin(), cmd.end());
    b.push_back(0);
    if (!CreateProcessA(NULL, b.data(), NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi))
    {
        CloseHandle(rd);
        CloseHandle(wr);
        return NULL;
    }
    CloseHandle(wr);
    return rd;
}

static void poll_config_loop(Runtime &rt)
{
    std::string last_sig;
    while (!rt.stop)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(2000));
        if (!g_registered)
            continue;
        std::string body = http_get(g_serverHost, g_serverPort,
                                    rmm_path("/agents/" + g_machineUID + "/config"),
                                    g_verifyCert);
        if (body.empty())
            continue;
        std::string codec, encoder, bitrate;
        int fps = 0, mq = 0;
        std::istringstream iss(body);
        std::string line;
        while (std::getline(iss, line))
        {
            if (!line.empty() && line.back() == '\r')
                line.pop_back();
            auto eq = line.find('=');
            if (eq == std::string::npos)
                continue;
            auto k = line.substr(0, eq), v = line.substr(eq + 1);
            if (k == "codec")
                codec = v;
            else if (k == "encoder")
                encoder = v;
            else if (k == "bitrate")
                bitrate = v;
            else if (k == "fps")
                fps = std::atoi(v.c_str());
            else if (k == "mjpeg_q")
                mq = std::atoi(v.c_str());
        }
        if (codec.empty())
            continue;
        std::string sig = codec + "|" + encoder + "|" + bitrate + "|" + std::to_string(fps) + "|" + std::to_string(mq);
        if (sig == last_sig)
            continue;
        last_sig = sig;
        std::lock_guard<std::mutex> lk(rt.m);
        rt.codec = codec;
        rt.encoder = encoder.empty() ? "cpu" : encoder;
        rt.bitrate = bitrate.empty() ? "4M" : bitrate;
        if (fps > 0)
            rt.framerate = fps;
        if (mq > 0)
            rt.mjpeg_q = mq;
        rt.restart = true;
        logf("config: codec=%s encoder=%s bitrate=%s fps=%d", rt.codec.c_str(), rt.encoder.c_str(), rt.bitrate.c_str(), rt.framerate);
    }
}

static void run_session(Runtime &rt)
{
    if (!g_registered)
    {
        std::this_thread::sleep_for(std::chrono::seconds(2));
        return;
    }

    std::string codec, encoder, bitrate;
    int fps, mq;
    {
        std::lock_guard<std::mutex> lk(rt.m);
        codec = rt.codec;
        encoder = rt.encoder;
        bitrate = rt.bitrate;
        fps = rt.framerate;
        mq = rt.mjpeg_q;
    }
    rt.restart = false;

    TlsConn *c = tls_connect(g_serverHost, g_serverPort, g_verifyCert);
    if (!c)
    {
        logs("tls_connect failed");
        return;
    }

    std::string path = rmm_path("/ingest/" + g_machineUID);
    std::string ctype = (codec == "mjpeg") ? "video/x-motion-jpeg" : "video/h264";
    std::ostringstream req;
    req << "POST " << path << " HTTP/1.1\r\n"
        << "Host: " << g_serverHost << ":" << g_serverPort << "\r\n"
        << "Content-Type: " << ctype << "\r\n"
        << "X-Agent-Encoder: " << encoder << "\r\n"
        << "X-Agent-Bitrate: " << bitrate << "\r\n"
        << "X-Agent-FPS: " << fps << "\r\n"
        << "Transfer-Encoding: chunked\r\n"
        << "Connection: close\r\n\r\n";
    std::string rs = req.str();
    if (!send_all(c, rs.data(), (int)rs.size()))
    {
        tls_close(c);
        delete c;
        return;
    }

    Runtime snap;
    snap.codec = codec;
    snap.encoder = encoder;
    snap.bitrate = bitrate;
    snap.framerate = fps;
    snap.mjpeg_q = mq;
    std::string cmd = build_ffmpeg_cmd(snap);

    PROCESS_INFORMATION pi{};
    HANDLE pipe = start_ffmpeg(cmd, pi);
    if (!pipe)
    {
        tls_close(c);
        delete c;
        return;
    }

    std::vector<char> buf(64 * 1024);
    auto t0 = std::chrono::steady_clock::now();
    uint64_t bytes = 0;
    while (!rt.stop)
    {
        if (rt.restart)
            break;
        DWORD n = 0;
        if (!ReadFile(pipe, buf.data(), (DWORD)buf.size(), &n, NULL) || n == 0)
            break;
        if (!send_chunk(c, buf.data(), (int)n))
            break;
        bytes += n;
    }
    send_all(c, "0\r\n\r\n", 5);
    TerminateProcess(pi.hProcess, 0);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    CloseHandle(pipe);
    tls_close(c);
    delete c;
}

// ===== main =====
int main()
{
    setupFileLogger();
    logf("Agent %s started, server=%s", g_buildSlug.c_str(), g_serverURL.c_str());

    WSADATA w;
    WSAStartup(MAKEWORD(2, 2), &w);
    init_screen();

    g_machineUID = loadOrCreateMachineUID();
    logf("machine_uid=%s", g_machineUID.c_str());

    // 1) регистрация в FastAPI
    registerLoop();
    if (!g_registered)
        return 1;

    // 2) первичная телеметрия
    sendTelemetry();

    // 3) heartbeat/update цикл в отдельном потоке
    std::thread hbT(heartbeatLoop);

    // 4) RMM потоки
    Runtime rt;
    std::thread ctrlT(control_loop, std::ref(rt));
    std::thread cfgT(poll_config_loop, std::ref(rt));
    std::thread resT(resolution_watch_loop, std::ref(rt));
    std::thread clpT(clipboard_watch_loop, std::ref(rt));

    while (!g_stopRequested)
    {
        run_session(rt);
        if (!g_stopRequested)
            std::this_thread::sleep_for(std::chrono::seconds(2));
    }

    rt.stop = true;
    ctrlT.join();
    cfgT.join();
    resT.join();
    clpT.join();
    hbT.join();
    WSACleanup();
    return 0;
}
