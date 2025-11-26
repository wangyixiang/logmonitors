// compile: cl /std:c++17 /EHsc /DUNICODE /D_UNICODE /utf-8 svcmain.cpp /link advapi32.lib setupapi.lib cfgmgr32.lib shlwapi.lib crypt32.lib user32.lib
#include <Windows.h>
#include <Winsvc.h>
#include <Dbt.h>
#include <devguid.h>
#include <SetupAPI.h>
#include <Cfgmgr32.h>
#include <Shlwapi.h>
#include <string>
#include <vector>
#include <unordered_map>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <wincrypt.h>

#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "Setupapi.lib")
#pragma comment(lib, "Cfgmgr32.lib")
#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "User32.lib")

static const wchar_t* kVersion = L"0.1.0.0";
static const GUID kGuidDevInterfaceMonitor =
{ 0xE6F07B5F, 0xEE97, 0x4A90, { 0xB0, 0x76, 0x33, 0xF5, 0x7B, 0xF4, 0xEA, 0xA7 } };

static const wchar_t* kLogDir = L"C:\\ProgramData\\MonitorEvents";
static const wchar_t* kLogFile = L"C:\\ProgramData\\MonitorEvents\\svcevents.json";
static const size_t   kMaxLogBytes = 10 * 1024 * 1024;
static const int      kMaxLogFiles = 5;
static const UINT     kEnumDelayMs = 150;
static const ULONGLONG kDedupWindowMs = 2000;
static const wchar_t* kServiceName = L"LogMonitorService";

std::wstring NowIso8601Utc() {
    using namespace std::chrono;
    auto now = system_clock::now();
    auto secs = time_point_cast<std::chrono::seconds>(now);
    auto ms = duration_cast<std::chrono::milliseconds>(now - secs).count();
    std::time_t t = system_clock::to_time_t(now);
    struct tm gtm{};
    gmtime_s(&gtm, &t);
    wchar_t buf[64];
    swprintf_s(buf, L"%04d-%02d-%02dT%02d:%02d:%02d.%03lldZ",
        gtm.tm_year + 1900, gtm.tm_mon + 1, gtm.tm_mday,
        gtm.tm_hour, gtm.tm_min, gtm.tm_sec, ms);
    return buf;
}
std::string WStringToUtf8(const std::wstring& ws) {
    if (ws.empty()) return {};
    int size = WideCharToMultiByte(CP_UTF8, 0, ws.c_str(), (int)ws.size(), nullptr, 0, nullptr, nullptr);
    std::string out(size, '\0');
    WideCharToMultiByte(CP_UTF8, 0, ws.c_str(), (int)ws.size(), out.data(), size, nullptr, nullptr);
    return out;
}
std::string JsonEscape(const std::string& s) {
    std::ostringstream o;
    for (unsigned char c : s) {
        switch (c) {
        case '\"': o << "\\\""; break;
        case '\\': o << "\\\\"; break;
        case '\b': o << "\\b"; break;
        case '\f': o << "\\f"; break;
        case '\n': o << "\\n"; break;
        case '\r': o << "\\r"; break;
        case '\t': o << "\\t"; break;
        default:
            if (c < 0x20) { o << "\\u" << std::hex << std::setw(4) << std::setfill('0') << int(c); }
            else { o << c; }
        }
    }
    return o.str();
}
bool EnsureDir(const std::wstring& dir) {
    DWORD attrs = GetFileAttributesW(dir.c_str());
    if (attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_DIRECTORY)) return true;
    return CreateDirectoryW(dir.c_str(), nullptr) != 0 || GetLastError() == ERROR_ALREADY_EXISTS;
}
uint64_t FileSize(const std::wstring& path) {
    WIN32_FILE_ATTRIBUTE_DATA fad{};
    if (!GetFileAttributesExW(path.c_str(), GetFileExInfoStandard, &fad)) return 0;
    ULARGE_INTEGER sz{};
    sz.HighPart = fad.nFileSizeHigh;
    sz.LowPart = fad.nFileSizeLow;
    return sz.QuadPart;
}
void RotateLogsIfNeeded(size_t incoming_bytes) {
    uint64_t current = FileSize(kLogFile);
    if (current + incoming_bytes <= kMaxLogBytes) return;
    std::wstring oldest = std::wstring(kLogFile) + L"." + std::to_wstring(kMaxLogFiles);
    DeleteFileW(oldest.c_str());
    for (int i = kMaxLogFiles - 1; i >= 1; --i) {
        std::wstring from = std::wstring(kLogFile) + L"." + std::to_wstring(i);
        std::wstring to = std::wstring(kLogFile) + L"." + std::to_wstring(i + 1);
        MoveFileExW(from.c_str(), to.c_str(), MOVEFILE_REPLACE_EXISTING);
    }
    std::wstring to1 = std::wstring(kLogFile) + L".1";
    MoveFileExW(kLogFile, to1.c_str(), MOVEFILE_REPLACE_EXISTING);
}
void AppendJsonLine(const std::string& line) {
    EnsureDir(kLogDir);
    RotateLogsIfNeeded(line.size() + 2);
    std::ofstream ofs(WStringToUtf8(kLogFile), std::ios::app | std::ios::binary);
    ofs << line << "\r\n";
}
std::wstring Sha1Hex(const std::vector<BYTE>& data) {
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    if (!CryptAcquireContext(&hProv, nullptr, nullptr, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) return L"";
    if (!CryptCreateHash(hProv, CALG_SHA1, 0, 0, &hHash)) { CryptReleaseContext(hProv, 0); return L""; }
    CryptHashData(hHash, data.data(), (DWORD)data.size(), 0);
    BYTE hash[20];
    DWORD hashLen = sizeof(hash);
    if (!CryptGetHashParam(hHash, HP_HASHVAL, hash, &hashLen, 0)) { CryptDestroyHash(hHash); CryptReleaseContext(hProv, 0); return L""; }
    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
    std::wostringstream oss;
    oss << std::hex << std::uppercase << std::setfill(L'0');
    for (DWORD i = 0; i < hashLen; ++i) oss << std::setw(2) << int(hash[i]);
    return oss.str();
}
std::wstring ReadEdidHashFromRegistry(const std::wstring& hardware, const std::wstring& instance) {
    HKEY hKey = nullptr;
    std::wstring base = L"SYSTEM\\CurrentControlSet\\Enum\\DISPLAY\\" + hardware + L"\\" + instance + L"\\Device Parameters";
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, base.c_str(), 0, KEY_READ, &hKey) != ERROR_SUCCESS) return L"";
    DWORD type = 0, size = 0;
    if (RegQueryValueExW(hKey, L"EDID", nullptr, &type, nullptr, &size) != ERROR_SUCCESS || type != REG_BINARY || size == 0) { RegCloseKey(hKey); return L""; }
    std::vector<BYTE> edid(size);
    if (RegQueryValueExW(hKey, L"EDID", nullptr, &type, edid.data(), &size) != ERROR_SUCCESS) { RegCloseKey(hKey); return L""; }
    RegCloseKey(hKey);
    return Sha1Hex(edid);
}

struct MonitorInfo {
    std::wstring hardware;
    std::wstring instance;
    std::wstring friendlyName;
    std::wstring edidHash;
    std::wstring gpuDescription;
    std::wstring gpuDeviceId;
};

std::wstring GetDevNodeProperty(DEVINST dn, ULONG prop) {
    wchar_t buf[512];
    ULONG len = sizeof(buf);
    if (CM_Get_DevNode_Registry_PropertyW(dn, prop, nullptr, buf, &len, 0) == CR_SUCCESS) {
        return buf;
    }
    return L"";
}

std::vector<MonitorInfo> EnumeratePresentMonitors() {
    std::vector<MonitorInfo> out;
    HDEVINFO h = SetupDiGetClassDevsW(&GUID_DEVCLASS_MONITOR, nullptr, nullptr, DIGCF_PRESENT);
    if (h == INVALID_HANDLE_VALUE) return out;
    SP_DEVINFO_DATA di{};
    di.cbSize = sizeof(di);
    for (DWORD i = 0; SetupDiEnumDeviceInfo(h, i, &di); ++i) {
        wchar_t idBuf[1024];
        if (!SetupDiGetDeviceInstanceIdW(h, &di, idBuf, ARRAYSIZE(idBuf), nullptr)) continue;
        std::wstring id = idBuf;
        if (id.rfind(L"DISPLAY\\", 0) != 0) continue;
        size_t p = id.find(L'\\', 8);
        if (p == std::wstring::npos) continue;
        std::wstring hardware = id.substr(8, p - 8);
        std::wstring instance = id.substr(p + 1);
        wchar_t nameBuf[256];
        DWORD type = 0, size = 0;
        std::wstring friendly;
        if (SetupDiGetDeviceRegistryPropertyW(h, &di, SPDRP_FRIENDLYNAME, &type, (BYTE*)nameBuf, sizeof(nameBuf), &size) && type == REG_SZ) friendly = nameBuf;
        else if (SetupDiGetDeviceRegistryPropertyW(h, &di, SPDRP_DEVICEDESC, &type, (BYTE*)nameBuf, sizeof(nameBuf), &size) && type == REG_SZ) friendly = nameBuf;
        std::wstring edid = ReadEdidHashFromRegistry(hardware, instance);

        // Resolve Parent (GPU) info
        std::wstring gpuDesc, gpuDevId;
        DEVINST parent = 0;
        if (CM_Get_Parent(&parent, di.DevInst, 0) == CR_SUCCESS) {
            gpuDesc = GetDevNodeProperty(parent, CM_DRP_FRIENDLYNAME);
            if (gpuDesc.empty()) gpuDesc = GetDevNodeProperty(parent, CM_DRP_DEVICEDESC);
            wchar_t parentIdBuf[1024];
            if (CM_Get_Device_IDW(parent, parentIdBuf, ARRAYSIZE(parentIdBuf), 0) == CR_SUCCESS) {
                gpuDevId = parentIdBuf;
            }
        }

        MonitorInfo mi{ hardware, instance, friendly, edid, gpuDesc, gpuDevId };
        out.push_back(std::move(mi));
    }
    SetupDiDestroyDeviceInfoList(h);
    return out;
}

struct KeyHash {
    size_t operator()(const std::wstring& s) const noexcept {
        size_t h = 1469598103934665603ull;
        for (wchar_t c : s) { h ^= (size_t)c; h *= 1099511628211ull; }
        return h;
    }
};
std::unordered_map<std::wstring, MonitorInfo, KeyHash> g_prev;
std::unordered_map<std::wstring, ULONGLONG, KeyHash> g_lastEmit;

bool ShouldEmit(const std::wstring& keyAction) {
    ULONGLONG now = GetTickCount64();
    auto it = g_lastEmit.find(keyAction);
    if (it == g_lastEmit.end() || now - it->second >= kDedupWindowMs) {
        g_lastEmit[keyAction] = now;
        return true;
    }
    return false;
}
void LogEvent(const MonitorInfo& mi, const std::wstring& action) {
    std::ostringstream js;
    auto ts = WStringToUtf8(NowIso8601Utc());
    std::wstring pnp = mi.hardware + L"\\" + mi.instance;
    js << "{";
    js << "\"timestamp\":\"" << JsonEscape(ts) << "\",";
    js << "\"action\":\"" << JsonEscape(WStringToUtf8(action)) << "\",";
    js << "\"monitorFriendlyName\":\"" << JsonEscape(WStringToUtf8(mi.friendlyName)) << "\",";
    js << "\"PNPDeviceID\":\"" << JsonEscape(WStringToUtf8(pnp)) << "\",";
    js << "\"EDIDHash\":\"" << JsonEscape(WStringToUtf8(mi.edidHash)) << "\",";
    js << "\"gpuDescription\":\"" << JsonEscape(WStringToUtf8(mi.gpuDescription)) << "\",";
    js << "\"gpuDeviceID\":\"" << JsonEscape(WStringToUtf8(mi.gpuDeviceId)) << "\",";
    // Windows 系统定义的标准标识符，全称为 GUID_DEVINTERFACE_MONITOR
    // 这个 GUID ( {E6F07B5F-EE97-4A90-B076-33F57BF4EAA7} ) 是 Windows 操作系统专门分配给 显示器设备接口（Monitor Device Interface） 的唯一标识。
    js << "\"deviceInterfaceClassGuid\":\"" << JsonEscape("{E6F07B5F-EE97-4A90-B076-33F57BF4EAA7}") << "\"";
    js << "}";
    AppendJsonLine(js.str());
}
void DiffAndLog(const std::vector<MonitorInfo>& cur) {
    std::unordered_map<std::wstring, MonitorInfo, KeyHash> curMap;
    for (auto& mi : cur) curMap.emplace(mi.hardware + L"\\" + mi.instance, mi);
    for (auto& [key, mi] : curMap) {
        if (g_prev.find(key) == g_prev.end()) {
            std::wstring keyAction = key + L":connected";
            if (ShouldEmit(keyAction)) LogEvent(mi, L"connected");
        }
    }
    for (auto& [key, miPrev] : g_prev) {
        if (curMap.find(key) == curMap.end()) {
            std::wstring keyAction = key + L":disconnected";
            if (ShouldEmit(keyAction)) LogEvent(miPrev, L"disconnected");
        }
    }
    g_prev.swap(curMap);
}

SERVICE_STATUS_HANDLE g_svcHandle = nullptr;
HDEVNOTIFY g_hDevNotify = nullptr;
HANDLE g_stopEvent = nullptr;
HANDLE g_enumEvent = nullptr;
HANDLE g_worker = nullptr;

void RequestEnumerate() { SetEvent(g_enumEvent); }

DWORD WINAPI HandlerEx(DWORD control, DWORD eventType, LPVOID eventData, LPVOID) {
    if (control == SERVICE_CONTROL_STOP || control == SERVICE_CONTROL_SHUTDOWN) {
        SERVICE_STATUS st{};
        st.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
        st.dwCurrentState = SERVICE_STOP_PENDING;
        st.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
        SetServiceStatus(g_svcHandle, &st);
        if (g_stopEvent) SetEvent(g_stopEvent);
        return NO_ERROR;
    }
    if (control == SERVICE_CONTROL_DEVICEEVENT) {
        if (eventType == DBT_DEVICEARRIVAL || eventType == DBT_DEVICEREMOVECOMPLETE || eventType == DBT_DEVNODES_CHANGED) {
            RequestEnumerate();
        }
        return NO_ERROR;
    }
    return NO_ERROR;
}

DWORD WINAPI WorkerThread(LPVOID) {
    g_prev.clear();
    auto snapshot = EnumeratePresentMonitors();
    for (auto& mi : snapshot) g_prev.emplace(mi.hardware + L"\\" + mi.instance, mi);
    HANDLE hs[2] = { g_stopEvent, g_enumEvent };
    while (true) {
        DWORD w = WaitForMultipleObjects(2, hs, FALSE, INFINITE);
        if (w == WAIT_OBJECT_0) break;
        if (w == WAIT_OBJECT_0 + 1) {
            ResetEvent(g_enumEvent);
            Sleep(kEnumDelayMs);
            auto cur = EnumeratePresentMonitors();
            DiffAndLog(cur);
        }
    }
    return 0;
}

void SetRunning() {
    SERVICE_STATUS st{};
    st.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    st.dwCurrentState = SERVICE_RUNNING;
    st.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    SetServiceStatus(g_svcHandle, &st);
}
void SetStopped() {
    SERVICE_STATUS st{};
    st.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    st.dwCurrentState = SERVICE_STOPPED;
    SetServiceStatus(g_svcHandle, &st);
}

void WINAPI ServiceMain(DWORD, LPWSTR*) {
    g_svcHandle = RegisterServiceCtrlHandlerExW(kServiceName, HandlerEx, nullptr);
    if (!g_svcHandle) return;
    EnsureDir(kLogDir);
    g_stopEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    g_enumEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    DEV_BROADCAST_DEVICEINTERFACE filter{};
    filter.dbcc_size = sizeof(filter);
    filter.dbcc_devicetype = DBT_DEVTYP_DEVICEINTERFACE;
    filter.dbcc_classguid = kGuidDevInterfaceMonitor;
    g_hDevNotify = RegisterDeviceNotificationW(g_svcHandle, &filter, DEVICE_NOTIFY_SERVICE_HANDLE);
    g_worker = CreateThread(nullptr, 0, WorkerThread, nullptr, 0, nullptr);
    SetRunning();
    WaitForSingleObject(g_worker, INFINITE);
    if (g_hDevNotify) { UnregisterDeviceNotification(g_hDevNotify); g_hDevNotify = nullptr; }
    if (g_worker) { CloseHandle(g_worker); g_worker = nullptr; }
    if (g_stopEvent) { CloseHandle(g_stopEvent); g_stopEvent = nullptr; }
    if (g_enumEvent) { CloseHandle(g_enumEvent); g_enumEvent = nullptr; }
    SetStopped();
}

int wmain() {
    SERVICE_TABLE_ENTRYW table[] = {
        { const_cast<LPWSTR>(kServiceName), ServiceMain },
        { nullptr, nullptr }
    };
    StartServiceCtrlDispatcherW(table);
    return 0;
}