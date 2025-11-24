// Monitor plug/unplug logger for Windows (C++ Win32, no external deps)
// Records connect/disconnect with adapter LUID + targetId, output technology,
// friendly names, DXGI adapter info, PNPDeviceID, EDID hash (best effort).
// Logs to C:\ProgramData\MonitorEvents\events.log with rotation.

#define NOMINMAX
#include <Windows.h>
#include <Dbt.h>
#include <devguid.h>
#include <dxgi.h>
#include <Shlwapi.h>
#include <string>
#include <vector>
#include <unordered_map>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <algorithm>
#include <filesystem>

#include <wincrypt.h>
#include <strsafe.h>

#pragma comment(lib, "User32.lib")
#pragma comment(lib, "Dxgi.lib")
#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "Shlwapi.lib")

// Stable monitor interface GUID (avoid SDK macro dependency)
// {E6F07B5F-EE97-4A90-B076-33F57BF4EAA7}
static const GUID kGuidDevInterfaceMonitor =
{ 0xE6F07B5F, 0xEE97, 0x4A90, { 0xB0, 0x76, 0x33, 0xF5, 0x7B, 0xF4, 0xEA, 0xA7 } };

// -------- Config --------
static const wchar_t* kLogDir = L"C:\\ProgramData\\MonitorEvents";
static const wchar_t* kLogFile = L"C:\\ProgramData\\MonitorEvents\\events.json";
static const size_t   kMaxLogBytes = 10 * 1024 * 1024; // 10MB
static const int      kMaxLogFiles = 5;
static const UINT     kEnumDelayMs = 150; // storm suppression
static const ULONGLONG kDedupWindowMs = 2000; // 2s

// -------- Utility --------
std::wstring LuidToString(const LUID& luid) {
    std::wstringstream ss;
    ss << std::hex << std::uppercase << luid.HighPart << L":" << luid.LowPart;
    return ss.str();
}

std::wstring OutputTechToString(DISPLAYCONFIG_VIDEO_OUTPUT_TECHNOLOGY tech) {
    switch (tech) {
    case DISPLAYCONFIG_OUTPUT_TECHNOLOGY_HDMI: return L"HDMI";
    case DISPLAYCONFIG_OUTPUT_TECHNOLOGY_DVI: return L"DVI";
#ifdef DISPLAYCONFIG_OUTPUT_TECHNOLOGY_DISPLAYPORT
    case DISPLAYCONFIG_OUTPUT_TECHNOLOGY_DISPLAYPORT: return L"DisplayPort";
#endif
#ifdef DISPLAYCONFIG_OUTPUT_TECHNOLOGY_DISPLAYPORT_EXTERNAL
    case DISPLAYCONFIG_OUTPUT_TECHNOLOGY_DISPLAYPORT_EXTERNAL: return L"DisplayPort";
#endif
#ifdef DISPLAYCONFIG_OUTPUT_TECHNOLOGY_DISPLAYPORT_EMBEDDED
    case DISPLAYCONFIG_OUTPUT_TECHNOLOGY_DISPLAYPORT_EMBEDDED: return L"DisplayPort";
#endif
    case DISPLAYCONFIG_OUTPUT_TECHNOLOGY_INTERNAL: return L"Internal";
    case DISPLAYCONFIG_OUTPUT_TECHNOLOGY_LVDS: return L"LVDS";
    case DISPLAYCONFIG_OUTPUT_TECHNOLOGY_COMPONENT_VIDEO: return L"Component";
    case DISPLAYCONFIG_OUTPUT_TECHNOLOGY_COMPOSITE_VIDEO: return L"Composite";
    case DISPLAYCONFIG_OUTPUT_TECHNOLOGY_SVIDEO: return L"S-Video";
#ifdef DISPLAYCONFIG_OUTPUT_TECHNOLOGY_USB
    case DISPLAYCONFIG_OUTPUT_TECHNOLOGY_USB: return L"USB";
#endif
    case DISPLAYCONFIG_OUTPUT_TECHNOLOGY_OTHER: return L"Other";
    default: return L"Unknown";
    }
}

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

    // Delete oldest
    std::wstring oldest = std::wstring(kLogFile) + L"." + std::to_wstring(kMaxLogFiles);
    DeleteFileW(oldest.c_str());

    // Shift
    for (int i = kMaxLogFiles - 1; i >= 1; --i) {
        std::wstring from = std::wstring(kLogFile) + L"." + std::to_wstring(i);
        std::wstring to = std::wstring(kLogFile) + L"." + std::to_wstring(i + 1);
        MoveFileExW(from.c_str(), to.c_str(), MOVEFILE_REPLACE_EXISTING);
    }
    // Base -> .1
    std::wstring to1 = std::wstring(kLogFile) + L".1";
    MoveFileExW(kLogFile, to1.c_str(), MOVEFILE_REPLACE_EXISTING);
}

void AppendJsonLine(const std::string& line) {
    EnsureDir(kLogDir);
    RotateLogsIfNeeded(line.size() + 2);
    std::ofstream ofs(WStringToUtf8(kLogFile), std::ios::app | std::ios::binary);
    ofs << line << "\r\n";
}

// SHA1 of EDID bytes -> hex
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

// Parse monitorDevicePath to PNP hardware+instance
// Example: "\\?\DISPLAY#GSM5B0A#4&2bd1b41d&0&UID697347#..." -> hardware="GSM5B0A", instance="4&2bd1b41d&0&UID697347"
bool ParsePnpFromDevicePath(const std::wstring& path, std::wstring& hardware, std::wstring& instance) {
    auto marker = L"DISPLAY#";
    size_t pos = path.find(marker);
    if (pos == std::wstring::npos) return false;
    size_t start = pos + wcslen(marker);
    size_t hEnd = path.find(L'#', start);
    if (hEnd == std::wstring::npos) return false;
    hardware = path.substr(start, hEnd - start);
    size_t iStart = hEnd + 1;
    size_t iEnd = path.find(L'#', iStart);
    if (iEnd == std::wstring::npos) iEnd = path.size();
    instance = path.substr(iStart, iEnd - iStart);
    return !hardware.empty() && !instance.empty();
}

// Read EDID from registry HKLM\SYSTEM\CCS\Enum\DISPLAY\<hardware>\<instance>\Device Parameters\EDID
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

// -------- DXGI cache --------
struct DxgiAdapterInfo {
    std::wstring description;
    UINT vendorId = 0;
};

struct LuidHash {
    size_t operator()(const LUID& l) const noexcept {
        return (size_t)l.LowPart ^ ((size_t)l.HighPart << 1);
    }
};
struct LuidEq {
    bool operator()(const LUID& a, const LUID& b) const noexcept {
        return a.HighPart == b.HighPart && a.LowPart == b.LowPart;
    }
};

class DxgiCache {
public:
    DxgiCache() { build(); }
    bool get(const LUID& luid, DxgiAdapterInfo& out) const {
        auto it = cache.find(luid);
        if (it == cache.end()) return false;
        out = it->second;
        return true;
    }
private:
    std::unordered_map<LUID, DxgiAdapterInfo, LuidHash, LuidEq> cache;
    void build() {
        IDXGIFactory* factory = nullptr;
        if (FAILED(CreateDXGIFactory(__uuidof(IDXGIFactory), (void**)&factory))) return;
        for (UINT i = 0; ; ++i) {
            IDXGIAdapter* adapter = nullptr;
            if (factory->EnumAdapters(i, &adapter) == DXGI_ERROR_NOT_FOUND) break;
            DXGI_ADAPTER_DESC desc{};
            if (SUCCEEDED(adapter->GetDesc(&desc))) {
                LUID luid = desc.AdapterLuid;
                DxgiAdapterInfo info;
                info.description = desc.Description;
                info.vendorId = desc.VendorId;
                cache[luid] = info;
            }
            adapter->Release();
        }
        factory->Release();
    }
};

// -------- Display enumeration --------
struct TargetInfo {
    LUID adapterLuid{};
    UINT32 targetId = 0;
    UINT32 sourceId = 0;
    DISPLAYCONFIG_VIDEO_OUTPUT_TECHNOLOGY tech = DISPLAYCONFIG_OUTPUT_TECHNOLOGY_OTHER;
    std::wstring displayName; // \\.\DISPLAY1
    std::wstring friendlyName; // monitor friendly
    std::wstring devicePath; // monitorDevicePath (contains PNP)
};

std::vector<TargetInfo> EnumerateActiveTargets() {
    UINT32 pathCount = 0, modeCount = 0;
    if (FAILED(GetDisplayConfigBufferSizes(QDC_ONLY_ACTIVE_PATHS, &pathCount, &modeCount))) {
        return {};
    }
    std::vector<DISPLAYCONFIG_PATH_INFO> paths(pathCount);
    std::vector<DISPLAYCONFIG_MODE_INFO> modes(modeCount);
    if (FAILED(QueryDisplayConfig(QDC_ONLY_ACTIVE_PATHS, &pathCount, paths.data(), &modeCount, modes.data(), nullptr))) {
        return {};
    }

    std::vector<TargetInfo> out;
    out.reserve(pathCount);

    for (UINT32 i = 0; i < pathCount; ++i) {
        auto& p = paths[i];
        TargetInfo ti;
        ti.adapterLuid = p.targetInfo.adapterId;
        ti.targetId = p.targetInfo.id;
        ti.sourceId = p.sourceInfo.id;
        ti.tech = p.targetInfo.outputTechnology;

        DISPLAYCONFIG_TARGET_DEVICE_NAME tname{};
        tname.header.size = sizeof(tname);
        tname.header.type = DISPLAYCONFIG_DEVICE_INFO_GET_TARGET_NAME;
        tname.header.adapterId = p.targetInfo.adapterId;
        tname.header.id = p.targetInfo.id;
        if (SUCCEEDED(DisplayConfigGetDeviceInfo(&tname.header))) {
            ti.friendlyName = tname.monitorFriendlyDeviceName;
            ti.devicePath = tname.monitorDevicePath;
        }

        DISPLAYCONFIG_SOURCE_DEVICE_NAME sname{};
        sname.header.size = sizeof(sname);
        sname.header.type = DISPLAYCONFIG_DEVICE_INFO_GET_SOURCE_NAME;
        sname.header.adapterId = p.sourceInfo.adapterId;
        sname.header.id = p.sourceInfo.id;
        if (SUCCEEDED(DisplayConfigGetDeviceInfo(&sname.header))) {
            ti.displayName = sname.viewGdiDeviceName; // e.g., \\.\DISPLAY1
        }

        out.push_back(std::move(ti));
    }
    return out;
}

// -------- State & dedup --------
struct KeyHash {
    size_t operator()(const std::wstring& s) const noexcept {
        // Simple FNV-1a
        size_t h = 1469598103934665603ull;
        for (wchar_t c : s) { h ^= (size_t)c; h *= 1099511628211ull; }
        return h;
    }
};

std::unordered_map<std::wstring, TargetInfo, KeyHash> g_prev; // key = LUID:targetId
std::unordered_map<std::wstring, ULONGLONG, KeyHash> g_lastEmit; // key+action -> tick
DxgiCache g_dxgi;

std::wstring MakeKey(const TargetInfo& ti) {
    return LuidToString(ti.adapterLuid) + L":" + std::to_wstring(ti.targetId);
}

bool ShouldEmit(const std::wstring& keyAction) {
    ULONGLONG now = GetTickCount64();
    auto it = g_lastEmit.find(keyAction);
    if (it == g_lastEmit.end() || now - it->second >= kDedupWindowMs) {
        g_lastEmit[keyAction] = now;
        return true;
    }
    return false;
}

void LogEvent(const TargetInfo& ti, const std::wstring& action) {
    DxgiAdapterInfo dxgi{};
    g_dxgi.get(ti.adapterLuid, dxgi);

    std::wstring hardware, instance;
    std::wstring pnpId, edidHash;
    if (ParsePnpFromDevicePath(ti.devicePath, hardware, instance)) {
        pnpId = hardware + L"\\" + instance;
        edidHash = ReadEdidHashFromRegistry(hardware, instance);
    }

    // JSON build (UTF-8 with escaping)
    std::ostringstream js;
    auto ts = WStringToUtf8(NowIso8601Utc());
    js << "{";
    js << "\"timestamp\":\"" << JsonEscape(ts) << "\",";
    js << "\"action\":\"" << JsonEscape(WStringToUtf8(action)) << "\",";
    js << "\"adapterLuid\":\"" << JsonEscape(WStringToUtf8(LuidToString(ti.adapterLuid))) << "\",";
    js << "\"vendorId\":\"" << dxgi.vendorId << "\",";
    js << "\"adapterDescription\":\"" << JsonEscape(WStringToUtf8(dxgi.description)) << "\",";
    js << "\"targetId\":" << ti.targetId << ",";
    js << "\"sourceId\":" << ti.sourceId << ",";
    js << "\"outputTechnology\":\"" << JsonEscape(WStringToUtf8(OutputTechToString(ti.tech))) << "\",";
    js << "\"displayName\":\"" << JsonEscape(WStringToUtf8(ti.displayName)) << "\",";
    js << "\"monitorFriendlyName\":\"" << JsonEscape(WStringToUtf8(ti.friendlyName)) << "\",";
    js << "\"PNPDeviceID\":\"" << JsonEscape(WStringToUtf8(pnpId)) << "\",";
    js << "\"EDIDHash\":\"" << JsonEscape(WStringToUtf8(edidHash)) << "\",";
    js << "\"topologyHint\":\"\",";
    js << "\"deviceInterfaceClassGuid\":\"" << JsonEscape("{E6F07B5F-EE97-4A90-B076-33F57BF4EAA7}") << "\"";
    js << "}";

    AppendJsonLine(js.str());
}

// Decide connect/disconnect compared to previous snapshot
void DiffAndLog(const std::vector<TargetInfo>& cur) {
    std::unordered_map<std::wstring, TargetInfo, KeyHash> curMap;
    for (auto& ti : cur) curMap.emplace(MakeKey(ti), ti);

    // Connected: in cur but not in prev
    for (auto& [key, ti] : curMap) {
        if (g_prev.find(key) == g_prev.end()) {
            std::wstring keyAction = key + L":connected";
            if (ShouldEmit(keyAction)) LogEvent(ti, L"connected");
        }
    }
    // Disconnected: in prev but not in cur
    for (auto& [key, tiPrev] : g_prev) {
        if (curMap.find(key) == curMap.end()) {
            std::wstring keyAction = key + L":disconnected";
            if (ShouldEmit(keyAction)) LogEvent(tiPrev, L"disconnected");
        }
    }
    g_prev.swap(curMap);
}

// -------- Window & notifications --------
static const wchar_t* kWndClass = L"MonitorEventLoggerHiddenClass";
static const UINT_PTR kTimerId = 1;

HDEVNOTIFY g_hDevNotify = nullptr;

void RequestEnumerate(HWND hwnd) {
    // arm storm suppression timer
    SetTimer(hwnd, kTimerId, kEnumDelayMs, nullptr);
}

LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_CREATE: {
        DEV_BROADCAST_DEVICEINTERFACE filter{};
        filter.dbcc_size = sizeof(filter);
        filter.dbcc_devicetype = DBT_DEVTYP_DEVICEINTERFACE;
        filter.dbcc_classguid = kGuidDevInterfaceMonitor;
        g_hDevNotify = RegisterDeviceNotificationW(hwnd, &filter, DEVICE_NOTIFY_WINDOW_HANDLE);
        // initial snapshot without logging
        g_prev.clear();
        auto snapshot = EnumerateActiveTargets();
        for (auto& ti : snapshot) g_prev.emplace(MakeKey(ti), ti);
        break;
    }
    case WM_DEVICECHANGE:
    case WM_DISPLAYCHANGE:
    case WM_SETTINGCHANGE:
        RequestEnumerate(hwnd);
        break;
    case WM_TIMER:
        if (wParam == kTimerId) {
            KillTimer(hwnd, kTimerId);
            auto cur = EnumerateActiveTargets();
            DiffAndLog(cur);
        }
        break;
    case WM_DESTROY:
        if (g_hDevNotify) { UnregisterDeviceNotification(g_hDevNotify); g_hDevNotify = nullptr; }
        PostQuitMessage(0);
        break;
    default:
        return DefWindowProcW(hwnd, msg, wParam, lParam);
    }
    return 0;
}

int APIENTRY wWinMain(HINSTANCE hInst, HINSTANCE, LPWSTR, int) {
    // Ensure log dir exists
    EnsureDir(kLogDir);

    WNDCLASSW wc{};
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInst;
    wc.lpszClassName = kWndClass;
    RegisterClassW(&wc);

    // Message-only window (hidden)
    HWND hwnd = CreateWindowExW(0, kWndClass, L"", 0,
        0, 0, 0, 0, HWND_MESSAGE, nullptr, hInst, nullptr);
    if (!hwnd) return 1;

    MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    return 0;
}