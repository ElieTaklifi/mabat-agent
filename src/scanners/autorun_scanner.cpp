#include "autorun_scanner.h"

#include <stdexcept>
#include <set>

#ifdef _WIN32
#include <windows.h>
#include <string>
#include <sddl.h>     // ConvertSidToStringSidA
#include <lmcons.h>   // UNLEN

#pragma comment(lib, "advapi32.lib")

// Open a key and call emitAllValues; silently returns on failure.
void scanValuesUnderKey(
    HKEY               root,
    const std::string& subPath,
    const char*        mechanism,
    const std::string& context,
    const std::string& userSid,
    std::vector<RawSoftwareEntry>& entries)
{
    HKEY key = nullptr;
    if (RegOpenKeyExA(root, subPath.c_str(), 0, KEY_READ, &key) != ERROR_SUCCESS)
        return;
    emitAllValues(key, subPath, mechanism, context, userSid, entries);
    RegCloseKey(key);
}

//  Scans:
//    HKLM  \SOFTWARE\Microsoft\Windows\CurrentVersion\Run
//    HKLM  \SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
//    HKLM  \SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx
//    HKLM  \SOFTWARE\WOW6432Node\...\Run
//    HKLM  \SOFTWARE\WOW6432Node\...\RunOnce
//    HKU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Run       (all loaded users)
//    HKU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce

std::vector<RawSoftwareEntry> AutorunScanner::scan(){
    std::vector<RawSoftwareEntry> entries;

    // ── Machine-wide (64-bit view) ──────────────────────────────
    const std::string base64 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\";
    scanValuesUnderKey(HKEY_LOCAL_MACHINE, base64 + "Run",
                       AutorunMechanism::RunKey, "machine", "", entries);
    scanValuesUnderKey(HKEY_LOCAL_MACHINE, base64 + "RunOnce",
                       AutorunMechanism::RunOnceKey, "machine", "", entries);
    scanValuesUnderKey(HKEY_LOCAL_MACHINE, base64 + "RunOnceEx",
                       AutorunMechanism::RunOnceKey, "machine", "", entries);

    // ── Machine-wide (32-bit / WOW64 view) ─────────────────────
    const std::string base32 = "SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\";
    scanValuesUnderKey(HKEY_LOCAL_MACHINE, base32 + "Run",
                       AutorunMechanism::RunKey, "machine", "", entries);
    scanValuesUnderKey(HKEY_LOCAL_MACHINE, base32 + "RunOnce",
                       AutorunMechanism::RunOnceKey, "machine", "", entries);

    // ── Per-user: all loaded hives under HKU ────────────────────
    char sidBuf[256] = {};
    for (DWORD i = 0; ; ++i) {
        DWORD sidSize = sizeof(sidBuf);
        LONG  rc      = RegEnumKeyExA(HKEY_USERS, i, sidBuf, &sidSize,
                                      nullptr, nullptr, nullptr, nullptr);
        if (rc == ERROR_NO_MORE_ITEMS) break;
        if (rc != ERROR_SUCCESS)       continue;

        std::string sid(sidBuf);
        if (isSystemSid(sid)) continue;

        std::string userName = sidToUsername(sid);
        std::string userBase = sid + "\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\";

        scanValuesUnderKey(HKEY_USERS, userBase + "Run",
                           AutorunMechanism::RunKey, userName, sid, entries);
        scanValuesUnderKey(HKEY_USERS, userBase + "RunOnce",
                           AutorunMechanism::RunOnceKey, userName, sid, entries);
    }

}