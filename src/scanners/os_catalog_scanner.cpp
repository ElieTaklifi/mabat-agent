#include "os_catalog_scanner.h"

#ifdef _WIN32
#include <windows.h>

#include <string>

namespace {

std::string readString(HKEY key, const char* valueName) {
    DWORD type = 0;
    DWORD size = 0;
    if (RegQueryValueExA(key, valueName, nullptr, &type, nullptr, &size) != ERROR_SUCCESS) {
        return {};
    }

    if ((type != REG_SZ && type != REG_EXPAND_SZ) || size == 0) {
        return {};
    }

    std::string value(size, '\0');
    if (RegQueryValueExA(key, valueName, nullptr, nullptr, reinterpret_cast<LPBYTE>(value.data()), &size) != ERROR_SUCCESS) {
        return {};
    }

    if (!value.empty() && value.back() == '\0') {
        value.pop_back();
    }

    return value;
}

}  // namespace
#endif

std::vector<RawSoftwareEntry> OSCatalogScanner::scan() {
    std::vector<RawSoftwareEntry> entries;

#ifdef _WIN32
    constexpr const char* kAppxPath = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Appx\\AppxAllUserStore\\Applications";

    HKEY applications = nullptr;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, kAppxPath, 0, KEY_READ, &applications) != ERROR_SUCCESS) {
        return entries;
    }

    char packageName[512] = {};
    for (DWORD index = 0;; ++index) {
        DWORD packageNameSize = static_cast<DWORD>(sizeof(packageName));
        if (RegEnumKeyExA(applications, index, packageName, &packageNameSize, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) {
            break;
        }

        HKEY packageKey = nullptr;
        if (RegOpenKeyExA(applications, packageName, 0, KEY_READ, &packageKey) != ERROR_SUCCESS) {
            continue;
        }

        RawSoftwareEntry entry;
        entry.name = packageName;
        entry.path = readString(packageKey, "Path");
        entry.source = "os_catalog";
        entry.rawMetadata["catalog"] = "appx";
        entry.rawMetadata["registryPath"] = std::string{kAppxPath} + "\\" + packageName;
        entries.push_back(std::move(entry));

        RegCloseKey(packageKey);
    }

    RegCloseKey(applications);
#endif

    return entries;
}
