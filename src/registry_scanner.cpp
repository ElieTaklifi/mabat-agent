#include "registry_scanner.h"

#include <stdexcept>

#ifdef _WIN32
#include <windows.h>

#include <string>

namespace {

std::string readRegString(HKEY key, const char* name) {
    DWORD type = 0;
    DWORD size = 0;
    if (RegQueryValueExA(key, name, nullptr, &type, nullptr, &size) != ERROR_SUCCESS) {
        return {};
    }

    if ((type != REG_SZ && type != REG_EXPAND_SZ) || size == 0) {
        return {};
    }

    std::string out(size, '\0');
    if (RegQueryValueExA(key, name, nullptr, nullptr, reinterpret_cast<LPBYTE>(out.data()), &size) != ERROR_SUCCESS) {
        return {};
    }

    if (!out.empty() && out.back() == '\0') {
        out.pop_back();
    }
    return out;
}

void enumerateUninstallRoot(HKEY root, const std::string& path, std::vector<RawSoftwareEntry>& entries) {
    HKEY uninstall = nullptr;
    if (RegOpenKeyExA(root, path.c_str(), 0, KEY_READ, &uninstall) != ERROR_SUCCESS) {
        return;
    }

    char subkeyName[512] = {};
    for (DWORD index = 0;; ++index) {
        DWORD subkeySize = static_cast<DWORD>(sizeof(subkeyName));
        if (RegEnumKeyExA(uninstall, index, subkeyName, &subkeySize, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) {
            break;
        }

        HKEY subkey = nullptr;
        if (RegOpenKeyExA(uninstall, subkeyName, 0, KEY_READ, &subkey) != ERROR_SUCCESS) {
            continue;
        }

        RawSoftwareEntry entry;
        entry.name = readRegString(subkey, "DisplayName");
        entry.path = readRegString(subkey, "InstallLocation");
        entry.source = "registry";
        entry.rawMetadata["registryPath"] = path + "\\" + subkeyName;
        entry.rawMetadata["publisher"] = readRegString(subkey, "Publisher");
        entry.rawMetadata["displayVersion"] = readRegString(subkey, "DisplayVersion");

        if (!entry.name.empty()) {
            entries.push_back(std::move(entry));
        }

        RegCloseKey(subkey);
    }

    RegCloseKey(uninstall);
}

}  // namespace
#endif

std::vector<RawSoftwareEntry> RegistryScanner::scan() {
    std::vector<RawSoftwareEntry> entries;

#ifdef _WIN32
    try {
        enumerateUninstallRoot(HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall", entries);
        enumerateUninstallRoot(HKEY_LOCAL_MACHINE, "Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall", entries);
    } catch (const std::exception& ex) {
        throw std::runtime_error(std::string("RegistryScanner failed: ") + ex.what());
    }
#endif

    return entries;
}
