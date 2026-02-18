#include "persistence_scanner.h"

#include <filesystem>

#ifdef _WIN32
#include <windows.h>

namespace {

void scanRunKey(HKEY root, const char* path, std::vector<RawSoftwareEntry>& entries) {
    HKEY runKey = nullptr;
    if (RegOpenKeyExA(root, path, 0, KEY_READ, &runKey) != ERROR_SUCCESS) {
        return;
    }

    char valueName[256] = {};
    BYTE valueData[2048] = {};

    for (DWORD index = 0;; ++index) {
        DWORD valueNameSize = static_cast<DWORD>(sizeof(valueName));
        DWORD valueDataSize = static_cast<DWORD>(sizeof(valueData));
        DWORD valueType = 0;
        LONG status = RegEnumValueA(
            runKey,
            index,
            valueName,
            &valueNameSize,
            nullptr,
            &valueType,
            valueData,
            &valueDataSize);

        if (status != ERROR_SUCCESS) {
            break;
        }

        if (valueType != REG_SZ && valueType != REG_EXPAND_SZ) {
            continue;
        }

        RawSoftwareEntry entry;
        entry.name = valueName;
        entry.path = reinterpret_cast<char*>(valueData);
        entry.source = "persistence";
        entry.rawMetadata["mechanism"] = "run_key";
        entry.rawMetadata["registryPath"] = path;
        entries.push_back(std::move(entry));
    }

    RegCloseKey(runKey);
}

}  // namespace
#endif

std::vector<RawSoftwareEntry> PersistenceScanner::scan() {
    std::vector<RawSoftwareEntry> entries;

#ifdef _WIN32
    scanRunKey(HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", entries);
    scanRunKey(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", entries);

    const std::filesystem::path startupPath =
        "C:/ProgramData/Microsoft/Windows/Start Menu/Programs/Startup";

    if (std::filesystem::exists(startupPath)) {
        for (const auto& item : std::filesystem::directory_iterator(startupPath)) {
            if (!item.is_regular_file()) {
                continue;
            }

            RawSoftwareEntry entry;
            entry.name = item.path().stem().string();
            entry.path = item.path().string();
            entry.source = "persistence";
            entry.rawMetadata["mechanism"] = "startup_folder";
            entries.push_back(std::move(entry));
        }
    }
#endif

    return entries;
}
