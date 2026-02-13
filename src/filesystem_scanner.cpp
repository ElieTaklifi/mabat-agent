#include "filesystem_scanner.h"

#include <filesystem>

std::vector<RawSoftwareEntry> FilesystemScanner::scan() {
    std::vector<RawSoftwareEntry> entries;

    try {
#ifdef _WIN32
        const std::vector<std::filesystem::path> roots = {
            std::filesystem::path{"C:/Program Files"},
            std::filesystem::path{"C:/Program Files (x86)"}};

        for (const auto& root : roots) {
            if (!std::filesystem::exists(root)) {
                continue;
            }

            for (const auto& item : std::filesystem::recursive_directory_iterator(root, std::filesystem::directory_options::skip_permission_denied)) {
                if (!item.is_regular_file()) {
                    continue;
                }

                if (item.path().extension() == ".exe") {
                    RawSoftwareEntry entry;
                    entry.name = item.path().stem().string();
                    entry.path = item.path().string();
                    entry.source = "filesystem";
                    entry.rawMetadata["extension"] = ".exe";
                    entries.push_back(std::move(entry));
                }
            }
        }
#endif
    } catch (const std::exception&) {
        // Non-fatal for scan pass; return partial discovery results.
    }

    return entries;
}
