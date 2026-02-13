#include "normalizer.h"

namespace {

std::string inferType(const RawSoftwareEntry& raw) {
    if (raw.source == "os_catalog") {
        return "UWP";
    }
    if (raw.source == "registry") {
        return "Win32";
    }
    if (raw.source == "persistence") {
        return "Service";
    }
    return "Portable";
}

std::string inferScope(const RawSoftwareEntry& raw) {
    const auto it = raw.rawMetadata.find("registryPath");
    if (it != raw.rawMetadata.end() && it->second.find("HKEY_CURRENT_USER") != std::string::npos) {
        return "per-user";
    }
    return "per-machine";
}

}  // namespace

NormalizedSoftwareEntry Normalizer::normalize(const RawSoftwareEntry& raw) const {
    NormalizedSoftwareEntry normalized;
    normalized.name = raw.name;
    normalized.type = inferType(raw);
    normalized.scope = inferScope(raw);
    normalized.source = raw.source;
    normalized.userSID = "N/A";
    normalized.metadata = raw.rawMetadata;
    normalized.metadata["path"] = raw.path;
    return normalized;
}

std::vector<NormalizedSoftwareEntry> Normalizer::normalizeAll(const std::vector<RawSoftwareEntry>& rawEntries) const {
    std::vector<NormalizedSoftwareEntry> output;
    output.reserve(rawEntries.size());

    for (const auto& entry : rawEntries) {
        output.push_back(normalize(entry));
    }

    return output;
}
