#pragma once

#include <vector>

#include "software_entry.h"

class Normalizer {
public:
    NormalizedSoftwareEntry normalize(const RawSoftwareEntry& raw) const;
    std::vector<NormalizedSoftwareEntry> normalizeAll(const std::vector<RawSoftwareEntry>& rawEntries) const;
};
