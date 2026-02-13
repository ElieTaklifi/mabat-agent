#pragma once

#include <string>
#include <vector>

#include "software_entry.h"

class JsonExporter {
public:
    void exportToFile(const std::vector<NormalizedSoftwareEntry>& entries, const std::string& outputPath) const;
};
