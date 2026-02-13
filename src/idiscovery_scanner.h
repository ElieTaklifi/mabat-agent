#pragma once

#include <vector>

#include "software_entry.h"

class IDiscoveryScanner {
public:
    virtual ~IDiscoveryScanner() = default;
    virtual std::vector<RawSoftwareEntry> scan() = 0;
};
