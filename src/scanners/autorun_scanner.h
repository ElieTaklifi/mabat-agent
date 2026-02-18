#pragma once

#include "idiscovery_scanner.h"

class AutoRunScanner final : public IDiscoveryScanner {
public:
    std::vector<RawSoftwareEntry> scan() override;
};