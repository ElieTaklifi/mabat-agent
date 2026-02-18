#pragma once

#include "idiscovery_scanner.h"

class OSCatalogScanner final : public IDiscoveryScanner {
public:
    std::vector<RawSoftwareEntry> scan() override;
};
