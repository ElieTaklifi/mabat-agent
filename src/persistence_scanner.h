#pragma once

#include "idiscovery_scanner.h"

class PersistenceScanner final : public IDiscoveryScanner {
public:
    std::vector<RawSoftwareEntry> scan() override;
};
