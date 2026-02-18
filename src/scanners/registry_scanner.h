#pragma once

#include "idiscovery_scanner.h"

class RegistryScanner final : public IDiscoveryScanner {
public:
    std::vector<RawSoftwareEntry> scan() override;
};
