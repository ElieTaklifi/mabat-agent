#pragma once

#include "idiscovery_scanner.h"

class FilesystemScanner final : public IDiscoveryScanner {
public:
    std::vector<RawSoftwareEntry> scan() override;
};
