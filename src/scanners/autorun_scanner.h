#pragma once

#include "idiscovery_scanner.h"

namespace AutorunMechanism {
    constexpr const char* RunKey        = "run_key";
    constexpr const char* RunOnceKey    = "run_once_key";
    constexpr const char* WinlogonValue = "winlogon_value";
}

class AutorunScanner final : public IDiscoveryScanner {
public:
    std::vector<RawSoftwareEntry> scan() override;
};