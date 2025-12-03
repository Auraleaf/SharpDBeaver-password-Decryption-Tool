#pragma once
#include "head.h"
namespace Tools {
auto EnableDebugPrivilege(bool bEnable) -> bool;
auto Is64BitPorcess(HANDLE hProcess) -> bool;
auto FindPatternInMemory(uint64_t StartAddress, size_t MemorySize,
                         std::string pattern) -> uint64_t;
};  // namespace Tools
