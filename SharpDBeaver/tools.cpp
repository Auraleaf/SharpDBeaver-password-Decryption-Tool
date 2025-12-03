#include "tools.h"
// 71 A3 52 10 47 AE A0
#define INRANGE(x, a, b) (x >= a && x <= b)
#define getBits(x)                                                  \
    (INRANGE((x & (~0x20)), 'A', 'F') ? ((x & (~0x20)) - 'A' + 0xa) \
                                      : (INRANGE(x, '0', '9') ? x - '0' : 0))
#define getByte(x) (getBits(x[0]) << 4 | getBits(x[1]))
namespace Tools {
auto FindPatternInMemory(uint64_t StartAddress, size_t MemorySize,
                         std::string pattern) -> uint64_t {
    const char* pat = pattern.c_str();
    uint64_t firstMatch = 0;
    uint64_t rangeStart = StartAddress;
    uint64_t rangeEnd = rangeStart + MemorySize;
    for (uint64_t pCur = rangeStart; pCur < rangeEnd; pCur++) {
        if (!*pat) return firstMatch;

        if (*(PBYTE)pat == '\?' || *(BYTE*)pCur == getByte(pat)) {
            if (!firstMatch) firstMatch = pCur;

            if (!pat[2]) return firstMatch;

            if (*(PWORD)pat == '\?\?' || *(PBYTE)pat != '\?')
                pat += 3;

            else
                pat += 2;  // one ?
        } else {
            pat = pattern.c_str();
            firstMatch = 0;
        }
    }
    return 0;
}
auto Is64BitPorcess(HANDLE hProcess) -> bool {
    BOOL bIsWow64 = false;
    IsWow64Process(hProcess, &bIsWow64);
    return bIsWow64 == false;
}
auto EnableDebugPrivilege(bool bEnable) -> bool {
    bool fOK = FALSE;  // Assume function fails
    HANDLE hToken;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES,
                         &hToken)) {
        TOKEN_PRIVILEGES tp;
        tp.PrivilegeCount = 1;
        LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tp.Privileges[0].Luid);
        tp.Privileges[0].Attributes = bEnable ? SE_PRIVILEGE_ENABLED : 0;
        AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
        fOK = (GetLastError() == ERROR_SUCCESS);
        CloseHandle(hToken);
    }
    return fOK;
}
};  // namespace Tools
