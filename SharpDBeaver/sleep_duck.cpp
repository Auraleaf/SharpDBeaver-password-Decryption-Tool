#include "head.h"

auto PrintProcessInfoFromHandle(HANDLE hProcess) -> void {
    DWORD pid = GetProcessId(hProcess);
    DWORD bufferSize = MAX_PATH;
    std::vector<wchar_t> pathBuffer(bufferSize);
    if (!QueryFullProcessImageNameW(hProcess, 0, pathBuffer.data(),
                                    &bufferSize)) {
        if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
            pathBuffer.resize(bufferSize);
            if (!QueryFullProcessImageNameW(hProcess, 0, pathBuffer.data(),
                                            &bufferSize)) {
                throw std::runtime_error(
                    "Failed to query process image name on second attempt. "
                    "Error code: " +
                    std::to_string(GetLastError()));
            }
        } else {
            throw std::runtime_error(
                "Failed to query process image name. Error code: " +
                std::to_string(GetLastError()));
        }
    }
    std::wstring processPath(pathBuffer.data(), bufferSize);
    printf("target process %d -> %ws \n", pid, pathBuffer.data());
}

auto SimpleCheckIn2020(HANDLE hProcess, uint64_t Address) -> bool {
    MEMORY_BASIC_INFORMATION mbi = {0};
    SIZE_T ReadNum = 0;
    bool detect = false;
    do {
        if (VirtualQueryEx(hProcess, (PVOID)Address, &mbi, sizeof(mbi)) ==
            false) {
            break;
        }
        if (mbi.Type == MEM_IMAGE) {
            break;
        }
        bool CheckExcuteFlag = mbi.AllocationProtect & PAGE_EXECUTE ||
                               mbi.AllocationProtect & PAGE_EXECUTE_READ ||
                               mbi.AllocationProtect & PAGE_EXECUTE_READWRITE ||
                               mbi.AllocationProtect & PAGE_EXECUTE_WRITECOPY;
        if (CheckExcuteFlag) {
            printf("rwx memory detect-> \n\t");
            PrintProcessInfoFromHandle(hProcess);
            detect = true;
            char PEStack[0x2];
            if (ReadProcessMemory(hProcess, mbi.BaseAddress, PEStack,
                                  sizeof(PEStack), &ReadNum)) {
                if (PEStack[0] == 'M' && PEStack[1] == 'Z') {
                    printf("rwx memory has pe module-> \n\t");
                    PrintProcessInfoFromHandle(hProcess);
                }
            }
        } else if (mbi.AllocationProtect & PAGE_READONLY ||
                   mbi.AllocationProtect & PAGE_READWRITE ||
                   mbi.AllocationProtect & PAGE_NOACCESS) {
            printf("no-excute-page detect at %p \n\t", Address);
            PrintProcessInfoFromHandle(hProcess);
            detect = true;
        }
    } while (false);
    return detect;
}
auto DoCFTrackX64(HANDLE hProcess,
                  std::vector<std::pair<uint64_t, uint64_t>>& stackArrays)
    -> void {
    for (size_t i = stackArrays.size() - 1; i > 0; i--) {
        auto ripAddr = stackArrays[i].first;
        auto retAddr = stackArrays[i].second;

        if (retAddr == 0) {
            continue;
        }
        auto rawAddress = ripAddr - 0x20;
        StackTracker stackTrack(hProcess, rawAddress, 0x28, false);
        if (stackTrack.TryFindValidDisasm(rawAddress, 0x28) == false) {
            printf("\nSleepMask Encryption Memory Detected: %p\n\t",
                   rawAddress);
            PrintProcessInfoFromHandle(hProcess);
            stackTrack.PrintAsm();
            continue;
        }
        auto [successTrack, nextJmpAddress] = stackTrack.CalcNextJmpAddress();

        if (successTrack == false) {
            // very perfer lazy method
            static const std::string WaitonAddressGate = "52 10 47 AE";
            if (Tools::FindPatternInMemory(
                    (uint64_t)stackTrack.SuccessReadedBuffer.data(),
                    stackTrack.SuccessReadedBuffer.size(),
                    WaitonAddressGate) != 0) {
                printf("skip waitonaddress, golang detect\n");
                continue;
            }
            if (stackTrack.feature != _features::kCallRip &&
                stackTrack.feature != _features::kCallReg &&
                stackTrack.feature != _features::kSyscall) {
                printf("\nNon-integrity Stack Detect: %p ripAddr: %p \n\t",
                       rawAddress, ripAddr);
                PrintProcessInfoFromHandle(hProcess);
                stackTrack.PrintAsm();
            }

            break;
        }
    }
    return;
}
auto DoX64StackDetect(HANDLE hProcess, HANDLE hThread) -> void {
    STACKFRAME64 StackFarmeEx = {};
    CONTEXT context = {0};
    context.ContextFlags = CONTEXT_ALL;
    std::vector<std::pair<uint64_t, uint64_t>> stackArrays;
    SymInitialize(hProcess, nullptr, TRUE);
    printf("scan tid: %d \n", GetThreadId(hThread));
    do {
        if (GetThreadContext(hThread, &context) == false) {
            break;
        }

        StackFarmeEx.AddrPC.Offset = context.Rip;
        StackFarmeEx.AddrPC.Mode = AddrModeFlat;
        StackFarmeEx.AddrStack.Offset = context.Rsp;
        StackFarmeEx.AddrStack.Mode = AddrModeFlat;
        StackFarmeEx.AddrFrame.Offset = context.Rsp;
        StackFarmeEx.AddrFrame.Mode = AddrModeFlat;
        bool detect = false;
        while (true) {
            if (StackWalk64(IMAGE_FILE_MACHINE_AMD64, hProcess, hThread,
                            &StackFarmeEx, &context, NULL,
                            SymFunctionTableAccess, SymGetModuleBase,
                            NULL) == false) {
                break;
            }
            if (StackFarmeEx.AddrFrame.Offset == 0) {
                break;
            }
            if (SimpleCheckIn2020(hProcess, StackFarmeEx.AddrPC.Offset)) {
                detect = true;
                // break;
            }

            stackArrays.push_back(
                {StackFarmeEx.AddrPC.Offset, StackFarmeEx.AddrReturn.Offset});
        }
        // if (detect) {
        //     break;
        // }
        DoCFTrackX64(hProcess, stackArrays);
    } while (false);
    SymCleanup(hProcess);
}

// 主扫描函数
auto DoLittleHackerMemeDetect(DWORD pidFilter = 0, bool scanAll = false)
    -> void {
    HANDLE hThreadSnap =
        CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);  // 所有线程
    THREADENTRY32 te32 = {};
    te32.dwSize = sizeof(THREADENTRY32);

    if (hThreadSnap == INVALID_HANDLE_VALUE ||
        !Thread32First(hThreadSnap, &te32))
        return;

    do {
        // 跳过当前线程
        if (te32.th32OwnerProcessID == GetCurrentProcessId() &&
            te32.th32ThreadID == GetCurrentThreadId())
            continue;

        // 判断是否过滤进程
        if (!scanAll && pidFilter != 0 && te32.th32OwnerProcessID != pidFilter)
            continue;

        if (!scanAll && pidFilter == 0 &&
            te32.th32OwnerProcessID != GetCurrentProcessId())
            continue;

        auto handleDeleter = [](HANDLE h) {
            if (h && h != INVALID_HANDLE_VALUE) CloseHandle(h);
        };

        std::unique_ptr<void, decltype(handleDeleter)> hThread(
            OpenThread(THREAD_ALL_ACCESS, FALSE, te32.th32ThreadID),
            handleDeleter);
        std::unique_ptr<void, decltype(handleDeleter)> hProcess(
            OpenProcess(PROCESS_ALL_ACCESS, FALSE, te32.th32OwnerProcessID),
            handleDeleter);

        if (!hProcess || hProcess.get() == INVALID_HANDLE_VALUE || !hThread ||
            hThread.get() == INVALID_HANDLE_VALUE)
            continue;

        if (!Tools::Is64BitPorcess(hProcess.get())) continue;
        DoX64StackDetect(hProcess.get(), hThread.get());

    } while (Thread32Next(hThreadSnap, &te32));

    CloseHandle(hThreadSnap);
}

int main(int argc, char* argv[]) {
    bool scanAll = true;
    DWORD targetPid = 0;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];

        if (arg == "-all") {
            scanAll = true;
        } else if (arg == "-pid" && i + 1 < argc) {
            scanAll = false;
            targetPid = static_cast<DWORD>(std::stoul(argv[++i]));
        } else {
            std::cerr << "[!] Unknown argument ,go scan all: " << arg << "\n";
            scanAll = true;
        }
    }

    DoLittleHackerMemeDetect(targetPid, scanAll);
    return 0;
}
