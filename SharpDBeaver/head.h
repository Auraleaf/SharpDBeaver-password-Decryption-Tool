#pragma once
#include <iostream>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <windows.h>
#include <psapi.h>
#include <shlwapi.h>
#include <string.h>
#include <wchar.h>
#include <dbghelp.h>
#include <vector>
#include <string>
#pragma comment(lib, "dbghelp.lib")
#include "tlhelp32.h"

#include "include/capstone/capstone.h"
#include "include/capstone/x86.h"
#include <optional>

#pragma comment(lib, "capstone64.lib")

#include "tools.h"
#include "stack_tracker.h"
