
#pragma once

#include <Windows.h>
#include <winternl.h>

namespace loadr {
void InstallDirContext(const UNICODE_STRING& cwd,
                       const UNICODE_STRING& app_path);
}
