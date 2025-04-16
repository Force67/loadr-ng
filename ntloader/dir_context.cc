#include "dir_context.h"

#include <Windows.h>

extern "C" {
NTSTATUS LdrSetDefaultDllDirectories(ULONG DirectoryFlags);
NTSTATUS LdrAddDllDirectory(UNICODE_STRING* Directory, DLL_DIRECTORY_COOKIE*);
NTSTATUS RtlSetCurrentDirectory_U(PUNICODE_STRING name);
PVOID RtlAllocateHeap(PVOID HeapHandle, ULONG Flags, SIZE_T Size);
BOOLEAN RtlFreeHeap(PVOID HeapHandle, ULONG Flags, PVOID BaseAddress);
}

namespace loadr {

// Helper function to calculate the length of a null-terminated wide string
size_t CalculateWideStringLength(const wchar_t* str) {
  size_t len = 0;
  while (str[len] != L'\0') {
    len++;
  }
  return len;
}

void InstallDirContext(const UNICODE_STRING& cwd,
                       const UNICODE_STRING& app_path) {
  constexpr ULONG kDirFlags =
      LOAD_LIBRARY_SEARCH_DEFAULT_DIRS | LOAD_LIBRARY_SEARCH_USER_DIRS;
  LdrSetDefaultDllDirectories(kDirFlags);

  DLL_DIRECTORY_COOKIE cookie;
  LdrAddDllDirectory(const_cast<UNICODE_STRING*>(&cwd), &cookie);
  LdrAddDllDirectory(const_cast<UNICODE_STRING*>(&app_path), &cookie);
  RtlSetCurrentDirectory_U(const_cast<UNICODE_STRING*>(&cwd));

  // Dynamically allocate a buffer for the PATH environment variable
  constexpr DWORD kPathBufSize = 32768;
  wchar_t* pathBuf = reinterpret_cast<wchar_t*>(
      RtlAllocateHeap(GetProcessHeap(), 0, kPathBufSize * sizeof(wchar_t)));
  if (!pathBuf) {
    return;  // Handle memory allocation failure
  }

  DWORD pathLen = GetEnvironmentVariableW(L"PATH", pathBuf, kPathBufSize);
  if (pathLen == 0) {
    RtlFreeHeap(GetProcessHeap(), 0, pathBuf);
    return;  // Handle error if GetEnvironmentVariableW fails
  }

  // Calculate the lengths of the strings
  size_t appPathLen = app_path.Length / sizeof(wchar_t);
  size_t cwdLen = cwd.Length / sizeof(wchar_t);
  size_t pathBufLen = CalculateWideStringLength(pathBuf);

  // Calculate the length of the new PATH string
  size_t newPathLen =
      appPathLen + cwdLen + pathBufLen + 2;  // +2 for the semicolons
  wchar_t* newPath = reinterpret_cast<wchar_t*>(
      RtlAllocateHeap(GetProcessHeap(), 0, (newPathLen + 1) * sizeof(wchar_t)));
  if (!newPath) {
    RtlFreeHeap(GetProcessHeap(), 0, pathBuf);
    return;  // Handle memory allocation failure
  }

  // Construct the new PATH string manually
  size_t offset = 0;

  // Copy app_path.Buffer
  for (size_t i = 0; i < appPathLen; i++) {
    newPath[offset++] = app_path.Buffer[i];
  }

  // Add semicolon
  newPath[offset++] = L';';

  // Copy cwd.Buffer
  for (size_t i = 0; i < cwdLen; i++) {
    newPath[offset++] = cwd.Buffer[i];
  }

  // Add semicolon
  newPath[offset++] = L';';

  // Copy pathBuf
  for (size_t i = 0; i < pathBufLen; i++) {
    newPath[offset++] = pathBuf[i];
  }

  // Null-terminate the new PATH
  newPath[offset] = L'\0';

  // Set the new PATH environment variable
  SetEnvironmentVariableW(L"PATH", newPath);

  // Clean up
  RtlFreeHeap(GetProcessHeap(), 0, pathBuf);
  RtlFreeHeap(GetProcessHeap(), 0, newPath);
}
}  // namespace loadr
