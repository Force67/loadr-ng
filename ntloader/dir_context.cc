
#include <Windows.h>
#include "dir_context.h"
#include <string>

extern "C" {
__declspec(dllimport) __kernel_entry NTSYSCALLAPI NTSTATUS
    LdrSetDefaultDllDirectories(ULONG DirectoryFlags);

__declspec(dllimport) __kernel_entry NTSYSCALLAPI NTSTATUS
    LdrAddDllDirectory(UNICODE_STRING* Directory, DLL_DIRECTORY_COOKIE*);
}

void InstallDirContext(
    const UNICODE_STRING& cwd, const UNICODE_STRING& app_path) {
  constexpr ULONG kDirFlags =
      LOAD_LIBRARY_SEARCH_DEFAULT_DIRS | LOAD_LIBRARY_SEARCH_USER_DIRS;
  LdrSetDefaultDllDirectories(kDirFlags);

  DLL_DIRECTORY_COOKIE cookie;
  LdrAddDllDirectory(const_cast<UNICODE_STRING*>(&cwd), &cookie);
  LdrAddDllDirectory(const_cast<UNICODE_STRING*>(&app_path), &cookie);

  std::wstring pathBuf;
  pathBuf.resize(32768);
  GetEnvironmentVariableW(L"PATH", pathBuf.data(),
                          static_cast<DWORD>(pathBuf.length()));

  std::wstring newPath = app_path.Buffer;
  newPath += L";";
  newPath += cwd.Buffer;
  newPath += L";";
  newPath += pathBuf;

  SetEnvironmentVariableW(L"PATH", newPath.c_str());


    #if 0
  SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_DEFAULT_DIRS |
                           LOAD_LIBRARY_SEARCH_USER_DIRS);
  AddDllDirectory(app_path.c_str());
  AddDllDirectory(gamePath.c_str());
  SetCurrentDirectoryW(gamePath.c_str());

  std::wstring pathBuf;
  pathBuf.resize(32768);
  GetEnvironmentVariableW(L"PATH", pathBuf.data(),
                          static_cast<DWORD>(pathBuf.length()));

  // append bin & game directories
  std::wstring newPath =
      appPath.native() + L";" + gamePath.native() + L";" + pathBuf;
  SetEnvironmentVariableW(L"PATH", newPath.c_str());
  #endif
}
