#include <ntloader/dir_context.h>
#include <ntloader/loader.h>
#include <ntloader/module_list.h>
#include <shellapi.h>
#include <shlwapi.h>
#include <stdio.h>

namespace loadr {
extern NTSTATUS LoadFileToMemory(PCWSTR FileName, PVOID* Buffer, PSIZE_T Size);
}

#pragma comment(lib, "ntdllx.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "shell32.lib")

bool MyLoaderHook(const loadr::NtLoaderModule* mod,
                  loadr::NT_LOADER_STAGE stage, void* user_context) {
  char buf[256];
  snprintf(buf, sizeof(buf), "Hook: %d\n", static_cast<int>(stage));
  ::OutputDebugStringA(buf);
  return true;
}

int APIENTRY WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
                     LPSTR lpCmdLine, int nCmdShow) {
  // Parse command line arguments properly
  int argc;
  LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
  if (argc < 2) {
    MessageBoxW(NULL,
                L"Usage: loader.exe \"<path_to_target_executable>\"\n"
                L"Note: Use quotes around paths containing spaces",
                L"Error", MB_ICONERROR);
    return 1;
  }

  // Get the full path to the target executable
  WCHAR targetPath[MAX_PATH] = {0};
  if (!GetFullPathNameW(argv[1], MAX_PATH, targetPath, NULL)) {
    MessageBoxW(NULL, L"Failed to resolve target path", L"Error", MB_ICONERROR);
    LocalFree(argv);
    return 1;
  }

  // Verify the file exists
  if (GetFileAttributesW(targetPath) == INVALID_FILE_ATTRIBUTES) {
    WCHAR errorMsg[512];
    swprintf_s(errorMsg, L"Target file not found:\n%s", targetPath);
    MessageBoxW(NULL, errorMsg, L"Error", MB_ICONERROR);
    LocalFree(argv);
    return 1;
  }

  // Get the directory part of the path
  WCHAR directoryPath[MAX_PATH] = {0};
  wcscpy_s(directoryPath, MAX_PATH, targetPath);
  if (!PathRemoveFileSpecW(directoryPath)) {
    MessageBoxW(NULL, L"Failed to extract directory from path", L"Error",
                MB_ICONERROR);
    LocalFree(argv);
    return 1;
  }

  // Get just the filename part
  WCHAR fileName[MAX_PATH] = {0};
  wcscpy_s(fileName, MAX_PATH, targetPath);
  PathStripPathW(fileName);

  // Debug output the paths we're using
  OutputDebugStringW(L"Target path: ");
  OutputDebugStringW(targetPath);
  OutputDebugStringW(L"\nDirectory: ");
  OutputDebugStringW(directoryPath);
  OutputDebugStringW(L"\nFilename: ");
  OutputDebugStringW(fileName);
  OutputDebugStringW(L"\n");

  // Initialize paths
  UNICODE_STRING bin_path;
  RtlInitUnicodeString(&bin_path, targetPath);

  UNICODE_STRING path;
  RtlInitUnicodeString(&path, directoryPath);

  UNICODE_STRING module_name;
  RtlInitUnicodeString(&module_name, fileName);

  // Load the target file into memory
  PVOID buffer;
  SIZE_T size;
  NTSTATUS status = loadr::LoadFileToMemory(bin_path.Buffer, &buffer, &size);
  if (!NT_SUCCESS(status)) {
    WCHAR errorMsg[512];
    swprintf_s(errorMsg,
               L"Failed to load file into memory:\n%s\nNTSTATUS: 0x%X",
               targetPath, status);
    MessageBoxW(NULL, errorMsg, L"Error", MB_ICONERROR);
    LocalFree(argv);
    return 1;
  }

  // Set up the directory context
  loadr::InstallDirContext(path, path);

  // Configure the loader
  const loadr::NtLoaderConfiguration config{
      .user_context = nullptr,
      .loader_hook = &MyLoaderHook,
      .load_limit = 0x10000000,
      .behaviour_flags = 0,
      .module_name = &module_name,
      .disk_path = &bin_path,
      .load_library = &::LoadLibraryA,
      .get_proc_address = &::GetProcAddress,
  };

  // Load the module
  loadr::NtLoaderModule loader_module;
  loadr::NT_LOADER_ERR_CODE err =
      loadr::NtLoaderLoad((const uint8_t*)buffer, ::GetModuleHandleW(nullptr),
                          config, loader_module);

  const char* const err_str = loadr::NtLoaderErrCodeToString(err);
  if (err_str) {
    ::OutputDebugStringA("Error: ");
    ::OutputDebugStringA(err_str);
    ::OutputDebugStringA("\n");
    char msg[512];
    sprintf_s(msg, "Loader error: %s", err_str);
    MessageBoxA(NULL, msg, "Error", MB_ICONERROR);
    LocalFree(argv);
    return 1;
  }

  // Insert module and overwrite initial module
  loadr::NtLoaderInsertModuleToModuleList(&loader_module);
  loadr::NtLoaderOverwriteInitialModule(&loader_module);

  // Debug output some info
  HMODULE m = ::GetModuleHandleW(fileName);
  char buf[256];
  sprintf_s(buf, "Module mapped at: %p\n", m);
  ::OutputDebugStringA(buf);

  // Get and output current directory for debugging
  wchar_t cwd[MAX_PATH];
  ::GetCurrentDirectoryW(MAX_PATH, cwd);
  ::OutputDebugStringW(L"Current directory: ");
  ::OutputDebugStringW(cwd);
  ::OutputDebugStringW(L"\n");

  // Invoke the entry point
  loadr::NTLoaderInvokeEntryPoint(loader_module);

  // Clean up
  LocalFree(argv);

  return 0;
}
