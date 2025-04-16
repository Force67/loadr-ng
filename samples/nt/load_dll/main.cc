
#include <ntloader/loader.h>
#include <ntloader/dir_context.h>
#include <ntloader/module_list.h>
#include <stdio.h>

namespace loadr {
extern NTSTATUS LoadFileToMemory(PCWSTR FileName, PVOID* Buffer,
                                        PSIZE_T Size);
}

#pragma comment(lib, "ntdllx.lib")

bool MyLoaderHook(const loadr::NtLoaderModule* mod, loadr::NT_LOADER_STAGE stage,
                  void* user_context) {
  char buf[256];
  snprintf(buf, sizeof(buf), "Hook: %d\n", static_cast<int>(stage));
  ::OutputDebugStringA(buf);
  return true;
}


// winmain
int WinMain(HINSTANCE hInstance,
            HINSTANCE hPrevInstance,
            LPSTR lpCmdLine,
            int nCmdShow) {

  constexpr wchar_t kDllPath[] = LR"(C:\Users\vince\Documents\GitHub\loadr-ng\samples\nt\sample_dll\bin\Debug\SampleDll_64.dll)";
  constexpr wchar_t kModulePath[] = LR"(LR"("C:\Users\vince\Documents\GitHub\loadr-ng\samples\nt\sample_dll\bin\Debug)";

  UNICODE_STRING bin_path;
  RtlInitUnicodeString(&bin_path, kDllPath);

  PVOID buffer;
  SIZE_T size;
  NTSTATUS status = loadr::LoadFileToMemory(bin_path.Buffer, &buffer, &size);
  if (!NT_SUCCESS(status)) {
    __debugbreak();
    return 1;
  }

  UNICODE_STRING path;
  RtlInitUnicodeString(&path, kModulePath);

  //loadr::InstallDirContext(path, path);

  UNICODE_STRING module_name;
  RtlInitUnicodeString(&module_name, L"SampleDll_64.dll");

  UNICODE_STRING full_path_to_module;
  RtlInitUnicodeString(&full_path_to_module, kDllPath);

  const loadr::NtLoaderConfiguration config{
      .user_context = nullptr,
      .loader_hook = &MyLoaderHook,
      .load_limit = 0x10000000,
      .behaviour_flags = 0,
      .module_name = &module_name,
      .disk_path = &full_path_to_module,
      .load_library = &::LoadLibraryA,
      .get_proc_address = &::GetProcAddress,
  };

  void *dll_base = ::VirtualAllocEx(::GetCurrentProcess(), nullptr, size * 10, // some BS
                                        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
  if (!dll_base) {
    ::OutputDebugStringA("VirtualAllocEx failed\n");
    return 1;
  }

  wchar_t buf[512];
  wprintf_s(buf, "Module will be loaded at %p", dll_base);
  ::OutputDebugStringW(buf);

  loadr::NtLoaderModule loader_module;
  loadr::NT_LOADER_ERR_CODE err = loadr::NtLoaderLoad((const uint8_t*)buffer,
                                        static_cast<HMODULE>(dll_base), config, loader_module);
  const char* const err_str = loadr::NtLoaderErrCodeToString(err);
  if (err_str) {
    ::OutputDebugStringA("Error: ");
    ::OutputDebugStringA(err_str);
    ::OutputDebugStringA("\n");
  }

  loadr::NtLoaderInsertModuleToModuleList(&loader_module);
  HMODULE m = ::GetModuleHandleW(L"SampleDll_64.dll");


  loadr::NtLoaderOverwriteInitialModule(&loader_module);

   wchar_t widebuf[256];
  ::GetModuleFileNameW(nullptr, widebuf, sizeof(widebuf));
  ::OutputDebugStringW(widebuf);
  ::OutputDebugStringW(L"\n");

  wchar_t cwd[256];
  ::GetCurrentDirectoryW(sizeof(cwd) / sizeof(wchar_t), cwd);
  ::OutputDebugStringW(cwd);
  ::OutputDebugStringW(L"\n");  

  loadr::NTLoaderInvokeEntryPoint(loader_module);

  return 0;
}