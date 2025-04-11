
#include <ntloader/loader.h>
#include <ntloader/dir_context.h>
#include <ntloader/module_list.h>
#include <stdio.h>

extern NTSTATUS LoadFileToMemory(PCWSTR FileName, PVOID* Buffer, PSIZE_T Size);

#pragma comment(lib, "ntdllx.lib")

bool MyLoaderHook(const NtLoaderModule* mod, NT_LOADER_STAGE stage,
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

  UNICODE_STRING bin_path;
  RtlInitUnicodeString(&bin_path,
                       L"C:\\Program Files "
                       L"(x86)\\Steam\\steamapps\\common\\"
                       L"Skyrim Special Edition\\SkyrimSE.exe.unpacked.exe");

  PVOID buffer;
  SIZE_T size;
  NTSTATUS status = LoadFileToMemory(bin_path.Buffer, &buffer, &size);
  if (!NT_SUCCESS(status)) {
    __debugbreak();
    return 1;
  }

  UNICODE_STRING path;
  RtlInitUnicodeString(&path,
                       L"C:\\Program Files "
                       L"(x86)\\Steam\\steamapps\\common\\"
                       L"Skyrim Special Edition");

  InstallDirContext(path, path);

  UNICODE_STRING module_name;
  RtlInitUnicodeString(&module_name, L"SkyrimSE.exe.unpacked.exe");

  UNICODE_STRING full_path_to_module;
  RtlInitUnicodeString(&full_path_to_module,
                       L"C:\\Program Files "
                       L"(x86)\\Steam\\steamapps\\common\\"
                       L"Skyrim Special Edition\\SkyrimSE.exe.unpacked.exe");

  NtLoaderConfiguration config{
      .user_context = nullptr,
      .loader_hook = &MyLoaderHook,
      .load_limit = 0x10000000,
      .behaviour_flags = 0,
      .module_name = &module_name,
      .disk_path = &full_path_to_module,
      .load_library = &::LoadLibraryA,
      .get_proc_address = &::GetProcAddress,
  };

  NtLoaderModule loader_module;
  NT_LOADER_ERR_CODE err = NtLoaderLoad((const uint8_t*)buffer,
                                        ::GetModuleHandleW(nullptr), config, loader_module);
  const char* const err_str = NtLoaderErrCodeToString(err);
  if (err_str) {
    ::OutputDebugStringA(err_str);
  }

  __debugbreak();

  NtLoaderInsertModuleToModuleList(&loader_module);
  HMODULE m = ::GetModuleHandleW(L"SkyrimSE.exe.unpacked.exe");
  m = m;
  char buf[256];
  // format the module ptr to a string
  sprintf(buf, "Module: %p\n", m);
  ::OutputDebugStringA(buf);

  void* LdrGetDllHandleByName =
      GetProcAddress(::GetModuleHandleW(L"ntdll.dll"), "LdrGetDllHandleByName");
  if (LdrGetDllHandleByName) {
    // call LdrGetDllHandleByName
    typedef NTSTATUS(WINAPI * LdrGetDllHandleByName_t)(UNICODE_STRING*,
                                                       UNICODE_STRING*, PVOID*);
    LdrGetDllHandleByName_t LdrGetDllHandleByNameFunc =
        (LdrGetDllHandleByName_t)LdrGetDllHandleByName;

    PVOID hMod = nullptr;
    NTSTATUS status = LdrGetDllHandleByNameFunc(
        loader_module.module_name, nullptr, &hMod);
    if (!NT_SUCCESS(status)) {
      __debugbreak();
    }
  }
  
  NTLoaderInvokeEntryPoint(loader_module);

  return 0;
}