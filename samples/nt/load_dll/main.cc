
#include <ntloader/loader.h>
#include <ntloader/dir_context.h>
#include <ntloader/module_list.h>
#include <stdio.h>

namespace loadr {
extern NTSTATUS LoadFileToMemory(PCWSTR FileName, PVOID* Buffer,
                                        PSIZE_T Size);
}

#pragma comment(lib, "ntdll.lib")

bool MyLoaderHook(const loadr::NtLoaderModule* mod, loadr::NT_LOADER_STAGE stage,
                  void* user_context) {
  char buf[256];
  snprintf(buf, sizeof(buf), "Hook: %d\n", static_cast<int>(stage));
  ::OutputDebugStringA(buf);
  return true;
}

// winmain
int APIENTRY WinMain(HINSTANCE hInstance,
            HINSTANCE hPrevInstance,
            LPSTR lpCmdLine,
            int nCmdShow) {
  wchar_t dllPathBuf[MAX_PATH];
  const size_t bufferSizeInWchars = MAX_PATH;

  DWORD pathLen = ::GetModuleFileNameW(nullptr, dllPathBuf, bufferSizeInWchars);
  wchar_t* last_backslash = wcsrchr(dllPathBuf, L'\\');
  if (!last_backslash) {
    wprintf(L"Error: No backslash found in module path: %s\n", dllPathBuf);
    __debugbreak();
    return 1;
  }
  wchar_t* fileNameStart = last_backslash + 1;
  const wchar_t* dllName = L"SampleDll_64.dll";
  size_t remaining_chars = bufferSizeInWchars - (fileNameStart - dllPathBuf);
  errno_t serr = wcscpy_s(fileNameStart, remaining_chars, dllName);

  if (serr != 0) {
    // Handle error: wcscpy_s failed (e.g., insufficient space calculated)
    wprintf(L"Error: wcscpy_s failed to append DLL name. Error code: %d\n",
            serr);
    __debugbreak();
    return 1;
  }


  UNICODE_STRING bin_path;
  RtlInitUnicodeString(&bin_path, dllPathBuf);

  PVOID buffer;
  SIZE_T size;
  NTSTATUS status = loadr::LoadFileToMemory(bin_path.Buffer, &buffer, &size);
  if (!NT_SUCCESS(status)) {
    __debugbreak();
    return 1;
  }

  UNICODE_STRING module_name;
  RtlInitUnicodeString(&module_name, L"SampleDll_64.dll");

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
  
  // Allocate memory for the module
  void *dll_base = ::VirtualAllocEx(::GetCurrentProcess(), nullptr, size * 10, // some BS
                                        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
  if (!dll_base) {
    ::OutputDebugStringA("VirtualAllocEx failed\n");
    return 1;
  }

  wchar_t buf[256];
  wprintf_s(buf, "Module will be loaded at %p", dll_base);
  ::OutputDebugStringW(buf);

  loadr::NtLoaderModule loader_module;
  const auto err = loadr::NtLoaderLoadDynBuffer((const uint8_t*)buffer,
                                        static_cast<HMODULE>(dll_base), config, loader_module);
  const char* const err_str = loadr::NtLoaderErrCodeToString(err);
  if (err_str) {
    ::OutputDebugStringA("Error: ");
    ::OutputDebugStringA(err_str);
    ::OutputDebugStringA("\n");
  }

  loadr::NtLoaderInsertModuleToModuleList(&loader_module);

  HMODULE found_module = ::GetModuleHandleW(L"SampleDll_64.dll");
  if (!found_module) {
    ::OutputDebugStringA("GetModuleHandle failed\n");
    return 1;
  }

  if (found_module != loader_module.module_handle) {
    ::OutputDebugStringA("Module handle mismatch\n");
    return 1;
  }

   wchar_t widebuf[256];
  ::OutputDebugStringW(L"GetModuleHandleW: ");
  wprintf_s(widebuf, L"module ptr %p", (void*)found_module);
  ::OutputDebugStringW(widebuf);
  ::OutputDebugStringW(L"\n");

  ::GetModuleFileNameW(found_module, widebuf, sizeof(widebuf));
  ::OutputDebugStringW(L"GetModuleFileNameW: ");
  ::OutputDebugStringW(widebuf);
  ::OutputDebugStringW(L"\n");

  loadr::NTLoaderInvokeDllMain(loader_module, DLL_PROCESS_ATTACH);

  FARPROC set_thread_local_var =
      ::GetProcAddress(found_module, "SetThreadLocalVar");
  FARPROC get_thread_local_var =
      ::GetProcAddress(found_module, "GetThreadLocalVar");

  FARPROC set_thread_local_var2 =
      NtLoaderGetProcAddress(loader_module, "SetThreadLocalVar");
  char buf2[256];
  snprintf(buf2, sizeof(buf2), "SetThreadLocalVar: %p\n",
           set_thread_local_var2);
  ::OutputDebugStringA(buf2);

  if (set_thread_local_var && get_thread_local_var) {
    void (*set_thread_local_var_f)(int) =
        reinterpret_cast<void (*)(int)>(set_thread_local_var);
    int (*get_thread_local_var_f)() =
        reinterpret_cast<int(*)()>(get_thread_local_var);
    // Set a thread-local variable
    int value = 42;
    set_thread_local_var_f(value);
    // Get the thread-local variable
    int thread_local_var = get_thread_local_var_f();
    if (thread_local_var) {
      wchar_t buf[256];
      swprintf_s(buf, L"Thread-local variable: %d\n", thread_local_var);
      ::OutputDebugStringW(buf);
    } else {
      ::OutputDebugStringW(L"Failed to get thread-local variable\n");
    }
  } else {
    ::OutputDebugStringW(L"Failed to get function addresses\n");
  }

  loadr::NTLoaderInvokeDllMain(loader_module, DLL_PROCESS_DETACH);
  loadr::NtLoaderRemoveModuleFromModuleList(&loader_module);
  // Free the allocated memory
  if (dll_base) {
    BOOL result = ::VirtualFreeEx(::GetCurrentProcess(), dll_base, 0, MEM_RELEASE);
    if (!result) {
      ::OutputDebugStringA("VirtualFreeEx failed\n");
      return 1;
    }
  }

  return 0;
}