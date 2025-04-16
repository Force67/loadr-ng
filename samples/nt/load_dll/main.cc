
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

FARPROC GetProcAddressRaw1337(HMODULE module_base, const char* proc_name) {
  // Validate inputs
  if (!module_base || !proc_name) {
    __debugbreak();
    ::OutputDebugStringA("Invalid parameters\n");
    return nullptr;
  }

  // Get DOS header and verify signature
  const IMAGE_DOS_HEADER* dos_header =
      reinterpret_cast<const IMAGE_DOS_HEADER*>(module_base);
  if (dos_header->e_magic != IMAGE_DOS_SIGNATURE) {
    __debugbreak();
    ::OutputDebugStringA("Invalid DOS signature\n");
    return nullptr;
  }

  // Get NT headers
  const IMAGE_NT_HEADERS* nt_headers =
      reinterpret_cast<const IMAGE_NT_HEADERS*>(
          reinterpret_cast<const uint8_t*>(module_base) + dos_header->e_lfanew);
  if (nt_headers->Signature != IMAGE_NT_SIGNATURE) {
    __debugbreak();
    ::OutputDebugStringA("Invalid NT signature\n");
    return nullptr;
  }

  // Get export directory
  const IMAGE_DATA_DIRECTORY* export_dir =
      &nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
  if (export_dir->Size == 0 || export_dir->VirtualAddress == 0) {
    __debugbreak();
    ::OutputDebugStringA("No export directory\n");
    return nullptr;  // Module has no exports
  }

  const IMAGE_EXPORT_DIRECTORY* export_directory =
      reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(
          reinterpret_cast<const uint8_t*>(module_base) +
          export_dir->VirtualAddress);

  // Get the various export tables
  const uint32_t* functions = reinterpret_cast<const uint32_t*>(
      reinterpret_cast<const uint8_t*>(module_base) +
      export_directory->AddressOfFunctions);
  const uint32_t* names = reinterpret_cast<const uint32_t*>(
      reinterpret_cast<const uint8_t*>(module_base) +
      export_directory->AddressOfNames);
  const uint16_t* ordinals = reinterpret_cast<const uint16_t*>(
      reinterpret_cast<const uint8_t*>(module_base) +
      export_directory->AddressOfNameOrdinals);

  // Determine if we're searching by name or ordinal
  if (reinterpret_cast<uintptr_t>(proc_name) <= 0xFFFF) {
    // Search by ordinal (16-bit value)
    uint16_t ordinal = LOWORD(proc_name);
    if (ordinal < export_directory->Base ||
        ordinal >=
            export_directory->Base + export_directory->NumberOfFunctions) {
      ::OutputDebugStringA("Invalid ordinal\n");
      __debugbreak();
      return nullptr;
    }

    uint32_t rva = functions[ordinal - export_directory->Base];
    if (rva == 0) {
      __debugbreak();
      ::OutputDebugStringA("Function RVA is zero\n");
      return nullptr;
    }

    // Check for forwarded exports
    if (rva >= export_dir->VirtualAddress &&
        rva < export_dir->VirtualAddress + export_dir->Size) {
      // Forwarded exports aren't supported in this raw implementation
      __debugbreak();
      ::OutputDebugStringA("Forwarded exports not supported\n");
      return nullptr;
    }

    return reinterpret_cast<FARPROC>(reinterpret_cast<uint8_t*>(module_base) +
                                     rva);
  } else {
    // Search by name (standard case)
    for (DWORD i = 0; i < export_directory->NumberOfNames; i++) {
      const char* name = reinterpret_cast<const char*>(
          reinterpret_cast<const uint8_t*>(module_base) + names[i]);

      if (strcmp(proc_name, name) == 0) {
        uint32_t rva = functions[ordinals[i]];
        if (rva == 0) {
          __debugbreak();
          ::OutputDebugStringA("Function RVA is zero\n");
          return nullptr;
        }

        // Check for forwarded exports
        if (rva >= export_dir->VirtualAddress &&
            rva < export_dir->VirtualAddress + export_dir->Size) {
          // Forwarded exports aren't supported in this raw implementation
          __debugbreak();
          ::OutputDebugStringA("Forwarded exports not supported\n");
          return nullptr;
        }

        return reinterpret_cast<FARPROC>(
            reinterpret_cast<uint8_t*>(module_base) + rva);
      }
    }
  }
  __debugbreak();
  ::OutputDebugStringA("Function not found\n");
  return nullptr;  // Function not found
}


// winmain
int WinMain(HINSTANCE hInstance,
            HINSTANCE hPrevInstance,
            LPSTR lpCmdLine,
            int nCmdShow) {

  constexpr wchar_t kDllPath[] = LR"(C:\Users\vince\Projects\ntloader-ng\samples\nt\sample_dll\bin\Debug\SampleDll_64.dll)";
  constexpr wchar_t kModulePath[] = LR"(C:\Users\vince\Projects\ntloader-ng\samples\nt\sample_dll\bin\Debug)";

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
  
  // Allocate memory for the module
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
  const auto err = loadr::NtLoaderLoad((const uint8_t*)buffer,
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
      GetProcAddressRaw1337(found_module, "SetThreadLocalVar");
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

  return 0;
}