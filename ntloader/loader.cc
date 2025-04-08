
#include "loader.h"

namespace {
const char* const NtLoaderErrStringArray[] = {
    "OK",                                  // OK
    "Hook failed",                         // HOOK_FAILED
    "Path is broken",                      // PATH_BROKEN
    "Bad module pointer",                  // BAD_MODULE_PTR
    "Bad Target Module",                   // BAD_TARGET_MODULE
    "(Input) Buffer has bad magic",        // BUFFER_BAD_MAGIC
    "Load limit exceeded",                 // LOAD_LIMIT_EXCEEDED
    "Missing import",                      // MISSING_IMPORT
    "Missing thunk",                       // MISSING_THUNK
    "Failed to install exception handler"  // FAILED_TO_INSTALL_EH
};

static_assert(
    _countof(NtLoaderErrStringArray) ==
        static_cast<size_t>(NT_LOADER_ERR_CODE::NT_LOADER_ERR_CODE_COUNT),
    "NT_LOADER_ERR_CODE enum and NtLoaderErrStringArray are out of sync");

inline NT_LOADER_ERR_CODE InvokeHook(const NtLoaderModule& mod,
                                     const NtLoaderConfiguration& config,
                                     NT_LOADER_STAGE stage) {
  if (config.loader_hook && config.user_context &&
      !config.loader_hook(&mod, stage, config.user_context)) {
    return NT_LOADER_ERR_CODE::HOOK_FAILED;
  }
  return NT_LOADER_ERR_CODE::OK;
}

uint8_t* GetTargetBuffer(const NtLoaderModule& mod) {
  return (uint8_t*)mod.module_handle;
}

uint32_t Rva2Offset(const uint8_t* buffer, uint32_t rva) noexcept {
  const IMAGE_DOS_HEADER* dos =
      reinterpret_cast<const IMAGE_DOS_HEADER*>(buffer);
  const IMAGE_NT_HEADERS* nt =
      reinterpret_cast<const IMAGE_NT_HEADERS*>(buffer + dos->e_lfanew);

  auto* section = IMAGE_FIRST_SECTION(nt);
  for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
    if (rva >= section[i].VirtualAddress &&
        (rva < section[i].VirtualAddress + section[i].Misc.VirtualSize)) {
      return static_cast<uint32_t>(
          rva - (section[i].VirtualAddress - section[i].PointerToRawData));
    }
  }
  return 0;
}

auto mmin = [](uint32_t a, uint32_t b) { return a < b ? a : b; };

// Place all sections into the specified memory regions
NT_LOADER_ERR_CODE LoadSections(NtLoaderModule& mod,
                                const NtLoaderConfiguration& config,
                                const IMAGE_NT_HEADERS* nt_header) {
  auto* section = IMAGE_FIRST_SECTION(nt_header);
  for (int i = 0; i < nt_header->FileHeader.NumberOfSections; i++) {
    uint8_t* targetAddress = reinterpret_cast<uint8_t*>(
        GetTargetBuffer(mod) + section->VirtualAddress);
    const void* sourceAddress = mod.binary_buffer + section->PointerToRawData;

    if (targetAddress >=
        (reinterpret_cast<uint8_t*>(mod.module_handle) + config.load_limit)) {
      return NT_LOADER_ERR_CODE::LOAD_LIMIT_EXCEEDED;
    }

    if (section->SizeOfRawData > 0) {
      uint32_t sizeOfData =
          mmin(section->SizeOfRawData, section->Misc.VirtualSize);

      ::memcpy(targetAddress, sourceAddress, sizeOfData);
      InvokeHook(mod, config, NT_LOADER_STAGE::LOAD_SECTION);

      DWORD oldProtect;
      ::VirtualProtect(targetAddress, sizeOfData, PAGE_EXECUTE_READWRITE,
                       &oldProtect);
    }

    section++;
  }

  return NT_LOADER_ERR_CODE::OK;
}

NT_LOADER_ERR_CODE ResolveImports(NtLoaderModule& mod,
                                  const NtLoaderConfiguration& config,
                                  const IMAGE_NT_HEADERS* apNtHeader) {
  const auto* import_dir =
      &apNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
  const auto* descriptor = reinterpret_cast<const IMAGE_IMPORT_DESCRIPTOR*>(
      GetTargetBuffer(mod) + import_dir->VirtualAddress);

  // Iterate over all import descriptors
  while (descriptor->Name) {
    char* dll_name =
        reinterpret_cast<char*>(GetTargetBuffer(mod) + descriptor->Name);

    HMODULE hMod = config.load_library(dll_name);
    if (!hMod &&
        (config.behaviour_flags & BehaviourFlags::IGNORE_MISSING_IMPORTS)) {
      return NT_LOADER_ERR_CODE::MISSING_IMPORT;
    }

    // "don't load"
    if (*reinterpret_cast<uint32_t*>(hMod) == 0xFFFFFFFF) {
      descriptor++;
      continue;
    }

    uintptr_t* name_table_entry = reinterpret_cast<uintptr_t*>(
        GetTargetBuffer(mod) + descriptor->OriginalFirstThunk);
    uintptr_t* address_table_entry = reinterpret_cast<uintptr_t*>(
        GetTargetBuffer(mod) + descriptor->FirstThunk);
    if (!descriptor->OriginalFirstThunk) {
      name_table_entry = reinterpret_cast<uintptr_t*>(GetTargetBuffer(mod) +
                                                      descriptor->FirstThunk);
    }

    while (*name_table_entry) {
      FARPROC function;
      const char* functionName{nullptr};

      // is this an ordinal-only import?
      if (IMAGE_SNAP_BY_ORDINAL(*name_table_entry)) {
        function = config.get_proc_address(
            hMod, MAKEINTRESOURCEA(IMAGE_ORDINAL(*name_table_entry)));
      } else {
        IMAGE_IMPORT_BY_NAME* import = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(
            GetTargetBuffer(mod) + static_cast<uint32_t>(*name_table_entry));
        function = config.get_proc_address(hMod, import->Name);
        functionName = import->Name;
      }

      if (!function &&
          (config.behaviour_flags & BehaviourFlags::IGNORE_MISSING_IMPORTS)) {
        return NT_LOADER_ERR_CODE::MISSING_THUNK;
      }

      *address_table_entry = (uintptr_t)function;

      name_table_entry++;
      address_table_entry++;
    }

    descriptor++;
  }

  return NT_LOADER_ERR_CODE::OK;
}

typedef enum _FUNCTION_TABLE_TYPE {
  RF_SORTED,
  RF_UNSORTED,
  RF_CALLBACK
} FUNCTION_TABLE_TYPE;

typedef struct _DYNAMIC_FUNCTION_TABLE {
  LIST_ENTRY Links;
  RUNTIME_FUNCTION* FunctionTable;
  LARGE_INTEGER TimeStamp;

  ULONG_PTR MinimumAddress;
  ULONG_PTR MaximumAddress;
  ULONG_PTR BaseAddress;

  void* Callback;
  PVOID Context;
  PWSTR OutOfProcessCallbackDll;
  FUNCTION_TABLE_TYPE Type;
  ULONG EntryCount;
} DYNAMIC_FUNCTION_TABLE;


NT_LOADER_ERR_CODE LoadExceptionTable(NtLoaderModule& mod,
                                      const IMAGE_NT_HEADERS* apNtHeader) {
  const IMAGE_DATA_DIRECTORY* exceptionDirectory =
      &apNtHeader->OptionalHeader
           .DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];

  RUNTIME_FUNCTION* function_list = reinterpret_cast<RUNTIME_FUNCTION*>(
      GetTargetBuffer(mod) + exceptionDirectory->VirtualAddress);

  DWORD entryCount = exceptionDirectory->Size / sizeof(RUNTIME_FUNCTION);

  // has no use - inverted function tables get used instead from Ldr; we have no
  // influence on those
  if (!RtlAddFunctionTable(function_list, entryCount,
                           (DWORD64)GetModuleHandle(nullptr))) {
    return NT_LOADER_ERR_CODE::FAILED_TO_INSTALL_EH;
  }

  // replace the function table stored for debugger purposes (though we just
  // added it above)
  {
    PLIST_ENTRY(NTAPI * rtlGetFunctionTableListHead)(VOID);
    rtlGetFunctionTableListHead =
        (decltype(rtlGetFunctionTableListHead))GetProcAddress(
            GetModuleHandleW(L"ntdll.dll"), "RtlGetFunctionTableListHead");

    if (rtlGetFunctionTableListHead) {
      auto tableListHead = rtlGetFunctionTableListHead();
      auto tableListEntry = tableListHead->Flink;

      while (tableListEntry != tableListHead) {
        auto functionTable =
            CONTAINING_RECORD(tableListEntry, DYNAMIC_FUNCTION_TABLE, Links);

        if (functionTable->BaseAddress ==
            reinterpret_cast<ULONG_PTR>(mod.module_handle)) {
          if (functionTable->FunctionTable != function_list) {
            DWORD oldProtect;
            VirtualProtect(functionTable, sizeof(DYNAMIC_FUNCTION_TABLE),
                           PAGE_READWRITE, &oldProtect);

            functionTable->EntryCount = entryCount;
            functionTable->FunctionTable = function_list;

            VirtualProtect(functionTable, sizeof(DYNAMIC_FUNCTION_TABLE),
                           oldProtect, &oldProtect);
          }
        }

        tableListEntry = functionTable->Links.Flink;
      }
    }
  }
}

NT_LOADER_ERR_CODE LoadTLS(NtLoaderModule& mod,
                           const IMAGE_NT_HEADERS* apNtHeader,
                        const IMAGE_NT_HEADERS* apSourceNt) {
  if (apNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS]
          .Size) {
    IMAGE_TLS_DIRECTORY* sourceTls = reinterpret_cast<IMAGE_TLS_DIRECTORY*>(
        GetTargetBuffer(mod) +
        apNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS]
            .VirtualAddress);
    IMAGE_TLS_DIRECTORY* targetTls = reinterpret_cast<IMAGE_TLS_DIRECTORY*>(
        GetTargetBuffer(mod) +
        apSourceNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS]
            .VirtualAddress);

    *(DWORD*)(sourceTls->AddressOfIndex) = 0;

    LPVOID tlsBase = *(LPVOID*)__readgsqword(0x58);

    DWORD oldProtect;
    VirtualProtect(
        reinterpret_cast<LPVOID>(targetTls->StartAddressOfRawData),
        sourceTls->EndAddressOfRawData - sourceTls->StartAddressOfRawData,
        PAGE_READWRITE, &oldProtect);

    memcpy(
        tlsBase, reinterpret_cast<void*>(sourceTls->StartAddressOfRawData),
        sourceTls->EndAddressOfRawData - sourceTls->StartAddressOfRawData);
    memcpy(
        (void*)targetTls->StartAddressOfRawData,
        reinterpret_cast<void*>(sourceTls->StartAddressOfRawData),
        sourceTls->EndAddressOfRawData - sourceTls->StartAddressOfRawData);
  }

  return NT_LOADER_ERR_CODE::OK;
}

NT_LOADER_ERR_CODE CallTLSInitalizisers(NtLoaderModule& mod,
                                        HMODULE target_module_handle,
                                        const IMAGE_NT_HEADERS* target_nt) {
  const IMAGE_TLS_DIRECTORY* tls_dir =
      reinterpret_cast<const IMAGE_TLS_DIRECTORY*>(
          GetTargetBuffer(mod) +
          target_nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS]
              .VirtualAddress);

  PIMAGE_TLS_CALLBACK* tlsCallbacks =
      (PIMAGE_TLS_CALLBACK*)tls_dir->AddressOfCallBacks;
  if (tlsCallbacks != NULL) {
    // Call each callback function in the array
    for (int i = 0; tlsCallbacks[i] != NULL; i++) {
      tlsCallbacks[i](target_module_handle, DLL_PROCESS_ATTACH, NULL);
    }
  }

  return NT_LOADER_ERR_CODE::OK;
}
}  // namespace

const char* const NtLoaderErrCodeToString(NT_LOADER_ERR_CODE err_code) {
  return NtLoaderErrStringArray[static_cast<size_t>(err_code)];
}

NT_LOADER_ERR_CODE NtLoaderLoad(const uint8_t* target_binary,
                                HMODULE target_module_handle,
                                const NtLoaderConfiguration& config,
                                NtLoaderModule& mod) {
  if (!target_binary)
    return NT_LOADER_ERR_CODE::BAD_PARAM;

  if (!target_module_handle)
    return NT_LOADER_ERR_CODE::BAD_PARAM;

  if (!config.module_name) return NT_LOADER_ERR_CODE::BAD_PARAM;

  // memset(&mod, 0, sizeof(NtLoaderModule));
  // mod.disk_path = path;
  mod.binary_buffer = target_binary;
  mod.module_handle = target_module_handle;  // The image to be overridden

  // check if the user supplied buffer is trash
  const IMAGE_DOS_HEADER* binary_dos =
      reinterpret_cast<const IMAGE_DOS_HEADER*>(target_binary);
  if (binary_dos->e_magic != IMAGE_DOS_SIGNATURE)
    return NT_LOADER_ERR_CODE::BUFFER_BAD_MAGIC;
  const IMAGE_NT_HEADERS* binary_nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(
      target_binary + binary_dos->e_lfanew);

  mod.image_size = binary_nt->OptionalHeader.SizeOfImage;
  mod.module_name = config.module_name; // For now.

  // these point to launcher.exe's headers (which is the memory region we
  // overwrite)
  const IMAGE_DOS_HEADER* target_dos =
      reinterpret_cast<const IMAGE_DOS_HEADER*>(GetTargetBuffer(mod));
  IMAGE_NT_HEADERS* target_nt = reinterpret_cast<IMAGE_NT_HEADERS*>(
      GetTargetBuffer(mod) + target_dos->e_lfanew);

  // the entry point will be in the target memory region but within the offset
  // of the binary we will load next
  mod.entry_point_addr = reinterpret_cast<const void*>(
      GetTargetBuffer(mod) + binary_nt->OptionalHeader.AddressOfEntryPoint);

  DWORD original_checksum = target_nt->OptionalHeader.CheckSum;
  DWORD original_timestamp = target_nt->FileHeader.TimeDateStamp;
  IMAGE_DATA_DIRECTORY original_debug_dir =
      target_nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];

  // Can be used to decrypt the buffer (image) more before further processing is
  // done
  auto result = InvokeHook(mod, config, NT_LOADER_STAGE::BEFORE_SECTION_LOAD);
  if (result != NT_LOADER_ERR_CODE::OK)
    return result;

  result = LoadSections(mod, config, binary_nt);
  if (result != NT_LOADER_ERR_CODE::OK)
    return result;

  result = ResolveImports(mod, config, binary_nt);
  if (result != NT_LOADER_ERR_CODE::OK)
    return result;

#if defined(_M_AMD64)
  LoadExceptionTable(mod, target_nt);
  LoadTLS(mod, binary_nt, target_nt);
#endif

  // Make the target address space writable (where we will write the new
  // headers)
  DWORD oldProtect;
  VirtualProtect((LPVOID)target_nt, 0x1000, PAGE_EXECUTE_READWRITE,
                 &oldProtect);

  // re-target the import directory to the target's; ours isn't needed anymore.
  const_cast<IMAGE_NT_HEADERS*>(target_nt)
      ->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT] =
      binary_nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
  const size_t ntCompleteHeaderSize =
      sizeof(IMAGE_NT_HEADERS) +
      (binary_nt->FileHeader.NumberOfSections * (sizeof(IMAGE_SECTION_HEADER)));

  // overwrite our headers with the target headers
  memcpy((LPVOID)target_nt, binary_nt, ntCompleteHeaderSize);

  if (config.behaviour_flags & BehaviourFlags::MAINTAIN_DEBUG_INFO) {
    target_nt->OptionalHeader.CheckSum = original_checksum;
    target_nt->FileHeader.TimeDateStamp = original_timestamp;
    target_nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG] =
        original_debug_dir;
  }

  // Reprotect the NT headers
  VirtualProtect((LPVOID)target_nt, 0x1000, oldProtect, &oldProtect);

  result = CallTLSInitalizisers(mod, target_module_handle, target_nt);
  if (result != NT_LOADER_ERR_CODE::OK)
    return result;

  return NT_LOADER_ERR_CODE::OK;
}

void NTLoaderInvokeEntryPoint(const NtLoaderModule& mod) {
  if (mod.entry_point_addr) {
    void (*entry_point)() = (void (*)())mod.entry_point_addr;
    entry_point();
  }
}
