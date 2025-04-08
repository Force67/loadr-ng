#pragma once

#include <Windows.h>
#include <winternl.h>
#include <cstdint>

enum class NT_LOADER_ERR_CODE {
  OK,
  HOOK_FAILED,
  BAD_PARAM,

  BAD_MODULE_PTR,
  BAD_TARGET_MODULE,

  BUFFER_BAD_MAGIC,

  LOAD_LIMIT_EXCEEDED,

  MISSING_IMPORT,
  MISSING_THUNK,

  FAILED_TO_INSTALL_EH,

  NT_LOADER_ERR_CODE_COUNT,
};
const char* const NtLoaderErrCodeToString(NT_LOADER_ERR_CODE);

enum class NT_LOADER_STAGE {
  BEFORE_SECTION_LOAD,
  LOAD_SECTION,  // During section load
  LOAD_IMPORTS,
  LOAD_TLS,
  LOAD_RELOCATIONS,
  LOAD_ENTRY_POINT,
  LOAD_DONE,
};

struct NtLoaderModule {
  // Buffer of the original binary that was to be loaded in this process
  const uint8_t* binary_buffer = nullptr;
  // Handle to the module that was loaded
  HMODULE module_handle = nullptr;
  // Entry point address of the newely loaded code
  const void* entry_point_addr = nullptr;

  UNICODE_STRING* disk_path = nullptr;

  // ModuleName is always valid
  UNICODE_STRING* module_name = nullptr;

  ULONG image_size;

 private:
  void* user_context{nullptr};
  bool (*loader_hook)(NT_LOADER_STAGE){nullptr};
};

enum BehaviourFlags {
  IGNORE_MISSING_IMPORTS = 1 << 0,
  IGNORE_MISSING_THUNKS = 1 << 1,

  // This flag will cause the host executable to retain the PDB information in
  // memory instead of being overwritten by the guest
  MAINTAIN_DEBUG_INFO = 1 << 2,
};

struct NtLoaderConfiguration {
  // Hooks can be used to execute custom code at various stages of the loading
  void* user_context{nullptr};
  bool (*loader_hook)(const NtLoaderModule*, NT_LOADER_STAGE, void*){nullptr};

  // How much of the binary to load
  const uint32_t load_limit{UINT_MAX};
  const uint32_t behaviour_flags{0};
  
  // Must be set to the current name of the module we are trying to load
  // So the load can insert the module into the modulelist.
  UNICODE_STRING* module_name{nullptr};

  // Function pointers you have to fill in
  HMODULE(__stdcall* load_library)(const char*) { nullptr };
  FARPROC(__stdcall* get_proc_address)(HMODULE, const char*) { nullptr };
};

NT_LOADER_ERR_CODE NtLoaderLoad(
    const uint8_t* target_binary /*buffer of the binary (pe img) to laod*/,
    HMODULE target_module_handle,
    const NtLoaderConfiguration& config,
    NtLoaderModule&);

void NTLoaderInvokeEntryPoint(const NtLoaderModule& mod);