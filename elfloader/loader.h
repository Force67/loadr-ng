#pragma once

#include <stdint.h>
#include <stddef.h>

namespace loadr {

enum class ELF_LOADER_ERR_CODE {
  OK,
  HOOK_FAILED,
  BAD_PARAM,

  BAD_MODULE_PTR,
  BAD_TARGET_MODULE,

  BUFFER_BAD_MAGIC,

  LOAD_LIMIT_EXCEEDED,

  MISSING_IMPORT,
  MISSING_THUNK,

  UNSUPPORTED_ARCH,
  UNSUPPORTED_RELOC,

  ELF_LOADER_ERR_CODE_COUNT,
};
const char* const ElfLoaderErrCodeToString(ELF_LOADER_ERR_CODE);

enum class ELF_LOADER_STAGE {
  BEFORE_SEGMENT_LOAD,
  LOAD_SEGMENT,
  LOAD_IMPORTS,
  LOAD_RELOCATIONS,
  LOAD_INIT,
  LOAD_DONE,
};

struct ElfLoaderModule {
  const uint8_t* binary_buffer{nullptr};
  void* module_handle{nullptr};
  const void* entry_point_addr{nullptr};

  const char* disk_path{nullptr};
  const char* module_name{nullptr};

  uint64_t image_size{0};
};

enum BehaviourFlags {
  IGNORE_MISSING_IMPORTS = 1 << 0,
  IGNORE_MISSING_THUNKS = 1 << 1,
};

struct ElfLoaderConfiguration {
  void* user_context{nullptr};
  bool (*loader_hook)(const ElfLoaderModule*, ELF_LOADER_STAGE, void*){nullptr};

  const uint64_t load_limit{(uint64_t)-1};
  const uint32_t behaviour_flags{0};

  const char* module_name{nullptr};
  const char* disk_path{nullptr};

  void* (*load_library)(const char*){nullptr};
  void* (*get_proc_address)(void*, const char*){nullptr};
};

ELF_LOADER_ERR_CODE ElfLoaderLoad(const uint8_t* target_binary,
                                  void* target_base,
                                  const ElfLoaderConfiguration& config,
                                  ElfLoaderModule&);

void ElfLoaderInvokeEntryPoint(const ElfLoaderModule& mod);
void ElfLoaderRunFinalizers(const ElfLoaderModule& mod);

void* ElfLoaderGetProcAddress(const ElfLoaderModule& mod,
                              const char* proc_name);
}  // namespace loadr
