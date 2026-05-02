#include "loader.h"

#include <elf.h>
#include <sys/mman.h>

namespace loadr {

namespace {

const char* const ElfLoaderErrStringArray[] = {
    "OK",                          // OK
    "Hook failed",                 // HOOK_FAILED
    "Bad parameter",               // BAD_PARAM
    "Bad module pointer",          // BAD_MODULE_PTR
    "Bad target module",           // BAD_TARGET_MODULE
    "(Input) Buffer has bad ELF magic",  // BUFFER_BAD_MAGIC
    "Load limit exceeded",         // LOAD_LIMIT_EXCEEDED
    "Missing import",              // MISSING_IMPORT
    "Missing thunk",               // MISSING_THUNK
    "Unsupported architecture",    // UNSUPPORTED_ARCH
    "Unsupported relocation",      // UNSUPPORTED_RELOC
};

static_assert(
    sizeof(ElfLoaderErrStringArray) / sizeof(ElfLoaderErrStringArray[0]) ==
        static_cast<size_t>(ELF_LOADER_ERR_CODE::ELF_LOADER_ERR_CODE_COUNT),
    "ELF_LOADER_ERR_CODE enum and ElfLoaderErrStringArray are out of sync");

inline void internal_memcpy(void* dst, const void* src, size_t n) {
  uint8_t* d = static_cast<uint8_t*>(dst);
  const uint8_t* s = static_cast<const uint8_t*>(src);
  for (size_t i = 0; i < n; i++) d[i] = s[i];
}

inline void internal_memset(void* dst, int v, size_t n) {
  uint8_t* d = static_cast<uint8_t*>(dst);
  for (size_t i = 0; i < n; i++) d[i] = static_cast<uint8_t>(v);
}

inline int internal_strcmp(const char* a, const char* b) {
  while (*a && *a == *b) {
    a++;
    b++;
  }
  return static_cast<uint8_t>(*a) - static_cast<uint8_t>(*b);
}

inline ELF_LOADER_ERR_CODE InvokeHook(const ElfLoaderModule& mod,
                                      const ElfLoaderConfiguration& config,
                                      ELF_LOADER_STAGE stage) {
  if (config.loader_hook &&
      !config.loader_hook(&mod, stage, config.user_context)) {
    return ELF_LOADER_ERR_CODE::HOOK_FAILED;
  }
  return ELF_LOADER_ERR_CODE::OK;
}

inline uint8_t* GetTargetBuffer(const ElfLoaderModule& mod) {
  return static_cast<uint8_t*>(mod.module_handle);
}

inline const Elf64_Phdr* FindPhdr(const Elf64_Ehdr* eh, uint32_t type) {
  const Elf64_Phdr* phdrs = reinterpret_cast<const Elf64_Phdr*>(
      reinterpret_cast<const uint8_t*>(eh) + eh->e_phoff);
  for (uint16_t i = 0; i < eh->e_phnum; i++) {
    if (phdrs[i].p_type == type) return &phdrs[i];
  }
  return nullptr;
}

struct DynamicInfo {
  const Elf64_Sym* symtab{nullptr};
  const char* strtab{nullptr};
  const uint32_t* hash{nullptr};

  const Elf64_Rela* rela{nullptr};
  size_t rela_sz{0};

  const Elf64_Rela* jmprel{nullptr};
  size_t jmprel_sz{0};
  int64_t pltrel_type{0};

  void (**init_array)(){nullptr};
  size_t init_array_sz{0};
  void (*init_fn)(){nullptr};

  void (**fini_array)(){nullptr};
  size_t fini_array_sz{0};
  void (*fini_fn)(){nullptr};
};

void ParseDynamic(uint8_t* base, const Elf64_Dyn* dyn, DynamicInfo& info) {
  for (const Elf64_Dyn* d = dyn; d->d_tag != DT_NULL; d++) {
    switch (d->d_tag) {
      case DT_SYMTAB:
        info.symtab =
            reinterpret_cast<const Elf64_Sym*>(base + d->d_un.d_ptr);
        break;
      case DT_STRTAB:
        info.strtab = reinterpret_cast<const char*>(base + d->d_un.d_ptr);
        break;
      case DT_HASH:
        info.hash =
            reinterpret_cast<const uint32_t*>(base + d->d_un.d_ptr);
        break;
      case DT_RELA:
        info.rela =
            reinterpret_cast<const Elf64_Rela*>(base + d->d_un.d_ptr);
        break;
      case DT_RELASZ:
        info.rela_sz = d->d_un.d_val;
        break;
      case DT_JMPREL:
        info.jmprel =
            reinterpret_cast<const Elf64_Rela*>(base + d->d_un.d_ptr);
        break;
      case DT_PLTRELSZ:
        info.jmprel_sz = d->d_un.d_val;
        break;
      case DT_PLTREL:
        info.pltrel_type = static_cast<int64_t>(d->d_un.d_val);
        break;
      case DT_INIT_ARRAY:
        info.init_array =
            reinterpret_cast<void (**)()>(base + d->d_un.d_ptr);
        break;
      case DT_INIT_ARRAYSZ:
        info.init_array_sz = d->d_un.d_val;
        break;
      case DT_INIT:
        info.init_fn = reinterpret_cast<void (*)()>(base + d->d_un.d_ptr);
        break;
      case DT_FINI_ARRAY:
        info.fini_array =
            reinterpret_cast<void (**)()>(base + d->d_un.d_ptr);
        break;
      case DT_FINI_ARRAYSZ:
        info.fini_array_sz = d->d_un.d_val;
        break;
      case DT_FINI:
        info.fini_fn = reinterpret_cast<void (*)()>(base + d->d_un.d_ptr);
        break;
      default:
        break;
    }
  }
}

ELF_LOADER_ERR_CODE LoadSegments(ElfLoaderModule& mod,
                                 const ElfLoaderConfiguration& config,
                                 const Elf64_Ehdr* eh) {
  const Elf64_Phdr* phdrs = reinterpret_cast<const Elf64_Phdr*>(
      mod.binary_buffer + eh->e_phoff);
  uint64_t image_size = 0;

  for (uint16_t i = 0; i < eh->e_phnum; i++) {
    const Elf64_Phdr* p = &phdrs[i];
    if (p->p_type != PT_LOAD) continue;

    const uint64_t end = p->p_vaddr + p->p_memsz;
    if (end > image_size) image_size = end;
    if (end > config.load_limit) {
      return ELF_LOADER_ERR_CODE::LOAD_LIMIT_EXCEEDED;
    }

    uint8_t* dst = GetTargetBuffer(mod) + p->p_vaddr;
    const uint8_t* src = mod.binary_buffer + p->p_offset;

    if (p->p_filesz > 0) {
      internal_memcpy(dst, src, p->p_filesz);
    }
    if (p->p_memsz > p->p_filesz) {
      internal_memset(dst + p->p_filesz, 0, p->p_memsz - p->p_filesz);
    }

    InvokeHook(mod, config, ELF_LOADER_STAGE::LOAD_SEGMENT);
  }

  mod.image_size = image_size;
  return ELF_LOADER_ERR_CODE::OK;
}

ELF_LOADER_ERR_CODE ResolveImports(ElfLoaderModule& mod,
                                   const ElfLoaderConfiguration& config,
                                   const Elf64_Dyn* dyn,
                                   const DynamicInfo& info) {
  if (!config.load_library || !info.strtab) {
    return ELF_LOADER_ERR_CODE::OK;
  }

  for (const Elf64_Dyn* d = dyn; d->d_tag != DT_NULL; d++) {
    if (d->d_tag != DT_NEEDED) continue;
    const char* libname = info.strtab + d->d_un.d_val;
    void* lib = config.load_library(libname);
    if (!lib && (config.behaviour_flags &
                 BehaviourFlags::IGNORE_MISSING_IMPORTS) == 0) {
      return ELF_LOADER_ERR_CODE::MISSING_IMPORT;
    }
  }
  InvokeHook(mod, config, ELF_LOADER_STAGE::LOAD_IMPORTS);
  return ELF_LOADER_ERR_CODE::OK;
}

ELF_LOADER_ERR_CODE ResolveSymbol(const ElfLoaderConfiguration& config,
                                  const DynamicInfo& info, uint32_t symidx,
                                  uint64_t base, uint64_t& out_value) {
  const Elf64_Sym* sym = &info.symtab[symidx];
  const char* name = info.strtab + sym->st_name;

  if (sym->st_shndx != SHN_UNDEF && sym->st_value != 0) {
    out_value = base + sym->st_value;
    return ELF_LOADER_ERR_CODE::OK;
  }

  if (config.get_proc_address) {
    void* v = config.get_proc_address(nullptr, name);
    if (v) {
      out_value = reinterpret_cast<uint64_t>(v);
      return ELF_LOADER_ERR_CODE::OK;
    }
  }

  out_value = 0;
  if (config.behaviour_flags & BehaviourFlags::IGNORE_MISSING_THUNKS) {
    return ELF_LOADER_ERR_CODE::OK;
  }
  return ELF_LOADER_ERR_CODE::MISSING_THUNK;
}

ELF_LOADER_ERR_CODE ApplyRela(const ElfLoaderConfiguration& config,
                              const DynamicInfo& info,
                              const Elf64_Rela* relocs, size_t count,
                              uint64_t base) {
  for (size_t i = 0; i < count; i++) {
    const Elf64_Rela* r = &relocs[i];
    const uint32_t type = ELF64_R_TYPE(r->r_info);
    const uint32_t symidx = ELF64_R_SYM(r->r_info);
    uint64_t* loc = reinterpret_cast<uint64_t*>(base + r->r_offset);

    switch (type) {
      case R_X86_64_NONE:
        break;
      case R_X86_64_RELATIVE:
        *loc = base + static_cast<uint64_t>(r->r_addend);
        break;
      case R_X86_64_64: {
        uint64_t v = 0;
        auto rc = ResolveSymbol(config, info, symidx, base, v);
        if (rc != ELF_LOADER_ERR_CODE::OK) return rc;
        *loc = v + static_cast<uint64_t>(r->r_addend);
        break;
      }
      case R_X86_64_GLOB_DAT:
      case R_X86_64_JUMP_SLOT: {
        uint64_t v = 0;
        auto rc = ResolveSymbol(config, info, symidx, base, v);
        if (rc != ELF_LOADER_ERR_CODE::OK) return rc;
        *loc = v;
        break;
      }
      default:
        return ELF_LOADER_ERR_CODE::UNSUPPORTED_RELOC;
    }
  }
  return ELF_LOADER_ERR_CODE::OK;
}

void ApplyMprotect(uint8_t* base, const Elf64_Ehdr* eh) {
  const Elf64_Phdr* phdrs = reinterpret_cast<const Elf64_Phdr*>(
      reinterpret_cast<const uint8_t*>(eh) + eh->e_phoff);
  constexpr uint64_t kPage = 0x1000ULL;
  constexpr uint64_t kMask = ~(kPage - 1);

  for (uint16_t i = 0; i < eh->e_phnum; i++) {
    const Elf64_Phdr* p = &phdrs[i];
    if (p->p_type != PT_LOAD) continue;

    int prot = 0;
    if (p->p_flags & PF_R) prot |= PROT_READ;
    if (p->p_flags & PF_W) prot |= PROT_WRITE;
    if (p->p_flags & PF_X) prot |= PROT_EXEC;

    uint8_t* addr = base + (p->p_vaddr & kMask);
    const uint64_t end = (p->p_vaddr + p->p_memsz + kPage - 1) & kMask;
    const size_t sz = static_cast<size_t>(end - (p->p_vaddr & kMask));
    mprotect(addr, sz, prot);
  }
}

void RunInitializers(const DynamicInfo& info) {
  if (info.init_fn) info.init_fn();
  if (info.init_array && info.init_array_sz) {
    const size_t n = info.init_array_sz / sizeof(void (*)());
    for (size_t i = 0; i < n; i++) {
      if (info.init_array[i]) info.init_array[i]();
    }
  }
}

}  // namespace

const char* const ElfLoaderErrCodeToString(ELF_LOADER_ERR_CODE err_code) {
  if (err_code == ELF_LOADER_ERR_CODE::OK) return nullptr;
  return ElfLoaderErrStringArray[static_cast<size_t>(err_code)];
}

ELF_LOADER_ERR_CODE ElfLoaderLoad(const uint8_t* target_binary,
                                  void* target_base,
                                  const ElfLoaderConfiguration& config,
                                  ElfLoaderModule& mod) {
  if (!target_binary) return ELF_LOADER_ERR_CODE::BAD_PARAM;
  if (!target_base) return ELF_LOADER_ERR_CODE::BAD_PARAM;

  const Elf64_Ehdr* eh = reinterpret_cast<const Elf64_Ehdr*>(target_binary);
  if (eh->e_ident[EI_MAG0] != ELFMAG0 || eh->e_ident[EI_MAG1] != ELFMAG1 ||
      eh->e_ident[EI_MAG2] != ELFMAG2 || eh->e_ident[EI_MAG3] != ELFMAG3) {
    return ELF_LOADER_ERR_CODE::BUFFER_BAD_MAGIC;
  }
  if (eh->e_ident[EI_CLASS] != ELFCLASS64 ||
      eh->e_ident[EI_DATA] != ELFDATA2LSB || eh->e_machine != EM_X86_64) {
    return ELF_LOADER_ERR_CODE::UNSUPPORTED_ARCH;
  }

  mod.binary_buffer = target_binary;
  mod.module_handle = target_base;
  mod.module_name = config.module_name;
  mod.disk_path = config.disk_path;
  mod.entry_point_addr = reinterpret_cast<const void*>(
      static_cast<uint8_t*>(target_base) + eh->e_entry);

  auto result = InvokeHook(mod, config, ELF_LOADER_STAGE::BEFORE_SEGMENT_LOAD);
  if (result != ELF_LOADER_ERR_CODE::OK) return result;

  result = LoadSegments(mod, config, eh);
  if (result != ELF_LOADER_ERR_CODE::OK) return result;

  const Elf64_Phdr* dyn_phdr = FindPhdr(eh, PT_DYNAMIC);
  if (dyn_phdr) {
    uint8_t* base = GetTargetBuffer(mod);
    const Elf64_Dyn* dyn =
        reinterpret_cast<const Elf64_Dyn*>(base + dyn_phdr->p_vaddr);

    DynamicInfo info;
    ParseDynamic(base, dyn, info);

    result = ResolveImports(mod, config, dyn, info);
    if (result != ELF_LOADER_ERR_CODE::OK) return result;

    InvokeHook(mod, config, ELF_LOADER_STAGE::LOAD_RELOCATIONS);

    const uint64_t base_u = reinterpret_cast<uint64_t>(base);
    if (info.rela && info.rela_sz) {
      const size_t n = info.rela_sz / sizeof(Elf64_Rela);
      result = ApplyRela(config, info, info.rela, n, base_u);
      if (result != ELF_LOADER_ERR_CODE::OK) return result;
    }
    if (info.jmprel && info.jmprel_sz && info.pltrel_type == DT_RELA) {
      const size_t n = info.jmprel_sz / sizeof(Elf64_Rela);
      result = ApplyRela(config, info, info.jmprel, n, base_u);
      if (result != ELF_LOADER_ERR_CODE::OK) return result;
    }

    ApplyMprotect(base, eh);

    InvokeHook(mod, config, ELF_LOADER_STAGE::LOAD_INIT);
    RunInitializers(info);
  } else {
    ApplyMprotect(GetTargetBuffer(mod), eh);
  }

  InvokeHook(mod, config, ELF_LOADER_STAGE::LOAD_DONE);
  return ELF_LOADER_ERR_CODE::OK;
}

void ElfLoaderInvokeEntryPoint(const ElfLoaderModule& mod) {
  if (!mod.entry_point_addr) return;
  auto fn = reinterpret_cast<void (*)()>(
      const_cast<void*>(mod.entry_point_addr));
  fn();
}

void ElfLoaderRunFinalizers(const ElfLoaderModule& mod) {
  uint8_t* base = static_cast<uint8_t*>(mod.module_handle);
  if (!base) return;

  const Elf64_Ehdr* eh = reinterpret_cast<const Elf64_Ehdr*>(base);
  const Elf64_Phdr* dyn_phdr = FindPhdr(eh, PT_DYNAMIC);
  if (!dyn_phdr) return;

  const Elf64_Dyn* dyn =
      reinterpret_cast<const Elf64_Dyn*>(base + dyn_phdr->p_vaddr);
  DynamicInfo info;
  ParseDynamic(base, dyn, info);

  if (info.fini_array && info.fini_array_sz) {
    const size_t n = info.fini_array_sz / sizeof(void (*)());
    for (size_t i = n; i > 0; i--) {
      if (info.fini_array[i - 1]) info.fini_array[i - 1]();
    }
  }
  if (info.fini_fn) info.fini_fn();
}

void* ElfLoaderGetProcAddress(const ElfLoaderModule& mod,
                              const char* proc_name) {
  uint8_t* base = static_cast<uint8_t*>(mod.module_handle);
  if (!base || !proc_name) return nullptr;

  const Elf64_Ehdr* eh = reinterpret_cast<const Elf64_Ehdr*>(base);
  const Elf64_Phdr* dyn_phdr = FindPhdr(eh, PT_DYNAMIC);
  if (!dyn_phdr) return nullptr;

  const Elf64_Dyn* dyn =
      reinterpret_cast<const Elf64_Dyn*>(base + dyn_phdr->p_vaddr);
  DynamicInfo info;
  ParseDynamic(base, dyn, info);
  if (!info.symtab || !info.strtab) return nullptr;
  if (!info.hash) return nullptr;
  const uint32_t nchain = info.hash[1];

  for (uint32_t i = 0; i < nchain; i++) {
    const Elf64_Sym* sym = &info.symtab[i];
    if (sym->st_value == 0 || sym->st_shndx == SHN_UNDEF) continue;
    const char* name = info.strtab + sym->st_name;
    if (internal_strcmp(name, proc_name) == 0) {
      return reinterpret_cast<void*>(base + sym->st_value);
    }
  }
  return nullptr;
}

}  // namespace loadr
