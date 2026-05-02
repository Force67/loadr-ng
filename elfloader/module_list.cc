#include "module_list.h"

#include <elf.h>
#include <link.h>
#include <sys/mman.h>

#include "loader.h"

namespace loadr {

namespace {

inline size_t internal_strlen(const char* s) {
  size_t n = 0;
  while (s[n]) n++;
  return n;
}

inline void internal_strcpy(char* dst, const char* src) {
  while ((*dst++ = *src++)) {
  }
}

inline void* alloc_pages(size_t sz) {
  constexpr size_t kPage = 0x1000;
  sz = (sz + kPage - 1) & ~(kPage - 1);
  void* p = ::mmap(nullptr, sz, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  return p == MAP_FAILED ? nullptr : p;
}

inline Elf64_Dyn* FindDynamic(uint8_t* base) {
  const Elf64_Ehdr* eh = reinterpret_cast<const Elf64_Ehdr*>(base);
  const Elf64_Phdr* phdrs =
      reinterpret_cast<const Elf64_Phdr*>(base + eh->e_phoff);
  for (uint16_t i = 0; i < eh->e_phnum; i++) {
    if (phdrs[i].p_type == PT_DYNAMIC) {
      return reinterpret_cast<Elf64_Dyn*>(base + phdrs[i].p_vaddr);
    }
  }
  return nullptr;
}

// r_brk is the no-op trampoline GDB plants a breakpoint on; ld.so calls it
// after every r_state transition.
inline void NotifyDebugger(struct r_debug* r) {
  if (!r->r_brk) return;
  auto fn = reinterpret_cast<void (*)()>(r->r_brk);
  fn();
}

}  // namespace

void ElfLoaderInsertModuleToModuleList(const ElfLoaderModule* module) {
  if (!module || !module->module_handle) return;

  uint8_t* base = static_cast<uint8_t*>(module->module_handle);
  Elf64_Dyn* dyn = FindDynamic(base);

  const char* path = module->disk_path ? module->disk_path : "";
  const size_t name_len = internal_strlen(path) + 1;

  uint8_t* mem = static_cast<uint8_t*>(
      alloc_pages(sizeof(struct link_map) + name_len));
  if (!mem) return;

  auto* lm = reinterpret_cast<struct link_map*>(mem);
  char* name_buf = reinterpret_cast<char*>(mem + sizeof(struct link_map));
  internal_strcpy(name_buf, path);

  lm->l_addr = reinterpret_cast<ElfW(Addr)>(base);
  lm->l_name = name_buf;
  lm->l_ld = reinterpret_cast<ElfW(Dyn)*>(dyn);
  lm->l_next = nullptr;
  lm->l_prev = nullptr;

  struct r_debug* r = &_r_debug;
  r->r_state = r_debug::RT_ADD;
  NotifyDebugger(r);

  if (!r->r_map) {
    r->r_map = lm;
  } else {
    struct link_map* tail = r->r_map;
    while (tail->l_next) tail = tail->l_next;
    lm->l_prev = tail;
    tail->l_next = lm;
  }

  r->r_state = r_debug::RT_CONSISTENT;
  NotifyDebugger(r);
}

bool ElfLoaderRemoveModuleFromModuleList(const ElfLoaderModule* module) {
  if (!module || !module->module_handle) return false;

  struct r_debug* r = &_r_debug;
  for (struct link_map* lm = r->r_map; lm != nullptr; lm = lm->l_next) {
    if (lm->l_addr == reinterpret_cast<ElfW(Addr)>(module->module_handle)) {
      r->r_state = r_debug::RT_DELETE;
      NotifyDebugger(r);

      if (lm->l_prev) {
        lm->l_prev->l_next = lm->l_next;
      } else {
        r->r_map = lm->l_next;
      }
      if (lm->l_next) {
        lm->l_next->l_prev = lm->l_prev;
      }

      r->r_state = r_debug::RT_CONSISTENT;
      NotifyDebugger(r);
      return true;
    }
  }
  return false;
}

}  // namespace loadr
