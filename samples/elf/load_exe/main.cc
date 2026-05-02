#include <elfloader/file_loader.h>
#include <elfloader/loader.h>
#include <elfloader/module_list.h>

#include <link.h>
#include <stdio.h>
#include <sys/mman.h>

static bool MyLoaderHook(const loadr::ElfLoaderModule* /*mod*/,
                         loadr::ELF_LOADER_STAGE stage,
                         void* /*user_context*/) {
  printf("[load_exe] hook stage: %d\n", static_cast<int>(stage));
  return true;
}

int main(int argc, char** argv) {
  if (argc < 2) {
    fprintf(stderr, "Usage: %s <path/to/sample_exe>\n", argv[0]);
    return 1;
  }

  void* file_buf = nullptr;
  size_t file_sz = 0;
  if (loadr::LoadFileToMemory(argv[1], &file_buf, &file_sz) != 0 || !file_buf) {
    fprintf(stderr, "Failed to load file: %s\n", argv[1]);
    return 1;
  }
  printf("[load_exe] loaded %s (%zu bytes)\n", argv[1], file_sz);

  // RWX up front; the loader tightens per-segment perms via mprotect.
  const size_t alloc = file_sz * 16 + (1u << 20);
  void* target_base =
      ::mmap(nullptr, alloc, PROT_READ | PROT_WRITE | PROT_EXEC,
             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (target_base == MAP_FAILED) {
    fprintf(stderr, "[load_exe] mmap failed\n");
    return 1;
  }
  printf("[load_exe] target base: %p\n", target_base);

  const loadr::ElfLoaderConfiguration config{
      .user_context = nullptr,
      .loader_hook = &MyLoaderHook,
      .load_limit = static_cast<uint64_t>(alloc),
      .behaviour_flags = 0,
      .module_name = argv[1],
      .disk_path = argv[1],
      .load_library = nullptr,
      .get_proc_address = nullptr,
  };

  loadr::ElfLoaderModule mod;
  const auto err = loadr::ElfLoaderLoad(static_cast<const uint8_t*>(file_buf),
                                        target_base, config, mod);
  const char* err_str = loadr::ElfLoaderErrCodeToString(err);
  if (err_str) {
    fprintf(stderr, "[load_exe] loader error: %s\n", err_str);
    return 1;
  }
  printf("[load_exe] loaded; entry @ %p, image_size = %lu\n",
         mod.entry_point_addr, (unsigned long)mod.image_size);

  loadr::ElfLoaderInsertModuleToModuleList(&mod);

  printf("\n--- _r_debug.r_map walk after insertion ---\n");
  bool found = false;
  for (struct link_map* lm = _r_debug.r_map; lm; lm = lm->l_next) {
    const bool ours = (lm->l_addr == reinterpret_cast<ElfW(Addr)>(target_base));
    printf("  %s l_addr=0x%lx  l_name=\"%s\"\n", ours ? "->" : "  ",
           static_cast<unsigned long>(lm->l_addr),
           lm->l_name ? lm->l_name : "(null)");
    if (ours) found = true;
  }
  printf("Module visible in _r_debug chain: %s\n\n",
         found ? "YES" : "NO");

  printf("[load_exe] >>> invoking entry point <<<\n");
  fflush(stdout);
  loadr::ElfLoaderInvokeEntryPoint(mod);
  printf("[load_exe] <<< returned from entry point >>>\n");

  loadr::ElfLoaderRemoveModuleFromModuleList(&mod);
  loadr::ElfLoaderRunFinalizers(mod);
  return 0;
}
