#include <elfloader/file_loader.h>
#include <elfloader/loader.h>
#include <elfloader/module_list.h>

#include <dlfcn.h>
#include <link.h>
#include <stdio.h>
#include <sys/mman.h>

static void* MyLoadLibrary(const char* name) {
  return ::dlopen(name, RTLD_NOW | RTLD_GLOBAL);
}

static void* MyGetProcAddress(void* /*module*/, const char* sym) {
  return ::dlsym(RTLD_DEFAULT, sym);
}

static bool MyLoaderHook(const loadr::ElfLoaderModule* /*mod*/,
                         loadr::ELF_LOADER_STAGE stage,
                         void* /*user_context*/) {
  printf("Hook stage: %d\n", static_cast<int>(stage));
  return true;
}

int main(int argc, char** argv) {
  if (argc < 2) {
    fprintf(stderr, "Usage: %s <path/to/sample.so>\n", argv[0]);
    return 1;
  }

  void* file_buf = nullptr;
  size_t file_sz = 0;
  if (loadr::LoadFileToMemory(argv[1], &file_buf, &file_sz) != 0 || !file_buf) {
    fprintf(stderr, "Failed to load file: %s\n", argv[1]);
    return 1;
  }
  printf("Loaded file %s (%zu bytes)\n", argv[1], file_sz);

  // RWX up front; the loader tightens per-segment perms via mprotect.
  const size_t alloc = file_sz * 16;
  void* target_base =
      ::mmap(nullptr, alloc, PROT_READ | PROT_WRITE | PROT_EXEC,
             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (target_base == MAP_FAILED) {
    fprintf(stderr, "mmap target failed\n");
    return 1;
  }
  printf("Module target base: %p\n", target_base);

  const loadr::ElfLoaderConfiguration config{
      .user_context = nullptr,
      .loader_hook = &MyLoaderHook,
      .load_limit = static_cast<uint64_t>(alloc),
      .behaviour_flags = loadr::BehaviourFlags::IGNORE_MISSING_THUNKS,
      .module_name = argv[1],
      .disk_path = argv[1],
      .load_library = &MyLoadLibrary,
      .get_proc_address = &MyGetProcAddress,
  };

  loadr::ElfLoaderModule mod;
  const auto err = loadr::ElfLoaderLoad(static_cast<const uint8_t*>(file_buf),
                                        target_base, config, mod);
  const char* err_str = loadr::ElfLoaderErrCodeToString(err);
  if (err_str) {
    fprintf(stderr, "Loader error: %s\n", err_str);
    return 1;
  }
  printf("Module loaded, entry @ %p, image_size = %lu\n",
         mod.entry_point_addr, (unsigned long)mod.image_size);

  auto* get_magic = reinterpret_cast<int (*)()>(
      loadr::ElfLoaderGetProcAddress(mod, "GetMagic"));
  if (!get_magic) {
    fprintf(stderr, "GetMagic not found\n");
    return 1;
  }
  printf("GetMagic() = 0x%X\n", get_magic());

  auto* set_var = reinterpret_cast<void (*)(int)>(
      loadr::ElfLoaderGetProcAddress(mod, "SetVar"));
  auto* get_var = reinterpret_cast<int (*)()>(
      loadr::ElfLoaderGetProcAddress(mod, "GetVar"));
  if (set_var && get_var) {
    set_var(42);
    printf("Round-trip via SetVar/GetVar: %d\n", get_var());
  }

  auto* add = reinterpret_cast<int (*)(int, int)>(
      loadr::ElfLoaderGetProcAddress(mod, "AddNumbers"));
  if (add) {
    printf("AddNumbers(7, 35) = %d\n", add(7, 35));
  }

  auto* get_hello = reinterpret_cast<const char* (*)()>(
      loadr::ElfLoaderGetProcAddress(mod, "GetHello"));
  if (get_hello) {
    const char* s = get_hello();
    printf("GetHello() = %s\n", s ? s : "(null)");
  }

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
  printf("Module visible in _r_debug chain: %s\n", found ? "YES" : "NO");

  loadr::ElfLoaderRemoveModuleFromModuleList(&mod);
  loadr::ElfLoaderRunFinalizers(mod);
  return 0;
}
