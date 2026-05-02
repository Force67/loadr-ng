#pragma once

namespace loadr {

struct ElfLoaderModule;

// Splices the module into _r_debug.r_map so debuggers (`info shared`) and
// other walkers of the public link_map chain can see it. Does NOT touch
// glibc's private dl_iterate_phdr namespace lists (those need
// link_map_private fields).
void ElfLoaderInsertModuleToModuleList(const ElfLoaderModule* module);

bool ElfLoaderRemoveModuleFromModuleList(const ElfLoaderModule* module);

}  // namespace loadr
