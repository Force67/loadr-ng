#pragma once

namespace loadr {

// Registers the module to the module list. It will then be available through APIs such as
// GetModuleHandleW
struct NtLoaderModule;
void NtLoaderInsertModuleToModuleList(const NtLoaderModule* module);

// This is useful for overwriting the intial entry used by a loader executable. Such that GetModuleFileName(nullptr)
// returns the name of the loaded binary instead of the original (host)
void NtLoaderOverwriteInitialModule(const NtLoaderModule* module);

bool NtLoaderRemoveModuleFromModuleList(const NtLoaderModule* module);
}