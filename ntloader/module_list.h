#pragma once

struct NtLoaderModule;
void NtLoaderInsertModuleToModuleList(const NtLoaderModule* module);

void NtLoaderOverwriteInitialModule(const NtLoaderModule* module);