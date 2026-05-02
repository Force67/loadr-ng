#pragma once

#include <stdint.h>
#include <stddef.h>

namespace loadr {

// Reads `path` into a freshly mmap'd RW buffer. Returns 0 on success,
// negative on error. Caller frees with munmap(*buffer, *size).
int LoadFileToMemory(const char* path, void** buffer, size_t* size);

}  // namespace loadr
