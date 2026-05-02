#include "file_loader.h"

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

namespace loadr {

int LoadFileToMemory(const char* path, void** buffer, size_t* size) {
  *buffer = nullptr;
  *size = 0;

  int fd = ::open(path, O_RDONLY);
  if (fd < 0) return -1;

  struct stat st;
  if (::fstat(fd, &st) < 0) {
    ::close(fd);
    return -1;
  }

  const size_t sz = static_cast<size_t>(st.st_size);
  if (sz == 0) {
    ::close(fd);
    return 0;
  }

  void* mem = ::mmap(nullptr, sz, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (mem == MAP_FAILED) {
    ::close(fd);
    return -1;
  }

  uint8_t* p = static_cast<uint8_t*>(mem);
  size_t remaining = sz;
  while (remaining > 0) {
    ssize_t r = ::read(fd, p, remaining);
    if (r < 0) {
      ::munmap(mem, sz);
      ::close(fd);
      return -1;
    }
    if (r == 0) break;
    p += r;
    remaining -= static_cast<size_t>(r);
  }

  ::close(fd);
  *buffer = mem;
  *size = sz;
  return 0;
}

}  // namespace loadr
