// Static-PIE, -nostdlib. Custom _start, raw syscalls, no libc/ld.so.

#include <stdint.h>
#include <sys/syscall.h>

static long sys_write(int fd, const void* buf, unsigned long n) {
  long ret;
  __asm__ volatile("syscall"
                   : "=a"(ret)
                   : "0"(SYS_write), "D"((long)fd), "S"(buf), "d"(n)
                   : "rcx", "r11", "memory");
  return ret;
}

static unsigned long my_strlen(const char* s) {
  const char* p = s;
  while (*p) p++;
  return (unsigned long)(p - s);
}

// Forces an R_X86_64_RELATIVE on the .data pointer.
static const char kBanner[] =
    "[sample_exe] hello from a loadr-loaded static-PIE binary\n";
static const char* const kBannerPtr = kBanner;

__attribute__((constructor)) static void ctor(void) {
  static const char kMsg[] = "[sample_exe] ctor ran\n";
  sys_write(1, kMsg, my_strlen(kMsg));
}

// Plain `ret` returns to the loader. Issuing an exit() syscall would kill
// the host process.
void _start(void) {
  sys_write(1, kBannerPtr, my_strlen(kBannerPtr));
  static const char kBye[] = "[sample_exe] _start returning to loader\n";
  sys_write(1, kBye, my_strlen(kBye));
}
