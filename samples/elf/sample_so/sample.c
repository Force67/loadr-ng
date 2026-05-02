// Built -nostdlib: no libc init, no external symbols to resolve.

static int g_var = 0;

__attribute__((visibility("default"))) void SetVar(int v) { g_var = v; }
__attribute__((visibility("default"))) int GetVar(void) { return g_var; }
__attribute__((visibility("default"))) int GetMagic(void) { return 0xCAFEBABE; }

__attribute__((visibility("default"))) int AddNumbers(int a, int b) {
  return a + b;
}

// Forces an R_X86_64_RELATIVE: the .data pointer needs rebasing at load time.
static const char kHello[] = "hello from sample.so";
__attribute__((visibility("default"))) const char* GetHello(void) {
  return kHello;
}
