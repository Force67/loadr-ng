
#include <Windows.h>

static thread_local int thread_local_var = 0; 

extern "C" __declspec(dllexport) int GetThreadLocalVar() {
  return thread_local_var;
}

extern "C" __declspec(dllexport) void SetThreadLocalVar(int value) {
  thread_local_var = value;
}

BOOL DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
  switch (fdwReason) {
    case DLL_PROCESS_ATTACH:
      // Disable thread library calls
      DisableThreadLibraryCalls(hinstDLL);
      break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
      break;
  }
  return TRUE;
}