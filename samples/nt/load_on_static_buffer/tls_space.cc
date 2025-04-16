#define DECLARE_TLS_VARS(i) static thread_local unsigned char tls[sizeof(int) * i]

DECLARE_TLS_VARS(8000);

#include <Windows.h>

struct TlsToucher
{
    TlsToucher() { *reinterpret_cast<int*>(&tls[sizeof(tls) - sizeof(__int64)]) = static_cast<int>(::GetTickCount64()); }
};

TlsToucher toucher;