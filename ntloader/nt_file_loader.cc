
#include <Windows.h>
#include <winternl.h>

extern "C" {

__declspec(dllimport) __kernel_entry NTSYSCALLAPI NTSTATUS
NtQueryInformationFile(HANDLE FileHandle,
                       PIO_STATUS_BLOCK IoStatusBlock,
                       PVOID FileInformation,
                       ULONG Length,
                       FILE_INFORMATION_CLASS FileInformationClass);

__declspec(dllimport) NTSYSCALLAPI NTSTATUS
NtAllocateVirtualMemory(HANDLE ProcessHandle,
                        PVOID* BaseAddress,
                        ULONG_PTR ZeroBits,
                        PSIZE_T RegionSize,
                        ULONG AllocationType,
                        ULONG Protect);

__declspec(dllimport) NTSYSCALLAPI NTSTATUS
NtFreeVirtualMemory(HANDLE ProcessHandle,
                    PVOID* BaseAddress,
                    PSIZE_T RegionSize,
                    ULONG FreeType);

__declspec(dllimport) NTSYSCALLAPI NTSTATUS
NtReadFile(_In_ HANDLE FileHandle,
           _In_opt_ HANDLE Event,
           _In_opt_ PIO_APC_ROUTINE ApcRoutine,
           _In_opt_ PVOID ApcContext,
           _Out_ PIO_STATUS_BLOCK IoStatusBlock,
           _Out_ PVOID Buffer,
           _In_ ULONG Length,
           _In_opt_ PLARGE_INTEGER ByteOffset,
           _In_opt_ PULONG Key);

typedef struct _FILE_STANDARD_INFORMATION {
  LARGE_INTEGER AllocationSize;
  LARGE_INTEGER EndOfFile;
  ULONG NumberOfLinks;
  BOOLEAN DeletePending;
  BOOLEAN Directory;
} FILE_STANDARD_INFORMATION, *PFILE_STANDARD_INFORMATION;

__declspec(dllimport) NTSTATUS
    RtlDosPathNameToNtPathName_U_WithStatus(__in PCWSTR DosFileName,
                                            __out PUNICODE_STRING NtFileName,
                                            __deref_opt_out_opt PWSTR* FilePart,
                                            __reserved PVOID Reserved);
}

static HANDLE NtCurrentProcess() {
  return (HANDLE)-1;
}

#define STATUS_FILE_TOO_LARGE ((NTSTATUS)0xC0000904L)
#define STATUS_INTERNAL_ERROR ((NTSTATUS)0xC00000E5L)
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#define FileStandardInformation (FILE_INFORMATION_CLASS)5

namespace loadr {
NTSTATUS LoadFileToMemory(PCWSTR FileName, PVOID* Buffer, PSIZE_T Size) {
  NTSTATUS status;
  HANDLE hFile = NULL;
  OBJECT_ATTRIBUTES objAttr;
  IO_STATUS_BLOCK ioStatus;
  UNICODE_STRING ntPath;

  // Initialize outputs
  *Buffer = NULL;
  *Size = 0;

  // Convert DOS path to NT path
  status =
      RtlDosPathNameToNtPathName_U_WithStatus(FileName, &ntPath, NULL, NULL);
  if (!NT_SUCCESS(status)) {
    return status;
  }

  // Initialize object attributes
  InitializeObjectAttributes(
      &objAttr, &ntPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

  // Open file with more comprehensive access rights
  status = NtCreateFile(
      &hFile, GENERIC_READ | SYNCHRONIZE, &objAttr, &ioStatus, NULL,
      FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_DELETE, FILE_OPEN,
      FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE, NULL, 0);

  RtlFreeUnicodeString(&ntPath);  // Free the NT path immediately after use

  if (!NT_SUCCESS(status)) {
    return status;
  }

  // Get file size information
  FILE_STANDARD_INFORMATION fileInfo;
  status = NtQueryInformationFile(hFile, &ioStatus, &fileInfo, sizeof(fileInfo),
                                  FileStandardInformation);

  if (!NT_SUCCESS(status)) {
    NtClose(hFile);
    return status;
  }

  // Check for empty file
  if (fileInfo.EndOfFile.QuadPart == 0) {
    NtClose(hFile);
    *Buffer = NULL;
    *Size = 0;
    return STATUS_SUCCESS;
  }

  // Check for reasonable file size
  if (fileInfo.EndOfFile.QuadPart > (1024 * 1024 * 1024)) {  // 1GB limit
    NtClose(hFile);
    return STATUS_FILE_TOO_LARGE;
  }

  // Allocate memory for file contents
  PVOID buffer = NULL;
  SIZE_T allocSize = (SIZE_T)fileInfo.EndOfFile.QuadPart;
  status = NtAllocateVirtualMemory(NtCurrentProcess(), &buffer, 0, &allocSize,
                                   MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

  if (!NT_SUCCESS(status)) {
    NtClose(hFile);
    return status;
  }

  // Read file contents
  LARGE_INTEGER byteOffset = {0};
  status = NtReadFile(hFile, NULL, NULL, NULL, &ioStatus, buffer,
                      (ULONG)fileInfo.EndOfFile.QuadPart, &byteOffset, NULL);

  if (!NT_SUCCESS(status)) {
    SIZE_T freeSize = allocSize;
    NtFreeVirtualMemory(NtCurrentProcess(), &buffer, &freeSize, MEM_RELEASE);
    NtClose(hFile);
    return status;
  }

  // Verify complete read
  if ((ULONG_PTR)ioStatus.Information !=
      (ULONG_PTR)fileInfo.EndOfFile.QuadPart) {
    SIZE_T freeSize = allocSize;
    NtFreeVirtualMemory(NtCurrentProcess(), &buffer, &freeSize, MEM_RELEASE);
    NtClose(hFile);
    return STATUS_INTERNAL_ERROR;
  }

  NtClose(hFile);

  // Set outputs
  *Buffer = buffer;
  *Size = allocSize;

  return STATUS_SUCCESS;
}
}