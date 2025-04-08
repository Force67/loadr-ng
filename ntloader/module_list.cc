#include "module_list.h"

#include <string>
#include <xmemory>

#include "loader.h"

extern "C" {
HMODULE LdrGetDllHandle(PWSTR DllPath, PULONG DllCharacteristics,
                        PUNICODE_STRING DllName, PVOID* DllHandle);

typedef struct _INTERNAL_LDR_DATA_TABLE_ENTRY {
  LIST_ENTRY InLoadOrderLinks;
  LIST_ENTRY InMemoryOrderLinks;
  LIST_ENTRY InInitializationOrderLinks;
  PVOID DllBase;
  PVOID EntryPoint;
  ULONG SizeOfImage;
  UNICODE_STRING FullDllName;
  UNICODE_STRING BaseDllName;
  ULONG Flags;
  WORD LoadCount;
  WORD TlsIndex;
  union {
    LIST_ENTRY HashLinks;
    struct {
      PVOID SectionPointer;
      ULONG CheckSum;
    };
  };
  union {
    ULONG TimeDateStamp;
    PVOID LoadedImports;
  };
  _ACTIVATION_CONTEXT* EntryPointActivationContext;
  PVOID PatchInformation;
  LIST_ENTRY ForwarderLinks;
  LIST_ENTRY ServiceTagLinks;
  LIST_ENTRY StaticLinks;
} INTERNAL_LDR_DATA_TABLE_ENTRY, *PINTERNAL_LDR_DATA_TABLE_ENTRY;

typedef struct _INTERNAL_PEB_LDR_DATA {
  ULONG Length;
  UCHAR Initialized;
  PVOID SsHandle;
  LIST_ENTRY InLoadOrderModuleList;
  LIST_ENTRY InMemoryOrderModuleList;
  LIST_ENTRY InInitializationOrderModuleList;
  PVOID EntryInProgress;
} INTERNAL_PEB_LDR_DATA, *PINTERNAL_PPEB_LDR_DATA;

typedef struct _INTERNAL_PEB {
  UCHAR InheritedAddressSpace;
  UCHAR ReadImageFileExecOptions;
  UCHAR BeingDebugged;
  UCHAR BitField;
  ULONG ImageUsesLargePages : 1;
  ULONG IsProtectedProcess : 1;
  ULONG IsLegacyProcess : 1;
  ULONG IsImageDynamicallyRelocated : 1;
  ULONG SpareBits : 4;
  PVOID Mutant;
  PVOID ImageBaseAddress;
  PINTERNAL_PPEB_LDR_DATA Ldr;
  PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
  PVOID SubSystemData;
  PVOID ProcessHeap;
  PRTL_CRITICAL_SECTION FastPebLock;
  PVOID AtlThunkSListPtr;
  PVOID IFEOKey;
  ULONG CrossProcessFlags;
  ULONG ProcessInJob : 1;
  ULONG ProcessInitializing : 1;
  ULONG ReservedBits0 : 30;
  union {
    PVOID KernelCallbackTable;
    PVOID UserSharedInfoPtr;
  };
  ULONG SystemReserved[1];
  ULONG SpareUlong;
} INTERNAL_PEB, *PINTERNAL_PEB;
}

UNICODE_STRING ExtractBaseName(UNICODE_STRING* FullName) {
  UNICODE_STRING baseName = {0};
  if (FullName->Buffer) {
    PWSTR lastBackslash = wcsrchr(FullName->Buffer, L'\\');
    if (lastBackslash) {
      baseName.Buffer = lastBackslash + 1;
      baseName.Length =
          FullName->Length -
          (USHORT)((lastBackslash + 1 - FullName->Buffer) * sizeof(WCHAR));
      baseName.MaximumLength = baseName.Length + sizeof(WCHAR);
    } else {
      baseName = *FullName;
    }
  }
  return baseName;
}


// https://github.com/bb107/MemoryModulePP/blob/588b48ebc728bb24438d2db71cf2747454593bdb/MemoryModule/Initialize.cpp#L12
void NtLoaderInsertModuleToModuleList(const NtLoaderModule* module) {
  PINTERNAL_PEB xpeb = (PINTERNAL_PEB)__readgsqword(0x60);  // x64 PEB
  PINTERNAL_PPEB_LDR_DATA ldr = xpeb->Ldr;
  HANDLE hHeap = GetProcessHeap();

  // Check if the module is already present in the InLoadOrder list
  for (PLIST_ENTRY p = ldr->InLoadOrderModuleList.Flink;
       p != &ldr->InLoadOrderModuleList; p = p->Flink) {
    PINTERNAL_LDR_DATA_TABLE_ENTRY entry =
        CONTAINING_RECORD(p, INTERNAL_LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
    if (entry->DllBase == module->module_handle) {
      return;  // Module already exists
    }
  }

  // Allocate and initialize the fake LDR entry
  PINTERNAL_LDR_DATA_TABLE_ENTRY fakeEntry =
      (PINTERNAL_LDR_DATA_TABLE_ENTRY)HeapAlloc(
          hHeap, HEAP_ZERO_MEMORY, sizeof(INTERNAL_LDR_DATA_TABLE_ENTRY));
  if (!fakeEntry) return;

  // Copy the full DLL name
  UNICODE_STRING fullName = *module->module_name;
  PWSTR fullNameBuffer = (PWSTR)HeapAlloc(hHeap, 0, fullName.MaximumLength);
  if (!fullNameBuffer) {
    HeapFree(hHeap, 0, fakeEntry);
    return;
  }
  memcpy(fullNameBuffer, fullName.Buffer, fullName.Length);
  fakeEntry->FullDllName.Buffer = fullNameBuffer;
  fakeEntry->FullDllName.Length = fullName.Length;
  fakeEntry->FullDllName.MaximumLength = fullName.MaximumLength;

  // Set the base DLL name
  fakeEntry->BaseDllName = ExtractBaseName(&fakeEntry->FullDllName);

  // Initialize critical fields
  fakeEntry->DllBase = module->module_handle;
  fakeEntry->SizeOfImage = module->image_size;
  fakeEntry->EntryPoint = (PVOID)module->entry_point_addr;
  fakeEntry->Flags = 0x4;  // LDRP_LOADED flag
  fakeEntry->LoadCount = 1;

 PLIST_ENTRY listHeads[] = {
      (PLIST_ENTRY)&ldr->InLoadOrderModuleList,
      (PLIST_ENTRY)&ldr->InMemoryOrderModuleList,
      (PLIST_ENTRY)&ldr->InInitializationOrderModuleList};

  for (int i = 0; i < 3; ++i) {
    PLIST_ENTRY head = listHeads[i];
    PLIST_ENTRY flink = head->Flink;
    PLIST_ENTRY entryLinks = nullptr;  // Changed to single pointer

    switch (i) {
      case 0:
        entryLinks = &fakeEntry->InLoadOrderLinks;
        break;
      case 1:
        entryLinks = &fakeEntry->InMemoryOrderLinks;
        break;
      case 2:
        entryLinks = &fakeEntry->InInitializationOrderLinks;
        break;
    }

    // Update links with correct pointer types
    entryLinks->Flink = flink;
    entryLinks->Blink = head;
    flink->Blink = entryLinks;
    head->Flink = entryLinks;
  }
}
