#include "module_list.h"

#include <string>
#include <xmemory>
#include <vector>
#include <string>
#include <sstream>


#include "loader.h"

extern "C" {
HMODULE LdrGetDllHandle(PWSTR DllPath, PULONG DllCharacteristics,
                        PUNICODE_STRING DllName, PVOID* DllHandle);

NTSTATUS RtlHashUnicodeString(IN PUNICODE_STRING String,
                              IN BOOLEAN CaseInSensitive,
                              IN ULONG HashAlgorithm, OUT PULONG HashValue);

typedef enum _LDR_DLL_LOAD_REASON {
  LoadReasonStaticDependency,
  LoadReasonStaticForwarderDependency,
  LoadReasonDynamicForwarderDependency,
  LoadReasonDelayloadDependency,
  LoadReasonDynamicLoad,
  LoadReasonAsImageLoad,
  LoadReasonAsDataLoad,
  LoadReasonEnclavePrimary,  // REDSTONE3
  LoadReasonEnclaveDependency,
  LoadReasonUnknown = -1
} LDR_DLL_LOAD_REASON,
    *PLDR_DLL_LOAD_REASON;

typedef struct _RTL_BALANCED_NODE {
  union {
    struct _RTL_BALANCED_NODE* Children[2];
    struct {
      struct _RTL_BALANCED_NODE* Left;
      struct _RTL_BALANCED_NODE* Right;
    };
  };
  union {
    UCHAR Red : 1;
    UCHAR Balance : 2;
    ULONG_PTR ParentValue;
  };
} RTL_BALANCED_NODE, *PRTL_BALANCED_NODE;

struct INTERNAL_LDR_DATA_TABLE_ENTRY {
  LIST_ENTRY InLoadOrderLinks;
  LIST_ENTRY InMemoryOrderLinks;
  union {
    LIST_ENTRY InInitializationOrderLinks;
    LIST_ENTRY InProgressLinks;
  };
  PVOID DllBase;
  void* EntryPoint;
  ULONG SizeOfImage;
  UNICODE_STRING FullDllName;
  UNICODE_STRING BaseDllName;
  union {
    UCHAR FlagGroup[4];
    ULONG Flags;
    struct {
      ULONG PackagedBinary : 1;
      ULONG MarkedForRemoval : 1;
      ULONG ImageDll : 1;
      ULONG LoadNotificationsSent : 1;
      ULONG TelemetryEntryProcessed : 1;
      ULONG ProcessStaticImport : 1;
      ULONG InLegacyLists : 1;
      ULONG InIndexes : 1;
      ULONG ShimDll : 1;
      ULONG InExceptionTable : 1;
      ULONG ReservedFlags1 : 2;
      ULONG LoadInProgress : 1;
      ULONG LoadConfigProcessed : 1;
      ULONG EntryProcessed : 1;
      ULONG ProtectDelayLoad : 1;
      ULONG ReservedFlags3 : 2;
      ULONG DontCallForThreads : 1;
      ULONG ProcessAttachCalled : 1;
      ULONG ProcessAttachFailed : 1;
      ULONG CorDeferredValidate : 1;
      ULONG CorImage : 1;
      ULONG DontRelocate : 1;
      ULONG CorILOnly : 1;
      ULONG ChpeImage : 1;
      ULONG ReservedFlags5 : 2;
      ULONG Redirected : 1;
      ULONG ReservedFlags6 : 2;
      ULONG CompatDatabaseProcessed : 1;
    };
  };
  USHORT ObsoleteLoadCount;
  USHORT TlsIndex;
  LIST_ENTRY HashLinks;
  ULONG TimeDateStamp;
  struct _ACTIVATION_CONTEXT* EntryPointActivationContext;
  PVOID Lock;  // RtlAcquireSRWLockExclusive
  void* DdagNode;
  LIST_ENTRY NodeModuleLink;
  struct _LDRP_LOAD_CONTEXT* LoadContext;
  PVOID ParentDllBase;
  PVOID SwitchBackContext;
  RTL_BALANCED_NODE BaseAddressIndexNode;
  RTL_BALANCED_NODE MappingInfoIndexNode;
  ULONG_PTR OriginalBase;
  LARGE_INTEGER LoadTime;
  ULONG BaseNameHashValue;
  LDR_DLL_LOAD_REASON LoadReason;
  ULONG ImplicitPathOptions;
  ULONG ReferenceCount;
  ULONG DependentLoadFlags;
  UCHAR SigningLevel;  // since REDSTONE2
};

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

#define HASH_STRING_ALGORITHM_DEFAULT 0x00000000

ULONG32
NTAPI
LdrpHashUnicodeString(IN PUNICODE_STRING NameString) {
  ULONG Result = 0;
  if (!SUCCEEDED(RtlHashUnicodeString(
          NameString, TRUE, HASH_STRING_ALGORITHM_DEFAULT, &Result))) {
    Result = MINLONG;
  }
  return Result;
}

void* FindNtdllTextSection(uint64_t* textSize) {
  HMODULE ntdll = GetModuleHandleA("ntdll.dll");
  if (!ntdll) return nullptr;

  // Parse PE headers
  PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)ntdll;
  PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((uintptr_t)ntdll + dos->e_lfanew);
  PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(nt);

  // Find .text section
  for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
    if (memcmp(sections[i].Name, ".text", 5) == 0) {
      *textSize = sections[i].SizeOfRawData;
      return (void*)((uintptr_t)ntdll + sections[i].VirtualAddress);
    }
  }
  return nullptr;
}

// Helper: Convert IDA-style signature ("40 53 ? ? C3") to pattern + mask
void ParseSignature(const std::string& signature, std::vector<uint8_t>& pattern,
                    std::string& mask) {
  std::istringstream iss(signature);
  std::string token;

  while (iss >> token) {
    if (token == "?") {
      pattern.push_back(0x00);  // Placeholder byte
      mask += '?';
    } else {
      pattern.push_back(static_cast<uint8_t>(std::stoul(token, nullptr, 16)));
      mask += 'x';
    }
  }
}

// Scanner function for IDA-style signatures
void* PatternScan(const char* signature, uint8_t* scanStart, size_t scanSize) {
  std::vector<uint8_t> pattern;
  std::string mask;
  ParseSignature(signature, pattern, mask);

  const size_t patternSize = pattern.size();
  if (patternSize == 0 || patternSize != mask.size()) return nullptr;

  for (size_t i = 0; i <= scanSize - patternSize; ++i) {
    bool found = true;
    for (size_t j = 0; j < patternSize; ++j) {
      if (mask[j] == 'x' && scanStart[i + j] != pattern[j]) {
        found = false;
        break;
      }
    }
    if (found) return &scanStart[i];
  }
  return nullptr;
}

ULONG CalculateBaseNameHashValue(const UNICODE_STRING* baseName) {
  ULONG hash = 0;
  for (USHORT i = 0; i < baseName->Length / sizeof(WCHAR); ++i) {
    hash ^= (hash << 7) ^ baseName->Buffer[i];
  }
  return hash;
}

// Usage for your signature:
void* FindLdrpInsertDataTableEntry() {
  uint64_t textSize;
  uint8_t* textAddr = (uint8_t*)FindNtdllTextSection(&textSize);
  if (!textAddr) return nullptr;

  const char* signature = "40 53 48 83 EC ? F6 41 ? ? 48 8B D9 0F 85";
  return PatternScan(signature, textAddr, textSize);
}

void* FindLdrpAllocateModuleEntry() {
  uint64_t textSize;
  uint8_t* textAddr = (uint8_t*)FindNtdllTextSection(&textSize);
  if (!textAddr) return nullptr;
  const char* signature = "48 89 5C 24 ? 48 89 6C 24 ? 48 89 74 24 ? 57 48 83 EC ? 8B 15";
  return PatternScan(signature, textAddr, textSize);
}

void* FindLdrpInsertModuleToIndex() {
  uint64_t textSize;
  uint8_t* textAddr = (uint8_t*)FindNtdllTextSection(&textSize);
  if (!textAddr) return nullptr;
  const char* signature = "48 89 5C 24 ? 57 48 83 EC ? 48 8B F9 48 8B DA 48 8D 0D ? ? ? ? E8 ? ? ? ? 48 8B D3";
  return PatternScan(signature, textAddr, textSize);
}
// https://github.com/bats3c/DarkLoadLibrary/blob/master/DarkLoadLibrary/src/pebutils.c
// https://github.com/bb107/MemoryModulePP/blob/588b48ebc728bb24438d2db71cf2747454593bdb/MemoryModule/Initialize.cpp#L12
void NtLoaderInsertModuleToModuleList(const NtLoaderModule* module) {
  PINTERNAL_PEB xpeb = (PINTERNAL_PEB)__readgsqword(0x60);  // x64 PEB
  PINTERNAL_PPEB_LDR_DATA ldr = xpeb->Ldr;
  HANDLE hHeap = GetProcessHeap();
  #if 0
  // Check if the module is already present in the InLoadOrder list
  for (PLIST_ENTRY p = ldr->InLoadOrderModuleList.Flink;
       p != &ldr->InLoadOrderModuleList; p = p->Flink) {
    INTERNAL_LDR_DATA_TABLE_ENTRY* entry =
        CONTAINING_RECORD(p, INTERNAL_LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
    __debugbreak();    
  }
  #endif

  // We must use this routine to get an entry that lives on the internal loader heap.
  void* addr = FindLdrpAllocateModuleEntry();
  INTERNAL_LDR_DATA_TABLE_ENTRY* (*LdrpAllocateModuleEntry)(void*) =
      (INTERNAL_LDR_DATA_TABLE_ENTRY*(*)(void*)) addr;

  auto* new_entry = LdrpAllocateModuleEntry(nullptr);
  if (!new_entry) return;
  new_entry->Flags = 0x000022cc;

  // Copy the full DLL name
  UNICODE_STRING fullName = *module->disk_path;
  PWSTR fullNameBuffer = (PWSTR)HeapAlloc(hHeap, 0, fullName.MaximumLength);
  if (!fullNameBuffer) {
    HeapFree(hHeap, 0, new_entry);
    return;
  }
  memcpy(fullNameBuffer, fullName.Buffer, fullName.Length);
  new_entry->FullDllName.Buffer = fullNameBuffer;
  new_entry->FullDllName.Length = fullName.Length;
  new_entry->FullDllName.MaximumLength = fullName.MaximumLength;

  // Set the base DLL name
  new_entry->BaseDllName = ExtractBaseName(&new_entry->FullDllName);
  new_entry->TlsIndex = 0xFFFFFFFF;
  new_entry->ObsoleteLoadCount = 0xFFFF;

  // Initialize critical fields
  new_entry->DllBase = module->module_handle;
  new_entry->SizeOfImage = module->image_size;
  new_entry->EntryPoint = (PVOID)module->entry_point_addr;
  //fakeEntry->Flags = 0x4;  // LDRP_LOADED flag
  //new_entry->Flags = 0x4;  // LDRP_LOADED flag
  new_entry->LoadReason = LoadReasonDynamicLoad;
  new_entry->ImageDll = 1;

  new_entry->LoadInProgress = FALSE;
  new_entry->OriginalBase = (ULONG_PTR)module->module_handle;
  //new_entry->LoadCount = 1;

  void* a1 = FindLdrpInsertDataTableEntry();
  void (*LdrpInsertDataTableEntry)(INTERNAL_LDR_DATA_TABLE_ENTRY*) =
      (void (*)(INTERNAL_LDR_DATA_TABLE_ENTRY*))a1;

  IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)NtLoaderGetBinaryNtHeader(*module);
  new_entry->TimeDateStamp = nt->FileHeader.TimeDateStamp;

  DWORD signature = nt->Signature;

  void* findModule = FindLdrpInsertModuleToIndex();
  void (*LdrpInsertModuleToIndex)(INTERNAL_LDR_DATA_TABLE_ENTRY*, IMAGE_NT_HEADERS*) =
      (void (*)(INTERNAL_LDR_DATA_TABLE_ENTRY*, IMAGE_NT_HEADERS*))findModule;
  
  //new_entry->FlagGroup[0] = 0x00; // whatever that means
  //  unset the InLegacyLists flag
  new_entry->InLegacyLists = 0;


  LdrpInsertDataTableEntry(new_entry);
  LdrpInsertModuleToIndex(new_entry, nt);

  // **MODIFIED**: Insert into PEB lists
  PLIST_ENTRY listHeads[] = {&ldr->InLoadOrderModuleList,
                             &ldr->InMemoryOrderModuleList,
                             &ldr->InInitializationOrderModuleList};
  for (int i = 0; i < 3; ++i) {
    PLIST_ENTRY head = listHeads[i];
    PLIST_ENTRY flink = head->Flink;
    PLIST_ENTRY entryLinks = nullptr;
    switch (i) {
      case 0:
        entryLinks = &new_entry->InLoadOrderLinks;
        break;
      case 1:
        entryLinks = &new_entry->InMemoryOrderLinks;
        break;
      case 2:
        entryLinks = &new_entry->InInitializationOrderLinks;
        break;
    }
    entryLinks->Flink = head->Flink;
    entryLinks->Blink = head;
    head->Flink->Blink = entryLinks;
    head->Flink = entryLinks;
  }

}
