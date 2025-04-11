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

NTSTATUS RtlHashUnicodeString(PUNICODE_STRING String,
                              BOOLEAN CaseInSensitive,
                              ULONG HashAlgorithm, PULONG HashValue);
#if 1
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
typedef struct _RTL_RB_TREE {
  PRTL_BALANCED_NODE Root;
  PRTL_BALANCED_NODE Min;
} RTL_RB_TREE, *PRTL_RB_TREE;


VOID RtlRbInsertNodeEx(PRTL_RB_TREE Tree,
                       PRTL_BALANCED_NODE Parent,
                       BOOLEAN Right,
                       PRTL_BALANCED_NODE Node);
#endif
#define LDRP_IMAGE_DLL 0x00000004
#define LDRP_ENTRY_INSERTED 0x00008000
#define LDRP_ENTRY_PROCESSED 0x00004000
#define LDRP_PROCESS_ATTACH_CALLED 0x00080000

#define LDR_HASH_TABLE_ENTRIES 32

#define RtlInitializeListEntry(entry) \
  ((entry)->Blink = (entry)->Flink = (entry))

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

typedef enum _LDR_DDAG_STATE {
  LdrModulesMerged = -5,
  LdrModulesInitError = -4,
  LdrModulesSnapError = -3,
  LdrModulesUnloaded = -2,
  LdrModulesUnloading = -1,
  LdrModulesPlaceHolder = 0,
  LdrModulesMapping = 1,
  LdrModulesMapped = 2,
  LdrModulesWaitingForDependencies = 3,
  LdrModulesSnapping = 4,
  LdrModulesSnapped = 5,
  LdrModulesCondensed = 6,
  LdrModulesReadyToInit = 7,
  LdrModulesInitializing = 8,
  LdrModulesReadyToRun = 9
} LDR_DDAG_STATE;

typedef struct _LDR_SERVICE_TAG_RECORD {
  struct _LDR_SERVICE_TAG_RECORD* Next;
  ULONG ServiceTag;
} LDR_SERVICE_TAG_RECORD, *PLDR_SERVICE_TAG_RECORD;
typedef struct _LDRP_CSLIST {
  PSINGLE_LIST_ENTRY Tail;
} LDRP_CSLIST, *PLDRP_CSLIST;
typedef struct _LDR_DDAG_NODE {
  LIST_ENTRY Modules;
  PLDR_SERVICE_TAG_RECORD ServiceTagList;
  ULONG LoadCount;
  ULONG LoadWhileUnloadingCount;
  ULONG LowestLink;
  union {
    LDRP_CSLIST Dependencies;
    SINGLE_LIST_ENTRY RemovalLink;
  };
  LDRP_CSLIST IncomingDependencies;
  LDR_DDAG_STATE State;
  SINGLE_LIST_ENTRY CondenseLink;
  ULONG PreorderNumber;
} LDR_DDAG_NODE, *PLDR_DDAG_NODE;

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
  _LDR_DDAG_NODE* DdagNode;
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


ULONG CalculateBaseNameHashValue(const UNICODE_STRING* baseName) {
  ULONG hash = 0;
  for (USHORT i = 0; i < baseName->Length / sizeof(WCHAR); ++i) {
    hash ^= (hash << 7) ^ baseName->Buffer[i];
  }
  return hash;
}

INTERNAL_LDR_DATA_TABLE_ENTRY* FindLdrTableEntry(PCWSTR BaseName) {
  PINTERNAL_PEB pPeb;
  INTERNAL_LDR_DATA_TABLE_ENTRY* pCurEntry;
  PLIST_ENTRY pListHead, pListEntry;

  pPeb = (PINTERNAL_PEB)__readgsqword(0x60); 

  if (pPeb == NULL) {
    return NULL;
  }

  pListHead = &pPeb->Ldr->InLoadOrderModuleList;
  pListEntry = pListHead->Flink;

  do {
    pCurEntry = CONTAINING_RECORD(pListEntry, INTERNAL_LDR_DATA_TABLE_ENTRY,
                                  InLoadOrderLinks);
    pListEntry = pListEntry->Flink;

    // BOOL BaseName1 = WideStringCompare(BaseName,
    // pCurEntry->BaseDllName.Buffer, (pCurEntry->BaseDllName.Length /
    // sizeof(wchar_t)) - 4);

    auto WideStringLength = [](PCWSTR str) { return wcslen(str); };

    auto len = WideStringLength(BaseName) * sizeof(WCHAR);    
    BOOL BaseName2 =
        RtlCompareMemory(BaseName, pCurEntry->BaseDllName.Buffer,
                         WideStringLength(BaseName) * sizeof(WCHAR)) == len;

    if (BaseName2 == TRUE) {
      return pCurEntry;
    }

  } while (pListEntry != pListHead);

  return NULL;
}

PLIST_ENTRY FindHashTable() {
  PLIST_ENTRY pList = NULL;
  PLIST_ENTRY pHead = NULL;
  PLIST_ENTRY pEntry = NULL;
  INTERNAL_LDR_DATA_TABLE_ENTRY* pCurrentEntry = NULL;

  PINTERNAL_PEB pPeb = (PINTERNAL_PEB)__readgsqword(0x60);
  if (!pPeb || !pPeb->Ldr) {
    OutputDebugStringW(L"Failed to access PEB or Ldr\n");
    return NULL;
  }

  pHead = &pPeb->Ldr->InInitializationOrderModuleList;
  pEntry = pHead->Flink;

  OutputDebugStringW(L"Searching for LdrpHashTable...\n");

  do {
    pCurrentEntry = CONTAINING_RECORD(pEntry, INTERNAL_LDR_DATA_TABLE_ENTRY,
                                      InInitializationOrderLinks);

    pEntry = pEntry->Flink;

    if (pCurrentEntry->HashLinks.Flink == &pCurrentEntry->HashLinks) {
      continue;
    }

    pList = pCurrentEntry->HashLinks.Flink;

    if (pList->Flink == &pCurrentEntry->HashLinks) {
      ULONG ulRawHash = LdrpHashUnicodeString(&pCurrentEntry->BaseDllName);
      // Correct the hash to map to one of the 32 buckets
      // (LDR_HASH_TABLE_ENTRIES)
      ULONG ulHash = ulRawHash & (LDR_HASH_TABLE_ENTRIES -
                                  1);  // Equivalent to ulRawHash % 32
      wchar_t debugMsg[128];
      wsprintfW(
          debugMsg,
          L"Found potential hash link, raw hash: %lu, bucket index: %lu\n",
          ulRawHash, ulHash);
      OutputDebugStringW(debugMsg);

      // Calculate the base of LdrpHashTable by subtracting the offset for the
      // bucket
      pList = (PLIST_ENTRY)((SIZE_T)pCurrentEntry->HashLinks.Flink -
                            ulHash * sizeof(LIST_ENTRY));

      wsprintfW(debugMsg, L"Calculated LdrpHashTable base: 0x%p\n", pList);
      OutputDebugStringW(debugMsg);
      break;
    }

    pList = NULL;
  } while (pHead != pEntry);

  if (!pList) {
    OutputDebugStringW(L"Failed to locate LdrpHashTable\n");
  }
  return pList;
}


NTSTATUS InsertTailList(PLIST_ENTRY ListHead, PLIST_ENTRY Entry) {
  // Validate input parameters
  if (ListHead == NULL || Entry == NULL) {
    return STATUS_INVALID_PARAMETER;
  }

  // Perform the insertion with extra caution
  __try {
    PLIST_ENTRY Blink = ListHead->Blink;

    Entry->Flink = ListHead;
    Entry->Blink = Blink;
    Blink->Flink = Entry;
    ListHead->Blink = Entry;

    return 0;
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    return STATUS_ACCESS_VIOLATION;
  }
}



#define RVA(type, base_addr, rva) (type)((ULONG_PTR)base_addr + rva)
PRTL_RB_TREE FindModuleBaseAddressIndex() {
  SIZE_T stEnd = NULL;
  PRTL_BALANCED_NODE pNode = NULL;
  PRTL_RB_TREE pModBaseAddrIndex = NULL;

  INTERNAL_LDR_DATA_TABLE_ENTRY* pLdrEntry = FindLdrTableEntry(L"ntdll.dll");

  pNode = &pLdrEntry->BaseAddressIndexNode;

  do {
    pNode = (PRTL_BALANCED_NODE)(pNode->ParentValue & (~7));
  } while (pNode->ParentValue & (~7));

  if (!pNode->Red) {
    DWORD dwLen = NULL;
    SIZE_T stBegin = NULL;

    PIMAGE_NT_HEADERS pNtHeaders =
        RVA(PIMAGE_NT_HEADERS, pLdrEntry->DllBase,
            ((PIMAGE_DOS_HEADER)pLdrEntry->DllBase)->e_lfanew);

    PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNtHeaders);

    for (INT i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++) {
      if (!strcmp(".data", (LPCSTR)pSection->Name)) {
        stBegin = (SIZE_T)pLdrEntry->DllBase + pSection->VirtualAddress;
        dwLen = pSection->Misc.VirtualSize;

        break;
      }

      ++pSection;
    }

    for (DWORD i = 0; i < dwLen - sizeof(SIZE_T); ++stBegin, ++i) {
      SIZE_T stRet =
          RtlCompareMemory((PVOID)stBegin, (PVOID)&pNode, sizeof(SIZE_T));

      if (stRet == sizeof(SIZE_T)) {
        stEnd = stBegin;
        break;
      }
    }

    if (stEnd == NULL) {
      return NULL;
    }

    PRTL_RB_TREE pTree = (PRTL_RB_TREE)stEnd;

    if (pTree && pTree->Root && pTree->Min) {
      pModBaseAddrIndex = pTree;
    }
  }

  return pModBaseAddrIndex;
}

ULONG LdrHashEntry(UNICODE_STRING UniName, BOOL XorHash) {
  ULONG ulRes = 0;
  RtlHashUnicodeString(&UniName, TRUE, 0, &ulRes);

  if (XorHash) {
    ulRes &= (LDR_HASH_TABLE_ENTRIES - 1);
  }

  return ulRes;
}

BOOL AddBaseAddressEntry(INTERNAL_LDR_DATA_TABLE_ENTRY* pLdrEntry, PVOID lpBaseAddr) {
  PRTL_RB_TREE pModBaseAddrIndex = FindModuleBaseAddressIndex();

  if (!pModBaseAddrIndex) {
    return FALSE;
  }

  BOOL bRight = FALSE;
  INTERNAL_LDR_DATA_TABLE_ENTRY* pLdrNode =
      (INTERNAL_LDR_DATA_TABLE_ENTRY*)((size_t)pModBaseAddrIndex -
                                       offsetof(INTERNAL_LDR_DATA_TABLE_ENTRY,
                                        BaseAddressIndexNode));

  do {
    if (lpBaseAddr < pLdrNode->DllBase) {
      if (!pLdrNode->BaseAddressIndexNode.Left) {
        break;
      }

      pLdrNode =
          (INTERNAL_LDR_DATA_TABLE_ENTRY*)((size_t)pLdrNode->BaseAddressIndexNode.Left -
                                           offsetof(
                                               INTERNAL_LDR_DATA_TABLE_ENTRY,
                                            BaseAddressIndexNode));
    }

    else if (lpBaseAddr > pLdrNode->DllBase) {
      if (!pLdrNode->BaseAddressIndexNode.Right) {
        bRight = TRUE;
        break;
      }

      pLdrNode =
          (INTERNAL_LDR_DATA_TABLE_ENTRY*)((size_t)
                                       pLdrNode->BaseAddressIndexNode.Right -
                                           offsetof(
                                               INTERNAL_LDR_DATA_TABLE_ENTRY,
                                            BaseAddressIndexNode));
    }

    else {
      pLdrNode->DdagNode->LoadCount++;
    }
  } while (TRUE);

  RtlRbInsertNodeEx(pModBaseAddrIndex, &pLdrNode->BaseAddressIndexNode, bRight,
                     &pLdrEntry->BaseAddressIndexNode);

  return TRUE;
}

BOOL AddHashTableEntry(INTERNAL_LDR_DATA_TABLE_ENTRY* pLdrEntry) {
  PINTERNAL_PEB pPeb;
  PINTERNAL_PPEB_LDR_DATA pPebData;
  PLIST_ENTRY LdrpHashTable;

  pPeb = (PINTERNAL_PEB)__readgsqword(0x60);

  RtlInitializeListEntry(&pLdrEntry->HashLinks);

  LdrpHashTable = FindHashTable();
  if (!LdrpHashTable) {
    OutputDebugStringW(L"Failed to find LdrpHashTable\n");
    return FALSE;
  }

  // Insert into hash table
  ULONG ulHash = LdrHashEntry(pLdrEntry->BaseDllName, TRUE);
  OutputDebugStringW(L"Inserting into hash table at index: ");
  wchar_t hashIdx[16];
  wsprintfW(hashIdx, L"%d\n", ulHash);
  OutputDebugStringW(hashIdx);

  InsertTailList(&LdrpHashTable[ulHash], &pLdrEntry->HashLinks);

  // Insert into other lists
  InsertTailList(&pPeb->Ldr->InLoadOrderModuleList,
                 &pLdrEntry->InLoadOrderLinks);
  InsertTailList(&pPeb->Ldr->InMemoryOrderModuleList,
                 &pLdrEntry->InMemoryOrderLinks);
  InsertTailList(&pPeb->Ldr->InInitializationOrderModuleList,
                 &pLdrEntry->InInitializationOrderLinks);

  return TRUE;
}


void EnumPebModuleList() { _INTERNAL_PEB* pPeb;
  pPeb = (_INTERNAL_PEB*)__readgsqword(0x60);
  PLIST_ENTRY pListHead = &pPeb->Ldr->InLoadOrderModuleList;
  PLIST_ENTRY pListEntry = pListHead->Flink;
  do {
    INTERNAL_LDR_DATA_TABLE_ENTRY* pCurEntry = CONTAINING_RECORD(
        pListEntry, INTERNAL_LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
    pListEntry = pListEntry->Flink;
    // Print the module name
    wchar_t moduleName[256];
  //  wsprintfW(moduleName, L"%s", &pCurEntry->BaseDllName);
    OutputDebugStringW(pCurEntry->BaseDllName.Buffer);
  } while (pListEntry != pListHead);
}


void EnumLdrTableEntries() {
  auto LdrpHashTable = FindHashTable();
  if (!LdrpHashTable) {
    OutputDebugStringW(L"Failed to find LdrpHashTable for enumeration\n");
    return;
  }

  OutputDebugStringW(L"Enumerating LdrpHashTable entries:\n");

  for (int i = 0; i < LDR_HASH_TABLE_ENTRIES; ++i) {
    __try {
      PLIST_ENTRY pListEntry = LdrpHashTable[i].Flink;
      if (!pListEntry) {
        continue;
      }
      if (pListEntry != &LdrpHashTable[i]) {
        wchar_t idxMsg[64];
        wsprintfW(idxMsg, L"Bucket %d:\n", i);
        OutputDebugStringW(idxMsg);
      }
      while (pListEntry != &LdrpHashTable[i]) {
        INTERNAL_LDR_DATA_TABLE_ENTRY* pCurEntry = CONTAINING_RECORD(
            pListEntry, INTERNAL_LDR_DATA_TABLE_ENTRY, HashLinks);
        pListEntry = pListEntry->Flink;
        if (pCurEntry->BaseDllName.Buffer) {
          OutputDebugStringW(pCurEntry->BaseDllName.Buffer);
          OutputDebugStringW(L"\n");
        }
      }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
      wchar_t errorMsg[64];
      wsprintfW(errorMsg, L"Access violation at bucket %d\n", i);
      OutputDebugStringW(errorMsg);
    }
  }
}
// https://github.com/bats3c/DarkLoadLibrary/blob/master/DarkLoadLibrary/src/pebutils.c
// https://www.mdsec.co.uk/2021/06/bypassing-image-load-kernel-callbacks/
// https://github.com/bb107/MemoryModulePP/blob/588b48ebc728bb24438d2db71cf2747454593bdb/MemoryModule/Initialize.cpp#L12
void NtLoaderInsertModuleToModuleList(const NtLoaderModule* module) {
  PIMAGE_NT_HEADERS pNtHeaders;
  UNICODE_STRING FullDllName, BaseDllName;
  INTERNAL_LDR_DATA_TABLE_ENTRY* pLdrEntry = NULL;

  pNtHeaders = (PIMAGE_NT_HEADERS)NtLoaderGetBinaryNtHeader(*module);

  // convert the names to unicode
  RtlInitUnicodeString(&FullDllName, module->disk_path->Buffer);
  RtlInitUnicodeString(&BaseDllName, module->module_name->Buffer);

  // link the entry to the PEB
  pLdrEntry = (INTERNAL_LDR_DATA_TABLE_ENTRY*)HeapAlloc(
      ::GetProcessHeap(), HEAP_ZERO_MEMORY,
      sizeof(INTERNAL_LDR_DATA_TABLE_ENTRY));

  if (!pLdrEntry) {
    OutputDebugStringW(L"Failed to allocate memory for LDR entry\n");
    return;
  }

  // start setting the values in the entry
  NtQuerySystemTime(&pLdrEntry->LoadTime);
  pLdrEntry->ReferenceCount = 1;
  pLdrEntry->LoadReason = LoadReasonDynamicLoad;
  pLdrEntry->OriginalBase = pNtHeaders->OptionalHeader.ImageBase;
  pLdrEntry->BaseNameHashValue = LdrHashEntry(BaseDllName, FALSE);

  //PVOID baseAddr = module->module_handle;
  // bogus:
  PVOID baseAddr = (PVOID)NtLoaderGetBinaryNtHeader(*module);

  // correctly add the base address to the entry
  if (!AddBaseAddressEntry(pLdrEntry, baseAddr)) {
    OutputDebugStringW(L"Failed to add base address entry\n");
    // Handle cleanup if necessary
    HeapFree(GetProcessHeap(), 0, pLdrEntry->DdagNode);
    HeapFree(GetProcessHeap(), 0, pLdrEntry);
    return;
  }

  // and the rest
  pLdrEntry->ImageDll = TRUE;
  pLdrEntry->LoadNotificationsSent = TRUE;  // lol
  pLdrEntry->EntryProcessed = TRUE;
  pLdrEntry->InLegacyLists = TRUE;
  pLdrEntry->InIndexes = TRUE;
  pLdrEntry->ProcessAttachCalled = TRUE;
  pLdrEntry->InExceptionTable = FALSE;
  pLdrEntry->DllBase = baseAddr;
  pLdrEntry->SizeOfImage = pNtHeaders->OptionalHeader.SizeOfImage;
  pLdrEntry->TimeDateStamp = pNtHeaders->FileHeader.TimeDateStamp;
  pLdrEntry->BaseDllName = BaseDllName;
  pLdrEntry->FullDllName = FullDllName;
  pLdrEntry->ObsoleteLoadCount = 1;
  pLdrEntry->Flags = LDRP_IMAGE_DLL | LDRP_ENTRY_INSERTED |
                     LDRP_ENTRY_PROCESSED | LDRP_PROCESS_ATTACH_CALLED;

  // set the correct values in the Ddag node struct
  pLdrEntry->DdagNode = (PLDR_DDAG_NODE)::HeapAlloc(
      ::GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(LDR_DDAG_NODE));

  if (!pLdrEntry->DdagNode) {
    return;
  }

  pLdrEntry->NodeModuleLink.Flink = &pLdrEntry->DdagNode->Modules;
  pLdrEntry->NodeModuleLink.Blink = &pLdrEntry->DdagNode->Modules;
  pLdrEntry->DdagNode->Modules.Flink = &pLdrEntry->NodeModuleLink;
  pLdrEntry->DdagNode->Modules.Blink = &pLdrEntry->NodeModuleLink;
  pLdrEntry->DdagNode->State = LdrModulesReadyToRun;
  pLdrEntry->DdagNode->LoadCount = 1;

  // add the hash to the LdrpHashTable
  AddHashTableEntry(pLdrEntry);

  // set the entry point
  pLdrEntry->EntryPoint = RVA(PVOID, module->module_handle,
                              pNtHeaders->OptionalHeader.AddressOfEntryPoint);

  EnumPebModuleList();
  OutputDebugStringW(L"Inserted module to the list\n");
  EnumLdrTableEntries();

}
